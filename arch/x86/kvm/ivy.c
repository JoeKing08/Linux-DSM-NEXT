/*
 * Support KVM software distributed memory (Ivy Protocol)
 *
 * This feature allows us to run multiple KVM instances on different machines
 * sharing the same address space.
 *
 * Copyright (C) 2019, Trusted Cloud Group, Shanghai Jiao Tong University.
 * 
 * Authors:
 *   Jin Zhang <jzhang3002@sjtu.edu.cn>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

/************************
 **DEADLOCK DELENDA EST**
 ************************/

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include "dsm-util.h"
#include "ivy.h"
#include "mmu.h"

#include <linux/kthread.h>
#include <linux/mmu_context.h>
 
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/watchdog.h>

/* 
 * [删除] enum kvm_dsm_request_type ... (已移至 kvm_host.h)
 * [删除] struct dsm_request ... (已移至 kvm_host.h)
 * [删除] struct dsm_response ... (已移至 kvm_host.h)
 */

static char* req_desc[3] = {"INV", "READ", "WRITE"};

/* 
 * [修改] dsm_get_copyset
 * 变化：现在 copyset 是结构体，我们需要返回它的地址 (&)，
 * 否则返回的是整个巨大的结构体副本。
 */
static inline copyset_t *dsm_get_copyset(
		struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
    /* 添加 & 取地址符 */
	return &slot->vfn_dsm_state[vfn - slot->base_vfn].copyset;
}

/* [Frontier] 微秒级抖动，打散万节点并发请求 */
/* 定义一个模块参数，允许运行时修改 */
static int enable_jitter = 1;
module_param(enable_jitter, int, 0644);

static inline void inject_jitter(void) {
    if (!enable_jitter) return; /* 玩游戏时，echo 0 > /sys/module/giantvm_kvm/parameters/enable_jitter */
    unsigned int delay = prandom_u32() % 10000;
    ndelay(delay);
}

/* [修改] 适配结构体 */
static inline void dsm_add_to_copyset(struct kvm_dsm_memory_slot *slot, hfn_t vfn, int id)
{
    copyset_t *cs = dsm_get_copyset(slot, vfn);
    
    /* [Frontier 新增] 熔断机制 (可能有逻辑错误，删掉)
     * 如果一个页面已经被超过 128 个节点共享，拒绝新的节点加入共享集。
     * 新节点将被迫向 owner 发起单播读取，而不是加入 copyset。
     * 目的：防止后续发生 Write 时，Owner 需要发送 10000 个 Invalidation 包导致系统卡死。
     
    if (bitmap_weight(cs->bits, DSM_MAX_INSTANCES) > 128) {
        return;
    } */

    set_bit(id, cs->bits);
}

/* [修改] 适配结构体 */
static inline void dsm_clear_copyset(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
    bitmap_zero(dsm_get_copyset(slot, vfn)->bits, DSM_MAX_INSTANCES);
}

/* [添加] 暴力接收：死循环直到读够 data_len 长度 */
static int reliable_recv(struct socket *sock, void *data, size_t data_len) {
    int received = 0;
    int ret = 0;
    struct kvec iov;
    struct msghdr msg;

    while (received < data_len) {
        iov.iov_base = (char*)data + received;
        iov.iov_len = data_len - received;
        
        memset(&msg, 0, sizeof(msg));
        /* MSG_WAITALL 在内核中告诉 TCP 栈尽可能多读 */
        ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, MSG_WAITALL);

        if (ret <= 0) {
            return ret; /* 连接断了或者真出错了 */
        }
        received += ret;
    }
    return received;
}

/* 修改 kvm_dsm_fetch */
static int kvm_dsm_fetch(struct kvm *kvm, uint16_t dest_id, bool from_server,
		const struct dsm_request *req, void *data, struct dsm_response *resp)
{
	kconnection_t **conn_sock;
	int ret;
	tx_add_t tx_add = {
		.txid = generate_txid(kvm, dest_id),
	};
	int retry_cnt = 0;
    
    /* [Frontier] 定义上下文标志 */
    int send_flags = 0;
    int recv_flags = 0;
    bool is_atomic = false;

	if (kvm->arch.dsm_stopped)
		return -EINVAL;

    /* [Frontier] 检测原子上下文 */
    if (in_atomic() || irqs_disabled()) {
        is_atomic = true;
        send_flags = MSG_DONTWAIT; /* 关键：禁止睡眠 */
        recv_flags = MSG_DONTWAIT;
    }  else {
        /* 非原子上下文，保持原作者的习惯 */
        send_flags = 0; 
        recv_flags = SOCK_NONBLOCK; 
    }

	if (!from_server)
		conn_sock = &kvm->arch.dsm_conn_socks[dest_id];
	else {
		conn_sock = &kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES + dest_id];
	}

	if (*conn_sock == NULL) {
        /* [Frontier] 原子上下文无法获取互斥锁建立连接，必须放弃 */
        if (is_atomic) return -ENOTCONN;

		mutex_lock(&kvm->arch.conn_init_lock);
		if (*conn_sock == NULL) {
			ret = kvm_dsm_connect(kvm, dest_id, conn_sock);
			if (ret < 0) {
				mutex_unlock(&kvm->arch.conn_init_lock);
				return ret;
			}
		}
		mutex_unlock(&kvm->arch.conn_init_lock);
	}

	dsm_debug_v("kvm[%d] sent request[0x%x] to kvm[%d] req_type[%s] gfn[%llu,%d]",
			kvm->arch.dsm_id, tx_add.txid, dest_id, req_desc[req->req_type],
			req->gfn, req->is_smm);

    /* [Frontier] 发送阶段：忙等待保护 */
retry_send:
	ret = network_ops.send(*conn_sock, (const char *)req, sizeof(struct
				dsm_request), send_flags, &tx_add);
    
    if (ret == -EAGAIN && is_atomic) {
        cpu_relax();
        touch_nmi_watchdog();        /* 防止硬死锁重启 */
        touch_softlockup_watchdog(); /* [新增] 防止软死锁报错 */
        goto retry_send;             /* 死磕直到缓冲区有空位 */
    }
	if (ret < 0)
		goto done;

	retry_cnt = 0;
    
    /* [Frontier] 接收阶段：忙等待保护 */
	if (req->req_type == DSM_REQ_INVALIDATE) {
retry_recv_inv:
		ret = network_ops.receive(*conn_sock, data, recv_flags, &tx_add);
        if (ret == -EAGAIN && is_atomic) {
            cpu_relax();
            touch_nmi_watchdog();
            touch_softlockup_watchdog(); /* [新增] */
            goto retry_recv_inv;
        }
	}
	else {
retry:
		ret = network_ops.receive(*conn_sock, data, SOCK_NONBLOCK, &tx_add);
		if (ret == -EAGAIN) {
			retry_cnt++;
            
            /* [Frontier] 原子上下文死等逻辑 */
            if (is_atomic) {
                cpu_relax();
                touch_nmi_watchdog();
                touch_softlockup_watchdog(); /* [新增] */
                goto retry;
            }

            /* 原有逻辑：普通上下文超时检测 */
			if (retry_cnt > 100000) {
				printk("%s: DEADLOCK kvm %d wait for gfn %llu response from "
						"kvm %d for too LONG",
						__func__, kvm->arch.dsm_id, req->gfn, dest_id);
				retry_cnt = 0;
			}
			goto retry;
		}
		resp->inv_copyset = tx_add.inv_copyset;
		resp->version = tx_add.version;
	}
	if (ret < 0)
		goto done;

done:
	return ret;
}

/*
 * kvm_dsm_invalidate - issued by owner of a page to invalidate all of its copies
 * [Frontier Modified] 使用安全循环防止万节点死锁
 */
static int kvm_dsm_invalidate(struct kvm *kvm, gfn_t gfn, bool is_smm,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn, copyset_t *cpyset, int req_id)
{
	int holder;
	int ret = 0;
	char r = 1; /* Dummy buffer for ACK */
	copyset_t *copyset;
	struct dsm_response resp; /* Placeholder, not used for invalidate */
    
    /* 循环计数器，用于 watchdog */
    int loop_cnt = 0;

	copyset = cpyset ? cpyset : dsm_get_copyset(slot, vfn);

    /* 
     * [Frontier 修正] 
     * 1. 使用 touch_softlockup_watchdog 防止内核报 "CPU stuck" 
     * 2. 只有在确实安全的时候才调度
     */
	for_each_set_bit(holder, copyset->bits, DSM_MAX_INSTANCES) {
		
        /* 构造请求结构体 */
        struct dsm_request req = {
			.req_type = DSM_REQ_INVALIDATE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.version = dsm_get_version(slot, vfn),
		};
        
		if (kvm->arch.dsm_id == holder)
			continue;
        
		/* Sanity check on copyset consistency. */
		BUG_ON(holder >= kvm->arch.cluster_iplist_len);

        /* 
         * [Frontier] 调用改造后的 kvm_dsm_fetch 
         * 此时它内部会自动使用 MSG_DONTWAIT，并在缓冲区满时 cpu_relax()
         */
		ret = kvm_dsm_fetch(kvm, holder, false, &req, &r, &resp);
		if (ret < 0)
			return ret;

        /* 每发送 64 个包检查一次状态 */
        if (++loop_cnt % 64 == 0) { 
            
            /* [关键新增 1] 同时喂 NMI 狗和 Softlockup 狗 */
            touch_nmi_watchdog();        // 防止硬死锁检测重启
            touch_softlockup_watchdog(); // [必须加] 防止软死锁检测报错
            
            /* [关键新增 2] 严格的上下文检查 */
            /* 如果我们在中断上下文、持有自旋锁或禁止抢占状态，绝对不能调度 */
            if (!in_atomic() && !irqs_disabled()) {
                cond_resched();
            } else {
                /* 
                 * 如果持有自旋锁 (Spinlock Held)，我们不能释放 CPU，
                 * 只能通过 cpu_relax() 通知 CPU 流水线歇口气。
                 */
                cpu_relax(); 
            }
        }
	}

	return 0;
}

static int dsm_handle_invalidate_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0;
	char r;

	if (dsm_is_pinned(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		dsm_debug("kvm[%d] REQ_INV blocked by pinned gfn[%llu,%d], sleep then retry\n",
				kvm->arch.dsm_id, req->gfn, req->is_smm);
		return 0;
	}

	/*
	 * The vfn->gfn rmap can be inconsistent with kvm_memslots when
	 * we're setting memslot, but this will not affect the correctness.
	 * If the old memslot is deleted, then the sptes will be zapped
	 * anyway, so nothing should be done with this case. On the other
	 * hand, if the new memslot is inserted (freshly created or moved),
	 * its sptes are yet to be constructed in tdp_page_fault, and that
	 * is protected by dsm_lock and cannot happen concurrently with the
	 * server side transaction, so the correct DSM state will be seen
	 * in spte construction.
	 *
	 * For usual cases, order between these two operations (change DSM state and
	 * modify page table right) counts. After spte is zapped, DSM software
	 * should make sure that #PF handler read the correct DSM state.
	 */
	BUG_ON(dsm_is_modified(slot, vfn));

	dsm_lock_fast_path(slot, vfn, true);

	dsm_change_state(slot, vfn, DSM_INVALID);
	kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID);
	dsm_set_prob_owner(slot, vfn, req->msg_sender);
	dsm_clear_copyset(slot, vfn);
	ret = network_ops.send(conn_sock, &r, 1, 0, tx_add);

	dsm_unlock_fast_path(slot, vfn, true);

	return ret < 0 ? ret : 0;
}

static int dsm_handle_write_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
    int ret = 0, length = 0;
    int owner = -1;
    bool is_owner = false;
    
    /* [Frontier] 改为指针，从专用 Slab Cache 分配 */
    struct dsm_response *resp;
    resp = kmem_cache_zalloc(dsm_resp_cache, GFP_ATOMIC);
    if (!resp) return -ENOMEM;

    /* [Frontier] 插入抖动，防止拥塞 */
    inject_jitter();

    if (dsm_is_pinned_read(slot, vfn) && !kvm->arch.dsm_stopped) {
        *retry = true;
        goto out_free; 
    }

    if ((is_owner = dsm_is_owner(slot, vfn))) {
        BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);
        dsm_change_state(slot, vfn, DSM_INVALID);
        kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID);
        
        /* 使用 memcpy 操作结构体 */
        memcpy(&resp->inv_copyset, dsm_get_copyset(slot, vfn), sizeof(copyset_t));
        resp->version = dsm_get_version(slot, vfn);
        
        clear_bit(kvm->arch.dsm_id, resp->inv_copyset.bits);
        
        ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
        if (ret < 0) goto out_free;
    }
    else if (dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0) {
        bitmap_zero(resp->inv_copyset.bits, DSM_MAX_INSTANCES);
        resp->version = dsm_get_version(slot, vfn);
        ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
        if (ret < 0) goto out_free;
        dsm_set_prob_owner(slot, vfn, req->msg_sender);
        dsm_change_state(slot, vfn, DSM_INVALID);
    }
    else {
        struct dsm_request new_req = {
            .req_type = DSM_REQ_WRITE,
            .requester = kvm->arch.dsm_id,
            .msg_sender = req->msg_sender,
            .gfn = req->gfn,
            .is_smm = req->is_smm,
            .version = req->version,
        };
        owner = dsm_get_prob_owner(slot, vfn);
        /* 传入指针 */
        ret = length = kvm_dsm_fetch(kvm, owner, true, &new_req, page, resp);
        if (ret < 0) goto out_free;

        dsm_change_state(slot, vfn, DSM_INVALID);
        kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID);
        dsm_set_prob_owner(slot, vfn, req->msg_sender);
        
        clear_bit(kvm->arch.dsm_id, resp->inv_copyset.bits);
    }

    if (is_owner) {
        length = dsm_encode_diff(slot, vfn, req->msg_sender, page, memslot, req->gfn, req->version);
    }

    tx_add->inv_copyset = resp->inv_copyset;
    tx_add->version = resp->version;
    ret = network_ops.send(conn_sock, page, length, 0, tx_add);

out_free:
    /* [Frontier] 归还内存到 Cache */
    kmem_cache_free(dsm_resp_cache, resp);
    return ret;
}

/*
 * A read fault causes owner transmission, too. It's different from original MSI
 * protocol. It mainly addresses a subtle data-race that *AFTER* DSM page fault
 * and *BEFORE* setting appropriate right a write requests (invalidation
 * request) issued by owner will be 'swallowed'. Specifically, in
 * mmu.c:tdp_page_fault:
 * // A read fault
 * [pf handler] dsm_access = kvm_dsm_vcpu_acquire_page()
 * .
 * . [server] dsm_handle_invalidate_req()
 * .
 * [pf handler] __direct_map(dsm_access)
 * [pf handler] kvm_dsm_vcpu_release_page()
 * dsm_handle_invalidate_req() takes no effects then (Note that invalidate
 * handler is lock-free). And if a read fault changes owner too, others write
 * faults will be synchronized by this node.
 */
static int dsm_handle_read_req(struct kvm *kvm, kconnection_t *conn_sock,
		struct kvm_memory_slot *memslot, struct kvm_dsm_memory_slot *slot,
		const struct dsm_request *req, bool *retry, hfn_t vfn, char *page,
		tx_add_t *tx_add)
{
	int ret = 0, length = 0;
	int owner = -1;
	bool is_owner = false;
	
	/* [Frontier] 1. 改为指针 */
	struct dsm_response *resp;

	/* [Frontier] 2. 从专用 Slab Cache 分配 */
	resp = kmem_cache_zalloc(dsm_resp_cache, GFP_ATOMIC);
	if (!resp) return -ENOMEM;

    /* [Frontier] 3. 注入微抖动 (可选，与 Write 保持一致) */
    inject_jitter();

	resp->version = 0;

	if (dsm_is_pinned_read(slot, vfn) && !kvm->arch.dsm_stopped) {
		*retry = true;
		ret = 0;
		goto out_free; /* 必须跳转释放 */
	}

	if ((is_owner = dsm_is_owner(slot, vfn))) {
		BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_change_state(slot, vfn, DSM_SHARED);
		kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_SHARED);

		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0) goto out_free;

        /* [修改] memcpy 复制结构体 */
		memcpy(&resp->inv_copyset, dsm_get_copyset(slot, vfn), sizeof(copyset_t));
        
        /* [修改] 指针操作检查 */
		BUG_ON(!(test_bit(kvm->arch.dsm_id, resp->inv_copyset.bits)));
		resp->version = dsm_get_version(slot, vfn);
	}
	else if (dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0) {
		ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
		if (ret < 0) goto out_free;

		dsm_set_prob_owner(slot, vfn, req->msg_sender);
		dsm_change_state(slot, vfn, DSM_SHARED);
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
		
        /* [修改] memcpy */
		memcpy(&resp->inv_copyset, dsm_get_copyset(slot, vfn), sizeof(copyset_t));
		resp->version = dsm_get_version(slot, vfn);
	}
	else {
		struct dsm_request new_req = {
			.req_type = DSM_REQ_READ,
			.requester = kvm->arch.dsm_id,
			.msg_sender = req->msg_sender,
			.gfn = req->gfn,
			.is_smm = req->is_smm,
			.version = req->version,
		};
		owner = dsm_get_prob_owner(slot, vfn);
		
        /* [修改] 传入 resp 指针 */
		ret = length = kvm_dsm_fetch(kvm, owner, true, &new_req, page, resp);
		if (ret < 0) goto out_free;
		
        /* [修改] bits 操作 */
		BUG_ON(dsm_is_readable(slot, vfn) && !(test_bit(kvm->arch.dsm_id, resp->inv_copyset.bits)));
		dsm_set_prob_owner(slot, vfn, req->msg_sender);
	}

	if (is_owner) {
		length = dsm_encode_diff(slot, vfn, req->msg_sender, page, memslot, req->gfn, req->version);
	}

	tx_add->inv_copyset = resp->inv_copyset;
	tx_add->version = resp->version;
	
	ret = network_ops.send(conn_sock, page, length, 0, tx_add);

out_free:
    /* [Frontier] 4. 释放回 Cache */
	kmem_cache_free(dsm_resp_cache, resp);
	return ret;
}

int ivy_kvm_dsm_handle_req(void *data)
{
	int ret = 0, idx;

	struct dsm_conn *conn = (struct dsm_conn *)data;
	struct kvm *kvm = conn->kvm;
	kconnection_t *conn_sock = conn->sock;

	struct kvm_memory_slot *memslot;
	struct kvm_dsm_memory_slot *slot;
	struct dsm_request req;
	bool retry = false;
	hfn_t vfn;
	char comm[TASK_COMM_LEN];

	char *page;
	int len;

	/* Size of the maximum buffer is PAGE_SIZE */
	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (page == NULL)
		return -ENOMEM;

	while (1) {
		tx_add_t tx_add = {
			/* Accept any incoming requests. */
			.txid = 0xFF,
		};

		if (kthread_should_stop()) {
			ret = -EPIPE;
			goto out;
		}

		len = network_ops.receive(conn_sock, (char*)&req, 0, &tx_add);
		BUG_ON(len > 0 && len != sizeof(struct dsm_request));

		if (len <= 0) {
			ret = len;
			goto out;
		}

		BUG_ON(req.requester == kvm->arch.dsm_id);

retry_handle_req:
		idx = srcu_read_lock(&kvm->srcu);
		memslot = __gfn_to_memslot(__kvm_memslots(kvm, req.is_smm), req.gfn);
		/*
		 * We should ignore private memslots since they are not really visible
		 * to guest and thus are not part of guest state that should be
		 * distributedly shared.
		 */
		if (!memslot || memslot->id >= KVM_USER_MEM_SLOTS ||
				memslot->flags & KVM_MEMSLOT_INVALID) {
			printk(KERN_WARNING "%s: kvm %d invalid gfn %llu!\n",
					__func__, kvm->arch.dsm_id, req.gfn);
			srcu_read_unlock(&kvm->srcu, idx);
			schedule();
			goto retry_handle_req;
		}

		vfn = __gfn_to_vfn_memslot(memslot, req.gfn);
		slot = gfn_to_hvaslot(kvm, memslot, req.gfn);
		if (!slot) {
			printk(KERN_WARNING "%s: kvm %d slot of gfn %llu doesn't exist!\n",
					__func__, kvm->arch.dsm_id, req.gfn);
			srcu_read_unlock(&kvm->srcu, idx);
			schedule();
			goto retry_handle_req;
		}

		dsm_debug_v("kvm[%d] received request[0x%x] from kvm[%d->%d] req_type[%s] "
				"gfn[%llu,%d] vfn[%llu] version %d myversion %d\n",
				kvm->arch.dsm_id, tx_add.txid, req.msg_sender, req.requester,
				req_desc[req.req_type], req.gfn, req.is_smm, vfn, req.version,
				dsm_get_version(slot, vfn));

		BUG_ON(dsm_is_initial(slot, vfn) && dsm_get_prob_owner(slot, vfn) != 0);
		/*
		 * All #PF transactions begin with acquiring owner's (global visble)
		 * dsm_lock. Since only owner can issue DSM_REQ_INVALIDATE, there's no
		 * need to acquire lock. And locking here is prone to cause deadlock.
		 *
		 * If the thread waits for the lock for too long, just buffer the
		 * request and finds whether there's some more requests.
		 */
		if (req.req_type != DSM_REQ_INVALIDATE) {
			dsm_lock(kvm, slot, vfn);
		}

		switch (req.req_type) {
		case DSM_REQ_INVALIDATE:
			ret = dsm_handle_invalidate_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		case DSM_REQ_WRITE:
			ret = dsm_handle_write_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		case DSM_REQ_READ:
			ret = dsm_handle_read_req(kvm, conn_sock, memslot, slot, &req,
					&retry, vfn, page, &tx_add);
			if (ret < 0)
				goto out_unlock;
			break;

		default:
			BUG();
		}

		/* Once a request has been completed, this node isn't owner then. */
		if (req.req_type != DSM_REQ_INVALIDATE)
			dsm_clear_copyset(slot, vfn);

		if (req.req_type != DSM_REQ_INVALIDATE)
			dsm_unlock(kvm, slot, vfn);

		srcu_read_unlock(&kvm->srcu, idx);

		if (retry) {
			retry = false;
			schedule();
			goto retry_handle_req;
		}
	}
out_unlock:
	if (req.req_type != DSM_REQ_INVALIDATE)
		dsm_unlock(kvm, slot, vfn);
	srcu_read_unlock(&kvm->srcu, idx);
out:
	kfree(page);
	/* return zero since we quit voluntarily */
	if (kvm->arch.dsm_stopped) {
		ret = 0;
	}
	else {
		get_task_comm(comm, current);
		dsm_debug("kvm[%d] %s exited server loop, error %d\n",
				kvm->arch.dsm_id, comm, ret);
	}

	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
	return ret;
}

/*
 * A faulting vCPU can fill in the EPT correctly without network operations.
 * There're two scenerios:
 * 1. spte is dropped (swap, ksm, etc.)
 * 2. The faulting page has been updated by another vCPU.
 */
static bool is_fast_path(struct kvm *kvm, struct kvm_dsm_memory_slot *slot,
		hfn_t vfn, bool write)
{
	/*
	 * DCL is required here because the invalidation server may change the DSM
	 * state too.
	 * Futher, a data race ocurrs when an invalidation request
	 * arrives, the client is between kvm_dsm_page_fault and __direct_map (see
	 * the comment of dsm_handle_read_req). By then EPT is readable while DSM
	 * state is invalid. This causes invalidation request, i.e., a remote write
	 * is omitted.
	 * All transactions should be synchorized by the owner, which is a basic
	 * rule of IVY. But the fast path breaks it. To keep consistency, the fast
	 * path should not be interrupted by an invalidation request. So both fast
	 * path and dsm_handle_invalidate_req should hold a per-page fast_path_lock.
	 */
	if (write && dsm_is_modified(slot, vfn)) {
		dsm_lock_fast_path(slot, vfn, false);
		if (write && dsm_is_modified(slot, vfn)) {
			return true;
		}
		else {
			dsm_unlock_fast_path(slot, vfn, false);
			return false;
		}
	}
	if (!write && dsm_is_readable(slot, vfn)) {
		dsm_lock_fast_path(slot, vfn, false);
		if (!write && dsm_is_readable(slot, vfn)) {
			return true;
		}
		else {
			dsm_unlock_fast_path(slot, vfn, false);
			return false;
		}
	}
	return false;
}

/*
 * copyset rules:
 * 1. Only copyset residing on the owner side is valid, so when owner
 * transmission occurs, copyset of the old one should be cleared.
 * 2. Copyset of a fresh write fault owner is zero.
 * 3. Every node can only operate its own bit of a copyset. For example, in a
 * typical msg_sender->manager->owner (write fault) chain, both owner and
 * manager should clear their own bit in the copyset sent back to the new
 * owner (msg_sender). In the current implementation, the chain may becomes
 * msg_sender->probOwner0->probOwner1->...->requester->owner, each probOwner
 * should clear their own bit.
 *
 * version rules:
 * Overview: Each page (gfn) has a version. If versions of two pages on different
 * nodes are the same, the data of two pages are the same.
 * 1. Upon a write fault, the version of requster is resp.version (old owner) + 1
 * 2. Upon a read fault, the version of requester is the same as resp.version
 */
int ivy_kvm_dsm_page_fault(struct kvm *kvm, struct kvm_memory_slot *memslot,
		gfn_t gfn, bool is_smm, int write)
{
	int ret, resp_len = 0;
	struct kvm_dsm_memory_slot *slot;
	hfn_t vfn;
	char *page = NULL;
	struct dsm_response resp;
	int owner;

	ret = 0;
	vfn = __gfn_to_vfn_memslot(memslot, gfn);
	slot = gfn_to_hvaslot(kvm, memslot, gfn);

	if (is_fast_path(kvm, slot, vfn, write)) {
		if (write) {
			return ACC_ALL;
		}
		else {
			return ACC_EXEC_MASK | ACC_USER_MASK;
		}
	}

	BUG_ON(dsm_is_initial(slot, vfn) && dsm_get_prob_owner(slot, vfn) != 0);

	page = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (page == NULL) {
		ret = -ENOMEM;
		goto out_error;
	}

	/*
	 * If #PF is owner write fault, then issue invalidate by itself.
	 * Or this node will be owner after #PF, it still issue invalidate by
	 * receiving copyset from old owner.
	 */
	if (write) {
		struct dsm_request req = {
			.req_type = DSM_REQ_WRITE,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.version = dsm_get_version(slot, vfn),
		};
		if (dsm_is_owner(slot, vfn)) {
			BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);

			ret = kvm_dsm_invalidate(kvm, gfn, is_smm, slot, vfn, NULL, kvm->arch.dsm_id);
			if (ret < 0)
				goto out_error;
			resp.version = dsm_get_version(slot, vfn);
			resp_len = PAGE_SIZE;

			dsm_incr_version(slot, vfn);
		}
		else {
			owner = dsm_get_prob_owner(slot, vfn);
			/* Owner of all pages is 0 on init. */
			if (unlikely(dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0)) {
				dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
				dsm_change_state(slot, vfn, DSM_OWNER | DSM_MODIFIED);
				dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
				ret = ACC_ALL;
				goto out;
			}
			/*
			 * Ask the probOwner. The prob(ably) owner is probably true owner,
			 * or not. If not, forward the request to next probOwner until find
			 * the true owner.
			 */
			ret = resp_len = kvm_dsm_fetch(kvm, owner, false, &req, page,
					&resp);
			if (ret < 0)
				goto out_error;
			ret = kvm_dsm_invalidate(kvm, gfn, is_smm, slot, vfn,
					&resp.inv_copyset, owner);
			if (ret < 0)
				goto out_error;

			dsm_set_version(slot, vfn, resp.version + 1);
		}

		dsm_clear_copyset(slot, vfn);
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);

		dsm_decode_diff(page, resp_len, memslot, gfn);
		dsm_set_twin_conditionally(slot, vfn, page, memslot, gfn,
				dsm_is_owner(slot, vfn), resp.version);

		if (!dsm_is_owner(slot, vfn) && resp_len > 0) {
			ret = __kvm_write_guest_page(memslot, gfn, page, 0, PAGE_SIZE);
			if (ret < 0) {
				goto out_error;
			}
		}

		dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
		dsm_change_state(slot, vfn, DSM_OWNER | DSM_MODIFIED);
		ret = ACC_ALL;
	} else {
		struct dsm_request req = {
			.req_type = DSM_REQ_READ,
			.requester = kvm->arch.dsm_id,
			.msg_sender = kvm->arch.dsm_id,
			.gfn = gfn,
			.is_smm = is_smm,
			.version = dsm_get_version(slot, vfn),
		};
		owner = dsm_get_prob_owner(slot, vfn);
		/*
		 * If I'm the owner, then I would have already been in Shared or
		 * Modified state.
		 */
		BUG_ON(dsm_is_owner(slot, vfn));

		/* Owner of all pages is 0 on init. */
		if (unlikely(dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0)) {
			dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
			dsm_change_state(slot, vfn, DSM_OWNER | DSM_SHARED);
			dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
			ret = ACC_EXEC_MASK | ACC_USER_MASK;
			goto out;
		}
		/* Ask the probOwner */
		ret = resp_len = kvm_dsm_fetch(kvm, owner, false, &req, page, &resp);
		if (ret < 0)
			goto out_error;

		dsm_set_version(slot, vfn, resp.version);
		memcpy(dsm_get_copyset(slot, vfn), &resp.inv_copyset, sizeof(copyset_t));
		dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);

		dsm_decode_diff(page, resp_len, memslot, gfn);

		ret = __kvm_write_guest_page(memslot, gfn, page, 0, PAGE_SIZE);
		if (ret < 0)
			goto out_error;

		dsm_set_prob_owner(slot, vfn, kvm->arch.dsm_id);
		/*
		 * The node becomes owner after read fault because of data locality,
		 * i.e. a write fault may occur soon. It's not designed to avoid annoying
		 * bugs, right? See comments of dsm_handle_read_req.
		 */
		dsm_change_state(slot, vfn, DSM_OWNER | DSM_SHARED);
		ret = ACC_EXEC_MASK | ACC_USER_MASK;
	}

out:
	kvm_dsm_pf_trace(kvm, slot, vfn, write, resp_len);
	kfree(page);
	return ret;

out_error:
	dump_stack();
	printk(KERN_ERR "kvm-dsm: node-%d failed to handle page fault on gfn[%llu,%d], "
			"error: %d\n", kvm->arch.dsm_id, gfn, is_smm, ret);
	kfree(page);
	return ret;
}
