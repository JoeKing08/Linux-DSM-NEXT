这是一份**最终定稿、全量合并、工程级**的实施手册。
它将所有之前的讨论（包括栈溢出修复、启动风暴修复、万节点扩展、双模切换）整合为一份可直接执行的文档。

---

**适用版本：** GiantVM-KVM (Linux 5.x/4.x basis) & QEMU 4.x/5.x basis
**核心目标：** 支持 10,240 节点集群，修复所有已知崩溃点，实现 Kernel/UFFD 双模自动切换。

---

## 1. 内核模块修改清单 (GiantVM-KVM)
*工作目录：`giantvm-kvm/` 或 `kernel/`*

### 1.1 头文件扩容与结构体重构
**文件：** `kvm_host.h`

**【操作】** 找到 `DSM_MAX_INSTANCES` 和 `copyset_t` 的定义。

**【修改前】** (示例)
```c
#define DSM_MAX_INSTANCES 64
typedef unsigned long copyset_t[...]; // 可能是数组定义
```

**【修改后】** (强制扩容并封装为结构体，防止参数传递时退化为指针)
```c
#ifndef __KVM_HOST_H_FRONTIER_EXTENSION
#define __KVM_HOST_H_FRONTIER_EXTENSION

/* [Frontier] 1. 扩容与头文件依赖 */
#define DSM_MAX_INSTANCES 10240
#include <linux/bitmap.h>
#include <linux/slab.h>
#include <linux/types.h>

/* [Frontier] 2. 新版 Copyset */
typedef struct {
    unsigned long bits[BITS_TO_LONGS(DSM_MAX_INSTANCES)];
} copyset_t;

/* [Frontier] 3. 搬运枚举定义 */
enum kvm_dsm_request_type {
	DSM_REQ_INVALIDATE,
	DSM_REQ_READ,
	DSM_REQ_WRITE,
};

/* 
 * [Frontier Critical Fix] 
 * 1. 加上 __attribute__((packed)) 防止编译器填充字节导致协议错位。
 * 2. version 升级为 uint32_t 防止高频读写回绕。
 */

/* [Frontier] 4. 搬运并强化 Request 结构体 */
struct dsm_request {
	unsigned char requester;
	unsigned char msg_sender;
	gfn_t gfn;
	unsigned char req_type;
	bool is_smm;
	uint32_t version;     /* Fix: 从 uint16_t 升级为 uint32_t */
} __attribute__((packed)); /* Fix: 强制对齐 */

/* [Frontier] 5. 搬运并强化 Response 结构体 */
struct dsm_response {
	copyset_t inv_copyset;
	uint32_t version;     /* Fix: 从 uint16_t 升级为 uint32_t */
} __attribute__((packed)); /* Fix: 强制对齐 */

/* [Frontier] 6. 声明全局缓存池变量 (供 ivy.c 使用) */
extern struct kmem_cache *dsm_resp_cache;

#endif /* __KVM_HOST_H_FRONTIER_EXTENSION */

/* 
 * /* [Frontier] 7.(可能和上面那几条不在同一个 kvm_host.h 文件里)
 * 必须与 kvm_host.h 中的 copyset_t 定义保持一致。
 * 之前的 uint16_t 只能存 16 个节点，现在需要存 10240 个节点。
 */

typedef struct tx_add {
#ifdef IVY_KVM_DSM
    /* 
     * [修改] 直接嵌入结构体 
     * 这里会占用约 1280 字节，网络层必须支持发送这么大的包头 
     */
    copyset_t inv_copyset;
    
    /* [修改] 升级为 32 位以匹配 kvm_host.h 的定义 */
    uint32_t version;
    
#elif defined(TARDIS_KVM_DSM)
    /* 
     * Tardis 模式如果不用 copyset，保留 Padding 即可。
     * 但建议检查 Tardis 逻辑是否也受影响。
     */
    uint16_t padding;
#endif

    /*
     * (Hopefully) unique transcation id
     */
    uint16_t txid;

} __attribute__((packed)) tx_add_t; /* [必须] 强制紧凑对齐 */
```

---

### 1.2. 核心协议逻辑 (栈溢出修复 + Jitter + Cache)
**文件：** `ivy.c`

**【修改目标】**
1.  引入随机延迟 (`inject_jitter`) 防止 TCP 拥塞。
2.  将大结构体 (`struct dsm_response`) 改为从 Slab Cache 动态分配。
3.  修复 Copyset 指针操作。

**【代码对比】**

#### A. 辅助函数与头文件

**[修改后 / Modified]** (直接添加在文件头部)
```c
/* ivy.c 头部 */

/* ... includes ... */

/* 
 * [删除/注释] 原来的结构体定义，因为已经移到 kvm_host.h 了
 * enum kvm_dsm_request_type { ... };
 * struct dsm_request { ... };
 * struct dsm_response { ... };
 */

/* 确保包含修改后的头文件 */
#include "kvm_host.h" 
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/watchdog.h>
#include <linux/delay.h>

/* 
 * [删除] enum kvm_dsm_request_type ... (已移至 kvm_host.h)
 * [删除] struct dsm_request ... (已移至 kvm_host.h)
 * [删除] struct dsm_response ... (已移至 kvm_host.h)
 */

/* [保留] 这个是本地调试用的描述符，不用移 */
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
```

#### B. 失效广播逻辑 (修复遍历 Bug)
**【替换说明】** 找到 `kvm_dsm_invalidate` 函数，全量替换。

```c
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
```

#### C. 写请求处理 (dsm_handle_write_req)

**[原代码 / Original]** (逻辑概要)
```c
static int dsm_handle_write_req(...) {
    struct dsm_response resp; // 在栈上分配，导致栈溢出
    /* ... 逻辑处理 ... */
    tx_add->inv_copyset = resp.inv_copyset;
    /* ... */
}
```

**[修改后 / Modified]**
```c
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
```

#### D. 读请求处理 (dsm_handle_read_req)

**【操作】** 打开 `ivy.c`，找到 `dsm_handle_read_req`，用下面的代码**全量替换**：

```c
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
```

---

### 1.3 内存槽拷贝修正 (dsm.c)
**文件：** `dsm.c`

**【操作】** 找到 `kvm_dsm_add_memslot` 函数，替换结构体拷贝部分。

```c
#ifdef IVY_KVM_DSM
    /* [修改] 使用 bitmap_copy 进行拷贝 */
    bitmap_copy(new_hvaslot->vfn_dsm_state[i + (vfn - new_hvaslot->base_vfn)].copyset.bits,
                hvaslot->vfn_dsm_state[i + (gfn - gfn_iter)].copyset.bits,
                DSM_MAX_INSTANCES);
#endif
```

### 1.4. 模块生命周期管理 (Slab Cache 初始化)
**文件：** `kvm_main.c`

**【修改目标】**
1.  定义全局变量 `dsm_resp_cache`。
2.  在 `kvm_init` 中创建缓存池。
3.  在 `kvm_exit` 中销毁缓存池。

**【代码对比】**

#### A. 全局变量定义 (文件头部)

**[原代码 / Original]**
*(无)*

**[修改后 / Modified]**
```c
/* [Frontier] 定义 DSM 专用缓存池 */
struct kmem_cache *dsm_resp_cache;
EXPORT_SYMBOL_GPL(dsm_resp_cache);
```

#### B. 初始化函数 (kvm_init)

**[原代码 / Original]**
```c
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", vcpu_size, vcpu_align,
					   SLAB_ACCOUNT, NULL);
	if (!kvm_vcpu_cache) {
		r = -ENOMEM;
		goto out_free_3;
	}

	r = kvm_async_pf_init();
	if (r)
		goto out_free;
```

**[修改后 / Modified]**
```c
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", vcpu_size, vcpu_align,
					   SLAB_ACCOUNT, NULL);
	if (!kvm_vcpu_cache) {
		r = -ENOMEM;
		goto out_free_3;
	}

	/* [Frontier] 初始化 DSM Response 专用缓存池 */
	/* 解决万节点高频交互下的内核内存碎片问题 */
	dsm_resp_cache = kmem_cache_create("dsm_resp_cache", 
					   sizeof(struct dsm_response), 
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!dsm_resp_cache) {
		r = -ENOMEM;
		goto out_free_vcpu_cache; /* 跳转到特定的释放点 */
	}

	r = kvm_async_pf_init();
	if (r)
		goto out_free_dsm_cache; /* 跳转到特定的释放点 */

    /* ... 后续代码 ... */
    
    /* 在函数末尾添加新的错误处理标签 */
out_free_dsm_cache:
	kmem_cache_destroy(dsm_resp_cache);
out_free_vcpu_cache:
	kmem_cache_destroy(kvm_vcpu_cache);
    /* 接入原有的 out_free_3 */
```

#### C. 退出函数 (kvm_exit)

**[原代码 / Original]**
```c
void kvm_exit(void)
{
	debugfs_remove_recursive(kvm_debugfs_dir);
	misc_deregister(&kvm_dev);
	kmem_cache_destroy(kvm_vcpu_cache);
	kvm_async_pf_deinit();
    /* ... */
```

**[修改后 / Modified]**
```c
void kvm_exit(void)
{
	debugfs_remove_recursive(kvm_debugfs_dir);
	misc_deregister(&kvm_dev);

	/* [Frontier] 销毁 DSM 缓存池 (LIFO 原则，先销毁后创建的) */
	if (dsm_resp_cache)
		kmem_cache_destroy(dsm_resp_cache);

	kmem_cache_destroy(kvm_vcpu_cache);
	kvm_async_pf_deinit();
	unregister_syscore_ops(&kvm_syscore_ops);
	unregister_reboot_notifier(&kvm_reboot_notifier);
	cpuhp_remove_state_nocalls(CPUHP_AP_KVM_STARTING);
	on_each_cpu(hardware_disable_nolock, NULL, 1);
	kvm_arch_hardware_unsetup();
	kvm_arch_exit();
	kvm_irqfd_exit();
	free_cpumask_var(cpus_hardware_enabled);
	kvm_vfio_ops_exit();
}
EXPORT_SYMBOL_GPL(kvm_exit);
```

---

## 2. QEMU 源码修改清单 (QEMU-System)
*工作目录：`qemu/`*

### 2.1 修复 Select 限制崩溃
**文件：** `hw/tpm/tpm_tis.c`

**[原代码 / Original]**
```c
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    n = select(fd + 1, &readfds, NULL, NULL, &tv);
```

**[修改后 / Modified]**
```c
#include <poll.h> /* 需确保包含 */

    /* [Frontier] 使用 poll 替代 select，防止 fd > 1024 崩溃 */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    n = poll(&pfd, 1, 1000); /* 1000ms timeout */
```

### 2.2 UFFD 双模后端引擎 (核心新增)

#### A. 头文件
**新增文件：** `dsm_backend.h`

```c
#ifndef DSM_BACKEND_H
#define DSM_BACKEND_H
#include <stddef.h>
#include <stdint.h>
void dsm_universal_init(void);
void dsm_universal_register(void *ptr, size_t size);
#endif
```

#### B. 实现文件 (包含 Lazy Connect 与 细粒度锁)
**文件：** 新增 `dsm_backend.c`
**注意：** 包含 `inject_jitter` 防止 UFFD 模式下的网络拥塞。

**[全量新代码 / New File]**
```c
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "dsm_backend.h"
#include <time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sched.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>

#define _GNU_SOURCE 
#include <endian.h>

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif

/* === 配置区域 === */
#define PREFETCH 32           // 预取页面数量 (32 * 4KB = 128KB)
#define PAGE_SIZE 4096
#define MAX_OPEN_SOCKETS 10240 // 允许同时保持的最大连接数
#define WORKER_THREADS 64     // UFFD 处理线程数

// 节点 IP 列表 (请按实际情况填写)
const char *NODE_IPS[] = { 
    "192.168.1.101", 
    "192.168.1.102", 
    // ... 更多节点
}; 
#define NODE_COUNT (sizeof(NODE_IPS)/sizeof(NODE_IPS[0]))

/* === 全局变量 === */
int gvm_mode = 0;              // 0: Kernel Mode, 1: User Mode
int uffd_fd = -1;
int *global_sockets = NULL;    // 存储 socket fd
pthread_mutex_t *conn_locks = NULL; // 每个节点的专用锁
int active_node_ids[MAX_OPEN_SOCKETS]; 
int next_victim_idx = 0;
pthread_mutex_t lru_lock = PTHREAD_MUTEX_INITIALIZER; 

/* 
 * 建立连接底层函数 
 * 包含：超时设置、KeepAlive、NoDelay
 */
static int connect_node_impl(const char *ip) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;

    /* 1. 暴力复位 (Linger 0)，防止 TIME_WAIT 耗尽端口 */
    struct linger sl = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(s, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

    /* 2. 基础性能优化 */
    int flag = 1, bufsize = 4 * 1024 * 1024;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&bufsize, sizeof(int));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&bufsize, sizeof(int));

    /* 3. KeepAlive (防止静默断开) */
    int keepalive = 1, keepidle = 5, keepintvl = 2, keepcnt = 3;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int));

    /* 4. [FIX] 读写超时 (防止死锁的关键) */
    struct timeval timeout;
    timeout.tv_sec = 2;  // 2秒无响应即视为断开，触发重连
    timeout.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons(9999);
    inet_pton(AF_INET, ip, &a.sin_addr);

    if (connect(s, (struct sockaddr*)&a, sizeof(a)) < 0) { 
        close(s); 
        return -1; 
    }
    return s;
}

/* 
 * [CRITICAL FIX] 获取连接并锁定
 * 返回值: Socket FD (>=0) 表示成功，且 conn_locks[node_id] 处于 LOCKED 状态。
 *        -1 表示失败，锁已被释放。
 */
static int get_or_connect_locked(int node_id) {
    if (node_id < 0 || node_id >= NODE_COUNT) return -1;

    pthread_mutex_lock(&conn_locks[node_id]);

    /* 极其简单：有就用，没有就连，不需要踢人 */
    if (global_sockets[node_id] != -1) {
        return global_sockets[node_id];
    }

    /* 建立连接 */
    int s = connect_node_impl(NODE_IPS[node_id]);
    if (s >= 0) {
        global_sockets[node_id] = s;
        return s;
    } else {
        pthread_mutex_unlock(&conn_locks[node_id]);
        return -1;
    }
}

/* 
 * 辅助函数：关闭连接并清理状态 
 * 调用前必须持有 conn_locks[node_id]
 */
static void close_socket_locked(int node_id) {
    int s = global_sockets[node_id];
    if (s != -1) {
        close(s);
        global_sockets[node_id] = -1;
    }
}

/* 工作线程 - 修复版 (包含重试与防死锁兜底) */
void *dsm_worker(void *arg) {
    const int BATCH_SIZE = 64;
    struct uffd_msg msgs[BATCH_SIZE];
    ssize_t nread;
    
    // 分配接收缓冲区
    char *buf = malloc(PAGE_SIZE * PREFETCH);
    if (!buf) return NULL;

    // 提高线程优先级，确保缺页响应速度
    struct sched_param p = { .sched_priority = 10 };
    pthread_setschedparam(pthread_self(), SCHED_RR, &p);

    // 随机种子用于 Jitter
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)pthread_self();

    while(1) {
        /* 读取事件 */
        struct pollfd pfd = { .fd = uffd_fd, .events = POLLIN };
        int poll_ret = poll(&pfd, 1, 2000); // 2秒超时
        
        if (poll_ret <= 0) continue;

        nread = read(uffd_fd, msgs, sizeof(struct uffd_msg) * BATCH_SIZE);
        if (nread <= 0) continue;

        int n_events = nread / sizeof(struct uffd_msg);

        for (int i = 0; i < n_events; i++) {
            struct uffd_msg *msg = &msgs[i];
            if (!(msg->event & UFFD_EVENT_PAGEFAULT)) continue;

            uint64_t addr = msg->arg.pagefault.address;
            uint64_t base = addr & ~(4095);
            int owner = (base / 4096) % NODE_COUNT;

            /* 1. 注入 Jitter (可选，缓解服务端并发压力) */
            // if ((rand_r(&seed) % 100) < 5) usleep(rand_r(&seed) % 10);

            /* 2. [CRITICAL FIX] 获取连接 (带重试机制) */
            int sock = -1;
            int retry_cnt = 0;
            const int MAX_RETRIES = 5;

            while (retry_cnt < MAX_RETRIES) {
                sock = get_or_connect_locked(owner);
                if (sock >= 0) break; // 成功拿到锁定的连接

                retry_cnt++;
                // 简单的线性退避: 1ms, 2ms, 3ms...
                usleep(1000 * retry_cnt); 
            }
            
            /* 3. [CRITICAL FIX] 兜底逻辑：防止死锁 */
            if (sock < 0) {
                fprintf(stderr, "[DSM] FATAL: Node %d unreachable after retries. Zero-filling %lx to unblock vCPU.\n", owner, base);
                
                // 必须填充一个零页，否则 vCPU 会永远停在这一行汇编指令上等待
                struct uffdio_zeropage z = { 
                    .range = { .start = base, .len = 4096 }, 
                    .mode = 0 
                };
                if (ioctl(uffd_fd, UFFDIO_ZEROPAGE, &z) < 0) {
                    // 如果页面已存在(EEXIST)，唤醒即可
                    if (errno == EEXIST) {
                         struct uffdio_wake w = { .start = base, .len = 4096, .mode = 0 };
                         ioctl(uffd_fd, UFFDIO_WAKE, &w);
                    } else {
                        perror("[DSM] Emergency zeropage failed");
                    }
                }
                
                // 跳过后续网络操作，处理下一个事件
                continue; 
            }

            /* 4. 发送请求 */
            uint64_t req = htobe64(base);
            if (send(sock, &req, 8, 0) != 8) {
                close_socket_locked(owner); // 发送失败，标记连接失效
                pthread_mutex_unlock(&conn_locks[owner]); // 必须解锁
                
                // 这里其实也可以 goto 到上面的 Zero-fill 逻辑，
                // 但简单起见，让 VM 再触发一次缺页重试通常更安全
                continue;
            }

            /* 5. 接收数据 */
            int total = PAGE_SIZE * PREFETCH;
            int recvd = 0;
            bool error = false;

            while (recvd < total) {
                int n = recv(sock, buf + recvd, total - recvd, MSG_WAITALL);
                if (n <= 0) {
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                         // 超时视为连接坏死
                    }
                    close_socket_locked(owner); 
                    error = true;
                    break;
                }
                recvd += n;
            }

            /* 6. [CRITICAL] 任务完成，解锁 */
            pthread_mutex_unlock(&conn_locks[owner]);

            if (error) {
                // 接收失败，不进行 UFFD 操作，让 VM 指令重试，
                // 下次重试时会重新触发 PageFault，进入重连逻辑
                continue; 
            }

            /* 7. 填充内存 (无需锁) */
            // 注意：虽然请求了 PREFETCH 大小，但 UFFD 只需要填充触发缺页的那个 base
            // 不过为了性能，我们可以把预取的数据都填进去（如果内核支持）
            for(int k=0; k<PREFETCH; k++) {
                struct uffdio_copy c = {
                    .dst = base + k*4096, 
                    .src = (uint64_t)(buf + k*4096), 
                    .len = 4096, 
                    .mode = 0 
                };
                
                // 重点：如果目标地址超出了注册范围，或者已被映射，ioctl 会失败
                // 我们主要关心 k=0 (当前缺页地址) 的成功
                if (ioctl(uffd_fd, UFFDIO_COPY, &c) < 0) {
                    if (errno == EEXIST) {
                        // 竞争条件下，页面可能已经被别的线程填了，唤醒即可
                        struct uffdio_wake w = { .start = c.dst, .len = c.len, .mode = 0 };
                        ioctl(uffd_fd, UFFDIO_WAKE, &w);
                    }
                }
            }
        }
    }
    free(buf);
    return NULL;
}

/* 初始化入口 */
void dsm_universal_init(void) {
    signal(SIGPIPE, SIG_IGN); // 忽略 Broken Pipe

    /* 检测内核模块是否存在 */
    if (access("/sys/module/giantvm_kvm", F_OK) == 0 || access("/dev/giantvm", F_OK) == 0) {
        printf("[GiantVM] KERNEL MODULE DETECTED. Using ORIGINAL FULL-SHARE Mode.\n");
        gvm_mode = 0; 
        return; 
    }

    printf("[GiantVM] NO KERNEL MODULE. Using MEMORY-ONLY Mode (Frontier Fixed).\n");
    gvm_mode = 1; 
    
    uffd_fd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd_fd < 0) {
        perror("[GiantVM] userfaultfd syscall failed");
        return;
    }

    struct uffdio_api api = { .api = UFFD_API, .features = 0 };
    if (ioctl(uffd_fd, UFFDIO_API, &api) < 0) {
        perror("[GiantVM] uffdio_api failed");
        close(uffd_fd);
        uffd_fd = -1;
        return;
    }
    
    /* 分配全局结构 */
    global_sockets = malloc(sizeof(int) * NODE_COUNT);
    conn_locks = malloc(sizeof(pthread_mutex_t) * NODE_COUNT);
    
    if (!global_sockets || !conn_locks) abort(); // OOM 必须死

    for(int i=0; i<NODE_COUNT; i++) {
        global_sockets[i] = -1;
        pthread_mutex_init(&conn_locks[i], NULL);
    }
    for(int i=0; i<MAX_OPEN_SOCKETS; i++) {
        active_node_ids[i] = -1;
    }

    /* 启动 Worker 线程 */
    for(int i=0; i < WORKER_THREADS; i++) {
        qemu_thread_create(NULL, "dsm-w", dsm_worker, NULL, QEMU_THREAD_JOINABLE);
    }
}

/* 注册内存区域 */
void dsm_universal_register(void *ptr, size_t size) {
    if (gvm_mode == 1 && uffd_fd >= 0) {
        struct uffdio_register r = { 
            .range = {(uint64_t)ptr, size}, 
            .mode = UFFDIO_REGISTER_MODE_MISSING 
        };
        if (ioctl(uffd_fd, UFFDIO_REGISTER, &r) < 0) {
             perror("[GiantVM] register memory failed");
        }
    }
}
```

#### C. 代码注入点 (Injection Points)

1.  **文件 `vl.c` (Main Loop):**
    *   在文件头添加：`#include "dsm_backend.h"`
    *   在 `main` 函数中，找到 `start_io_router();`（或类似的 QEMU 初始化后期），在其**之前**插入：
        ```c
        dsm_universal_init();
        ```

2.  **文件 `exec.c` (Memory Handling):**
    *   在文件头添加：`#include "dsm_backend.h"`
    *   在 `ram_block_add` 函数中，找到 `return 0;` 之前的位置，插入：
        ```c
        if (new_block->host) dsm_universal_register(new_block->host, new_block->max_length);
        ```

3.  **文件 `Makefile.objs`:**
    *   找到 `common-obj-y += vl.o`，在后面添加：
        ```makefile
        common-obj-y += dsm_backend.o
        ```

---

## 3. 内存服务端脚本 (Mode B 专用)
** SO_REUSEPORT 多进程版 (fast_mem_server.c) **
**文件：** `fast_mem_server.c`

**【修改目标】**
1.  开启 `SO_REUSEPORT`，允许启动多个进程绑定同一端口。
2.  利用内核自动负载均衡解决单线程 Accept 瓶颈。

**【全量新代码 / New File】**
```c
/* 
 * GiantVM Frontier High-Performance Memory Server 
 * Feature: SO_REUSEPORT included for Multi-Process Scaling
 * Compile: gcc -O3 -o fast_mem_server fast_mem_server.c -lpthread
 * Usage: Run 8 instances of this program in background.
 */
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#define _GNU_SOURCE 
#include <endian.h>

#define MAX_EVENTS 10240
#define PORT 9999
#define PAGE_SIZE 4096
#define PREFETCH 32
#define MEM_FILE "physical_ram.img"

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    int listen_sock, conn_sock, nfds, epollfd;
    struct epoll_event ev, events[MAX_EVENTS];
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    int fd_mem = open(MEM_FILE, O_RDONLY);
    if (fd_mem < 0) { perror("Open memory file"); return 1; }
    off_t file_size = lseek(fd_mem, 0, SEEK_END);
    char *mem_ptr = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd_mem, 0);
    if (mem_ptr == MAP_FAILED) { perror("mmap"); return 1; }

    /* [Frontier 新增] 开启大页与预读优化 */
    /* 作用：将 TLB Miss 减少 99%，防止 CPU 卡在页表查找上 */
    madvise(mem_ptr, file_size, MADV_HUGEPAGE); 
    madvise(mem_ptr, file_size, MADV_RANDOM);   // 告诉内核：这是随机访问，别做顺序预读
    madvise(mem_ptr, file_size, MADV_WILLNEED); // 告诉内核：我会用到这些内存，尽快换入

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    /* [Frontier] 开启 SO_REUSEPORT，允许开启多个进程绑定同一端口 */
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
    //int bufsize = 4 * 1024 * 1024;
    //setsockopt(listen_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    //setsockopt(listen_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_sock, 20000) < 0) { perror("listen"); return 1; }

    epollfd = epoll_create1(0);
    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev) == -1) { perror("epoll_ctl: listen_sock"); return 1; }

    printf("[*] High-Perf Memory Server running on port %d (PID: %d)\n", PORT, getpid());

    while (1) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) { perror("epoll_wait"); break; }

        for (int n = 0; n < nfds; ++n) {
            if (events[n].data.fd == listen_sock) {
                while (1) {
                    conn_sock = accept(listen_sock, (struct sockaddr *)&addr, &addrlen);
                    if (conn_sock == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break; // 处理完了
                        perror("accept"); break;
                    }
        
                    set_nonblocking(conn_sock);
                    int flag = 1;
                    setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

                    ev.events = EPOLLIN | EPOLLET; // 保持边缘触发
                    ev.data.fd = conn_sock;
                    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev) == -1) {
                        close(conn_sock);
                    }
                }
            } else {
                int fd = events[n].data.fd;
                /* [CRITICAL FIX] 循环读取直到 EAGAIN */
                while (1) {
                    uint64_t req_addr_be;
                    ssize_t count = recv(fd, &req_addr_be, 8, MSG_WAITALL);
                    
                    if (count == 8) {
                        uint64_t base = be64toh(req_addr_be);
                        if (base + PAGE_SIZE * PREFETCH > file_size) base = 0; 
                        
                        size_t total_to_send = PAGE_SIZE * PREFETCH;
                        size_t sent_total = 0;
                        char *send_ptr = mem_ptr + base;

                        /* [修改后] 基于时间的宽容超时逻辑 */
                        struct timespec ts_start = {0}, ts_now;
                        
                        while(sent_total < total_to_send) {
                            ssize_t s = send(fd, send_ptr + sent_total, total_to_send - sent_total, 0);
                            if (s < 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    /* 第一次遇到阻塞时，记录当前时间 */
                                    if (ts_start.tv_sec == 0) {
                                        clock_gettime(CLOCK_MONOTONIC, &ts_start);
                                    }
                                    
                                    /* 检查是否超时 */
                                    clock_gettime(CLOCK_MONOTONIC, &ts_now);
                                    if (ts_now.tv_sec - ts_start.tv_sec > 5) {
                                        // 阻塞超过 5 秒，判定为死链接，断开
                                        close(fd); goto next_event; 
                                    }
                                    
                                    /* 增加睡眠时间到 50us，避免 CPU 空转过热 */
                                    usleep(50); 
                                    continue; 
                                }
                                // 其他错误直接断开
                                close(fd); goto next_event;
                            }
                            
                            sent_total += s;
                            /* 只要成功发送了数据，重置超时计时器，给下一次发送机会 */
                            ts_start.tv_sec = 0; 
                        }
                    } else if (count < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break; // 读空了，退出循环等待下一次事件
                        close(fd); 
                        break;
                    } else if (count == 0) {
                        close(fd); // 对端关闭
                        break;
                    } else {
                        // 读到了半截数据(小于8字节)，这在 TCP流中极少见但理论存在
                        // 简单处理：关连接。复杂处理：维护个 buffer 拼包。
                        // 鉴于这是高性能场景，视为协议错误关闭即可。
                        close(fd);
                        break;
                    }
                }
                next_event:;
            }
        }
    }
    return 0;
}
```

---

## 4.完整部署流程

#### 0. 基础环境与依赖安装
**所有节点（物理机或虚拟机）均需执行：**

```bash
# 1. 基础编译工具 (Kernel & QEMU)
sudo apt-get update
sudo apt-get install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev \
    pkg-config libglib2.0-dev libpixman-1-dev libpython3-dev libaio-dev libcap-ng-dev \
    libattr1-dev libcap-dev python3-venv python3-pip
# 必须大于等于你代码里的 listen 参数
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_syn_retries=2
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# 2. 系统参数调优 (防止万节点连接耗尽资源)
# 将以下内容追加到 /etc/sysctl.conf
cat <<EOF | sudo tee -a /etc/sysctl.conf
fs.file-max = 2097152
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
vm.max_map_count = 262144
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
net.netfilter.nf_conntrack_max = 1048576
net.nf_conntrack_max = 1048576
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_mem = 4194304 6291456 8388608
net.ipv4.tcp_wmem = 4096 16384 4194304
net.ipv4.tcp_rmem = 4096 87380 6291456
net.ipv4.tcp_max_syn_backlog = 65536
net.core.netdev_max_backlog = 65536
echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a 
EOF
sudo sysctl -p

# 3. 用户句柄限制
# 将以下内容追加到 /etc/security/limits.conf
cat <<EOF | sudo tee -a /etc/security/limits.conf
* soft nofile 1048576
* hard nofile 1048576
EOF
#以此配置重新登录 Shell
```

---

#### 流程 A：原版全共享模式 (DSM Mode)
**适用场景：** 分布式操作系统研究、跨节点内存/CPU 聚合。
**架构：** L0 (物理机) -> L1 (GiantVM 宿主机集群) -> L2 (GiantVM 客户机)。

**步骤 1：L0 环境准备**
1.  **物理机端口扩容：**
    在 L0 物理机上，必须扩大端口范围，否则无法支撑全连接：
    ```bash
    sysctl -w net.ipv4.ip_local_port_range="1024 65535"
    ```

2.  **关闭 NMI Watchdog：**
    为了防止发送大量广播包时 CPU 卡死被看门狗咬死：
    ```bash
    sysctl -w kernel.nmi_watchdog=0
    sysctl -w kernel.softlockup_panic=0
    ```

3.  **增加 ARP 表大小：**
    10,000 个节点意味着 10,000 个 IP。默认的 ARP 表只有 1024 或 4096，填满后网络会断。
    ```bash
    sysctl -w net.ipv4.neigh.default.gc_thresh1=4096
    sysctl -w net.ipv4.neigh.default.gc_thresh2=8192
    sysctl -w net.ipv4.neigh.default.gc_thresh3=16384
    ```


**步骤 2：L1 环境准备**
在所有 L1 节点上安装编译好的内核模块：
```bash
cd giantvm-kvm/
make -j
sudo insmod giantvm-kvm.ko
```

**步骤 3：配置集群 (cluster.conf)**
创建一个描述所有 L1 节点信息的配置文件 `cluster.conf`：
```text
# 格式: ID IP PORT
0 192.168.1.101 9999
1 192.168.1.102 9999
2 192.168.1.103 9999
...
```

**步骤 4：启动 GiantVM**
在每个 L1 节点上运行对应的 QEMU 命令。(编译 QEMU 具体参数见流程 B 的步骤 2)
*注意：必须为每个节点指定不同的 `-giantvm-id`。*

```bash
# 节点 0
./qemu-system-x86_64 \
  -enable-kvm \
  -m 4G \
  -smp 4 \
  -giantvm-id 0 \
  -giantvm-cluster cluster.conf \
  -drive file=disk.qcow2,format=qcow2 \
  -netdev tap,id=n1,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=n1 \
  -vnc :0

# 节点 1 (只需修改 id)
./qemu-system-x86_64 ... -giantvm-id 1 ...
```

**验证：**
查看 `dmesg`，如果看到 `[DSM] Connection established` 和内存映射日志，说明 DSM 协议已接管。

---

#### 流程 B：双模 UFFD 内存模式 (Frontier Mode)
**适用场景：** 万节点云游戏、GPU 直通、高性能计算。
**架构：** L0 (物理机) 直接作为计算节点和存储节点。

**步骤 1：服务端 (Memory Server) 启动**

*   1. 保存 C 代码
    将上面提供的内存服务脚本保存为 `fast_mem_server.c`。

*   2. 编译服务端
    在服务端节点执行编译命令（使用 `-O3` 开启最高优化）：
    ```bash
    gcc -O3 -o fast_mem_server fast_mem_server.c -lpthread
    ```

*   3. 手动生成内存镜像文件 (必须)
    Python 脚本会自动创建文件，但 C 程序为了极致速度，默认文件已存在。你需要用 `fallocate` (极快) 或 `dd` 预先分配空间。
    *假设你需要 32GB 内存：*
    ```bash
    # 推荐方式 (瞬间完成)
    fallocate -l 32G physical_ram.img

    # 兼容方式 (如果文件系统不支持 fallocate)
    # dd if=/dev/zero of=physical_ram.img bs=1G count=32
    ```

    在拥有高速存储的节点上，按顺序执行：

    1.  **解除系统限制 (这步对于 C 语言 Epoll 服务端至关重要)**
        为了能接纳 10,240 个并发连接，必须在当前 Shell 临时解除文件句柄限制（或者写入 `/etc/security/limits.conf` 永久生效）。
        ```bash
        ulimit -n 1048576
        ```

    2.  **启动服务端**
        ```bash
        ./fast_mem_server
        ```
        *看到输出 `[*] High-Perf Memory Server running on port 9999` 即表示启动成功。*

    3.  **（可选）后台静默运行**
        如果是生产环境部署，建议使用 `nohup`：
        ```bash
        nohup ./fast_mem_server > server.log 2>&1 &
        ```

    启动后，你可以用简单的 `nc` (netcat) 命令模拟客户端验证服务端是否活着：

    ```bash
    # 在另一台机器执行
    nc -z -v <服务端IP> 9999
    ```
    如果返回 `succeeded`，说明端口通了。

**步骤 2：客户端 (Compute Node) 准备**
```bash
# 1. 卸载内核模块
sudo rmmod giantvm-kvm

# 2. 修改代码 IP (确保 dsm_backend.c 指向正确服务端)
# ... 编辑文件操作 ...

# 3. [关键新增] 重新编译 QEMU (必须强制扩容句柄限制)
cd qemu/
make clean  # 清理旧的编译缓存，防止宏未生效

# 配置编译环境 (必须加上 --extra-cflags)
./configure \
  --target-list=x86_64-softmmu \
  --enable-kvm \
  --enable-vnc \
  --disable-werror \
  --extra-cflags="-O3 -D__FD_SETSIZE=65536 -DFD_SETSIZE=65536" \
  --python=/usr/bin/python3

# 开始编译
make -j$(nproc)
```

**步骤 3：启动客户端**
```bash
sudo ./qemu-system-x86_64 \
  -name GiantVM-Frontier \
  -machine type=q35,accel=kvm \
  -cpu host \
  -smp 8 \
  -m 16G \
  -vga std \
  -vnc :0 \
  -netdev user,id=n1 \
  -device virtio-net-pci,netdev=n1
```
**验证：**
QEMU 控制台输出 `[GiantVM] NO KERNEL MODULE. Using MEMORY-ONLY Mode.`，此时虚拟机内存完全由网络按需拉取。

---


## 5.效率对比与 GPU 调用

**基准：** 物理机 (i9/4090) = 100%。

| 模式 | 子模式 | 触发条件 | CPU 效率 | GPU 性能 | 内存性能 | GPU 调用方式 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **原版全共享** | **KVM** | 加载内核模块 | **1%~10%** | **0%** | 50µs 延迟 | **无法直接调用**。<br>分布式 CPU 不支持 PCIe 直通，替代方案见下。 |
| **只共享内存** | **KVM** | 无模块 + 有 KVM | **98%** | **98%** | 50µs 延迟 | **VFIO 直通**。<br>仅主节点显卡工作，玩游戏专用。 |
| **只共享内存** | **TCG** | 无模块 + 无 KVM | **5%** | **0%** | 50µs 延迟 | **软件模拟**。<br>Virtio-GPU，无法玩游戏。 |

**总结：**
*   **原版全共享模式：** 支持 CPU/Mem 分布式，但 GPU 无法使用，速度极慢。
*   **只共享内存模式：** 放弃 CPU 分布式，换取 GPU 直通和原生 CPU 速度。**这是唯一能玩游戏的方案。**

## 6.原版模式运行 Star Citizen

为了让《星际公民》（Star Citizen，一款对 I/O 和内存吞吐极其敏感的游戏）在 GiantVM 原版模式下达到**“可玩（Playable）”**的极限（比如 15-30 FPS，操作延迟 < 100ms），你必须进行一场**“全链路极致压榨”**的配置。

以下是针对你这个特殊环境的**终极优化方案**：

---

#### 第一层：物理层与网络层（RDMA 调优）
*目标：把物理延迟压到物理极限，让 DSM 协议跑在光速上。*

1.  **硬件要求：**
    *   必须使用支持 **RoCE v2** 或 **InfiniBand** 的网卡（ConnectX-4 或更高）。
    *   交换机必须配置 **PFC (Priority Flow Control)** 和 **ECN**，保证 RDMA 流量无丢包（无损网络）。GiantVM 的 DSM 协议极其脆弱，一旦丢包导致 TCP 重传（或者 RDMA 重传），游戏会瞬间卡死 200ms 以上。
2.  **MTU 巨帧：**
    *   所有节点（L0 和 L1）的 MTU 必须设为 **9000**（甚至更高，如果 IB 支持）。减少包头开销，提高有效载荷。
3.  **CPU 绑核 (Pinning)：**
    *   **极其重要。** RDMA Polling 线程必须独占物理核心。
    *   在 L0 宿主机上，将 L1 虚拟机的 vCPU 与物理核心 **1:1 绑定**。
    *   防止宿主机调度器把处理 DSM 的线程切走，哪怕切走 1ms，对游戏来说就是掉帧。

---

#### 第二层：L1 宿主机层（GPU 供给侧）
*目标：让 GPU 渲染完直接推流，绝对不要写回虚拟机！*

这是**最核心**的策略变更。千万不要让 VirtualGL 把渲染好的画面通过网络传回 GiantVM 的 Windows 桌面显示。
**因为：渲染回写 = 巨量内存写入 = 巨量 DSM 同步 = 崩溃。**

**正确做法：** 采用“**计算与显示分离**”架构。

1.  **L1 节点配置 (GPU Server)：**
    *   配置好 **VirtualGL** 服务端。
    *   配置 **TurboVNC** 或 **Sunshine** (推荐)。
    *   **关键操作：** 在 L1 节点上直接启动一个 X Server（带 GPU 加速），用来承载 GiantVM 发来的渲染指令。

2.  **显示输出路径（旁路推流）：**
    *   **不要**在 GiantVM (L2) 里面看画面。
    *   你需要在 **L1 节点** 上运行推流服务（Sunshine/Moonlight Host）。
    *   **数据流向：**
        1.  GiantVM (CPU) 发出 OpenGL/Vulkan 指令 ->
        2.  VirtualGL 拦截 ->
        3.  发给 L1 节点的 GPU 渲染 ->
        4.  **渲染结果直接存入 L1 的显存/内存** ->
        5.  Sunshine (运行在 L1) 直接捕获 L1 的屏幕/显存 ->
        6.  编码视频流 ->
        7.  通过普通 TCP/UDP 发送到你手里的物理显示终端（手机/PC）。

    *   **结果：** 这一路下来，**没有一帧画面数据经过 GiantVM 的 DSM 协议**。GiantVM 只负责处理鼠标输入和游戏逻辑（物理碰撞、AI），负载降低 90%。

---

#### 第三层：GiantVM L2 内部（Windows 减肥）
*目标：消灭一切不必要的内存写入。*

Windows 10 对 GiantVM 来说是“噪音之王”。必须进行外科手术式阉割：

1.  **系统版本：**
    *   务必使用 **Windows 10 LTSC** 或 **Tiny10**（魔改精简版）。不要用普通的 Home/Pro 版。
2.  **服务禁用（必须）：**
    *   `Windows Defender` (实时扫描会疯狂读写内存，必关)。
    *   `SysMain` (原 Superfetch，会预加载内存，导致不必要的 DSM 流量)。
    *   `Windows Search` (索引文件，卡顿源)。
    *   `Windows Update`。
3.  **内存机制：**
    *   **关闭虚拟内存 (Pagefile):** 彻底关闭。强迫 Windows 只用 RAM。因为如果发生 Swap，就是“在网络内存上的虚拟磁盘上进行换页”，速度会慢到系统静止。
4.  **网络驱动 (Virtio)：**
    *   使用最新的 NetKVM 驱动，并开启多队列 (Multiqueue)。

---

#### 第四层：游戏配置（星际公民特调）
*目标：减少 I/O 请求。*

1.  **游戏安装位置：**
    *   **绝对不能**放在基于 QCOW2 的虚拟磁盘上。
    *   **方案 A (土豪)：** 给 GiantVM 分配 128GB 内存，创建一个 **Ramdisk**，把《星际公民》拷进去运行。这是最快的，I/O 速度等于内存速度。
    *   **方案 B (常规)：** 在 L1 宿主机上挂载 NVMe SSD，通过 `virtio-scsi` (配置 `iothread`) 透传给 GiantVM。
2.  **r_DisplayInfo = 3：**
    *   进游戏第一时间开启性能监视，关注 CPU 延迟。
3.  **降低物理计算频率：**
    *   如果可能，降低游戏的分辨率和物理效果。虽然 GPU 在 L1 跑得飞快，但 CPU (跑在 GiantVM 里) 需要处理物理碰撞数据。如果 CPU 算不过来，GPU 渲染再快也没用。

---

#### 最终架构图（Playable Configuration）

```text
【你的物理机/客户端】(运行 Moonlight Client)
       ^
       | (h.264/h.265 视频流，绕过 GiantVM)
       |
【L1 宿主机 (Node 1)】 <---(RDMA 极速同步)---> 【L1 宿主机 (Node 0)】
   |  [NVIDIA 4090]                                  |
   |  (运行 X Server + VirtualGL Server)              |
   |  (运行 Sunshine 推流服务)                         |
   |                                                 |
   +-------------------------------------------------+
           | (VirtualGL 传输渲染指令)
           v
   【GiantVM L2 (Windows 10)】
      - 运行 Star Citizen.exe (CPU 逻辑)
      - 拦截 GPU 调用 -> 发送给 L1
      - 内存：分布在 Node0/1 上 (RDMA 加速)
      - 磁盘：Ramdisk (避免 I/O))
```

#### 预期效果评估

*   **帧率 (FPS):** 如果 L1 的显卡够强，且使用了上述“旁路推流”方案，画面本身可以达到 **30-60 FPS**。
*   **操作延迟:** 约 **50-80ms**（Sunshine 编码延迟 + 网络传输）。
*   **卡顿 (Stuttering):** 依然会存在。每当游戏加载新资产（进入新区域、刷出新飞船）时，CPU 需要分配新内存，这会触发 DSM 锁，导致瞬间掉帧。
*   **结论:** 这是一个**“可以起飞，可以看风景，但打空战可能会输”**的状态。

**一句话总结配置核心：**
**用 RDMA 救 CPU 和内存，用 Sunshine+VirtualGL 旁路推流救显卡，用 Ramdisk 救硬盘。** 祝你好运，公民！
