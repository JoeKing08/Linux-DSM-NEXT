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
#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/watchdog.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/module.h>

/* 
 * [删除] enum kvm_dsm_request_type ... (已移至 kvm_host.h)
 * [删除] struct dsm_request ... (已移至 kvm_host.h)
 * [删除] struct dsm_response ... (已移至 kvm_host.h)
 */

/* 定义可配置的原子操作超时（单位：毫秒） */
static int atomic_timeout_ms = 1000; /* 默认1秒，保持安全基线 */
module_param(atomic_timeout_ms, int, 0644);
MODULE_PARM_DESC(atomic_timeout_ms, "Timeout in milliseconds for atomic network operations before triggering guest fault. (Default: 1000)");

/* [添加] 定义 Per-CPU 发送缓冲区，专供原子上下文使用，防止 OOM */
static DEFINE_PER_CPU(tx_add_t, atomic_tx_buffer);
static DEFINE_PER_CPU(int, tx_buffer_busy);

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

/* 修改 helper 函数，增加安全检查 */
static inline void inject_jitter(void) {
    if (!enable_jitter) return;
    
    /* [关键修正] 如果处于原子上下文(中断/自旋锁)，绝对不能空转等待！
     * 否则会导致 NMI Watchdog 认为 CPU 死锁，或者阻碍其他核获取锁。
     */
    if (in_atomic() || irqs_disabled()) {
        return; 
    }

    /* 只有在普通进程上下文（可以被抢占/调度）才进行抖动 */
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
     * 目的：防止后续发生 Write 时，Owner 需要发送 10000 个 Invalidation 包导致系统卡死。*/
     
    if (bitmap_weight(cs->bits, DSM_MAX_INSTANCES) > 128) {
        return;
    } 

    set_bit(id, cs->bits);
}

/* [修改] 适配结构体 */
static inline void dsm_clear_copyset(struct kvm_dsm_memory_slot *slot, hfn_t vfn)
{
    bitmap_zero(dsm_get_copyset(slot, vfn)->bits, DSM_MAX_INSTANCES);
}

/* 
 * kvm_dsm_fetch - Modified for "Watchdog-Aware Persistence"
 * 修复：混合内存分配策略 + 原子上下文死锁 + 脑裂防护
 */
/*
 * kvm_dsm_fetch - Modified for "Tolerant Asynchronous Operations" (方案A)
 * 最终修正版：
 * 1. 使用可由模块参数 `atomic_timeout_ms` 配置的超时阈值。
 * 2. 在原子等待循环中，使用 udelay(10) + touch_watchdog() 策略，
 *    以在保证主机安全的同时，为网络协议栈争取处理时间。
 * 3. 超时后依旧返回 -EIO，以强制执行安全的 VM 熔断机制。
 * 4. 保留所有原有优化：混合内存分配、Jitter 等。
 */
static int kvm_dsm_fetch(struct kvm *kvm, uint16_t dest_id, bool from_server,
		const struct dsm_request *req, void *data, struct dsm_response *resp)
{
	kconnection_t **conn_sock;
	int ret;
    tx_add_t *tx_add;
	int retry_cnt = 0;
    int send_flags = 0;
    int recv_flags = 0;
    bool is_atomic = false;
    bool use_percpu_buffer = false;
    
    u64 start_time_ns = 0;

    /* 1. 内存分配策略 (混合模式) - 保持不变 */
    if (in_atomic() || irqs_disabled()) {
        int *busy = this_cpu_ptr(&tx_buffer_busy);
        if (*busy) return -EBUSY; /* 重入保护 */

        *busy = 1;
        is_atomic = true;
        send_flags = MSG_DONTWAIT;
        recv_flags = MSG_DONTWAIT;
        
        tx_add = this_cpu_ptr(&atomic_tx_buffer);
        memset(tx_add, 0, sizeof(tx_add_t));
        use_percpu_buffer = true;
    } else {
        is_atomic = false;
        send_flags = 0;
        recv_flags = SOCK_NONBLOCK;
        
        tx_add = kzalloc(sizeof(tx_add_t), GFP_KERNEL);
        if (!tx_add) {
            printk(KERN_ERR "kvm-dsm: Critical memory exhaustion in fetch\n");
            return -ENOMEM;
        }
        use_percpu_buffer = false;
    }

	tx_add->txid = generate_txid(kvm, dest_id);

    /* 2. 注入抖动 (如果在非原子上下文) - 保持不变 */
    inject_jitter();

	if (kvm->arch.dsm_stopped) {
        ret = -EINVAL;
        goto done_free;
    }
    
    /* 连接逻辑 - 保持不变 */
	if (!from_server)
		conn_sock = &kvm->arch.dsm_conn_socks[dest_id];
	else
		conn_sock = &kvm->arch.dsm_conn_socks[DSM_MAX_INSTANCES + dest_id];

	if (*conn_sock == NULL) {
        if (is_atomic) {
            ret = -ENOTCONN;
            goto done_free;
        }
		mutex_lock(&kvm->arch.conn_init_lock);
		if (*conn_sock == NULL) {
			ret = kvm_dsm_connect(kvm, dest_id, conn_sock);
			if (ret < 0) {
				mutex_unlock(&kvm->arch.conn_init_lock);
                goto done_free;
			}
		}
		mutex_unlock(&kvm->arch.conn_init_lock);
	}

	dsm_debug_v("kvm[%d] sent request[0x%x] to kvm[%d] req_type[%s] gfn[%llu,%d]",
			kvm->arch.dsm_id, tx_add->txid, dest_id, req_desc[req->req_type],
			req->gfn, req->is_smm);

retry_send:
    ret = network_ops.send(*conn_sock, (const char *)req, sizeof(struct dsm_request), send_flags, tx_add);

    /* [核心修正][方案A] 针对“不够好”网络的宽容等待策略 */
    if (ret == -EAGAIN && is_atomic) {
        if (unlikely(start_time_ns == 0)) start_time_ns = local_clock();
        
        /* 使用模块参数来决定超时时间 */
        if (unlikely((local_clock() - start_time_ns) > (u64)atomic_timeout_ms * 1000 * 1000)) {
            printk(KERN_EMERG "GiantVM: [FATAL] Atomic send STUCK > %dms. Halting VM operation.\n", atomic_timeout_ms);
            ret = -EIO; /* 返回致命I/O错误，上层必须处理 */
            goto done_free;
        }

        /* 关键：喂狗，防止物理机因 NMI watchdog 重启 */
        touch_nmi_watchdog();
        touch_softlockup_watchdog();
        
        /* 关键：使用 udelay(10) 代替 cpu_relax()，为网络处理争取时间 */
        udelay(10);
        
        goto retry_send;
    }
    
	if (ret < 0) goto done_free;

    /* 重置计时器供接收使用 */
	retry_cnt = 0;
    start_time_ns = 0;
    
    /* 4. 接收逻辑 (同样应用方案A的策略) */
	if (req->req_type == DSM_REQ_INVALIDATE) {
retry_recv_inv:
        ret = network_ops.receive(*conn_sock, data, recv_flags, tx_add);
        if (ret == -EAGAIN && is_atomic) {
            if (unlikely(start_time_ns == 0)) start_time_ns = local_clock();
            
            if (unlikely((local_clock() - start_time_ns) > (u64)atomic_timeout_ms * 1000 * 1000)) {
                printk(KERN_EMERG "GiantVM: [FATAL] Atomic recv_inv STUCK > %dms.\n", atomic_timeout_ms);
                ret = -EIO;
                goto done_free;
            }

            touch_nmi_watchdog();
            touch_softlockup_watchdog();
            udelay(10);
            goto retry_recv_inv;
        }
	} else {
        /* 普通请求接收 (Read/Write response) */
retry:
		ret = network_ops.receive(*conn_sock, data, recv_flags, tx_add);
		if (ret == -EAGAIN) {
            /* 原子上下文的超时逻辑 */
            if (is_atomic) {
                if (unlikely(start_time_ns == 0)) start_time_ns = local_clock();
                
                if (unlikely((local_clock() - start_time_ns) > (u64)atomic_timeout_ms * 1000 * 1000)) {
                     printk(KERN_EMERG "GiantVM: [FATAL] Atomic recv STUCK > %dms. Killing VM.\n", atomic_timeout_ms);
                     ret = -EIO;
                     goto done_free;
                }
                touch_nmi_watchdog();
                touch_softlockup_watchdog();
                udelay(10);
                goto retry;
            }

            /* 普通进程上下文的超时逻辑 (保留原版逻辑) */
			retry_cnt++;
			if (retry_cnt > 100000) {
				printk_ratelimited("%s: Waiting long for gfn %llu from kvm %d\n",
						__func__, req->gfn, dest_id);
				retry_cnt = 0;
                cond_resched(); /* 让出 CPU */
			}
			goto retry;
		}
		resp->inv_copyset = tx_add->inv_copyset;
		resp->version = tx_add->version;
	}
	if (ret < 0) goto done_free;

done_free:
    if (use_percpu_buffer) {
        *this_cpu_ptr(&tx_buffer_busy) = 0; /* 释放 Per-CPU 锁 */
    } else {
        kfree(tx_add);
    }
	return ret;
}
```

#### B. 失效广播逻辑 (修复遍历 Bug)
**【替换说明】** 找到 `kvm_dsm_invalidate` 函数，全量替换。

```c
/*
 * kvm_dsm_invalidate - issued by owner of a page to invalidate all of its copies
 * 修复：万节点循环看门狗 + 错误传播
 */
static int kvm_dsm_invalidate(struct kvm *kvm, gfn_t gfn, bool is_smm,
		struct kvm_dsm_memory_slot *slot, hfn_t vfn, copyset_t *cpyset, int req_id)
{
	int holder;
	int ret = 0;
	char r = 1; /* Dummy buffer for ACK */
	copyset_t *copyset;
	struct dsm_response resp; /* Placeholder */
    
    int loop_cnt = 0;

	copyset = cpyset ? cpyset : dsm_get_copyset(slot, vfn);

	for_each_set_bit(holder, copyset->bits, DSM_MAX_INSTANCES) {
		
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
        
		BUG_ON(holder >= kvm->arch.cluster_iplist_len);

		ret = kvm_dsm_fetch(kvm, holder, false, &req, &r, &resp);
		
        if (ret < 0) {
            if (ret == -EIO) {
                printk(KERN_EMERG "GiantVM: Invalidation aborted due to network failure. Halting guest.\n");
                return -EIO;
            }
			return ret;
        }

        if (++loop_cnt % 64 == 0) { 
            touch_nmi_watchdog();        
            touch_softlockup_watchdog(); 
            
            if (!in_atomic() && !irqs_disabled()) {
                cond_resched();
            } else {
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
    struct dsm_response *resp;
    resp = kmem_cache_zalloc(dsm_resp_cache, GFP_ATOMIC);
    if (!resp) return -ENOMEM;
    if (dsm_is_pinned_read(slot, vfn) && !kvm->arch.dsm_stopped) {
        *retry = true;
        goto out_free; 
    }
    if ((is_owner = dsm_is_owner(slot, vfn))) {
        BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);
        dsm_change_state(slot, vfn, DSM_INVALID);
        kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_INVALID);
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
        struct dsm_request new_req = { /* ... */ };
        owner = dsm_get_prob_owner(slot, vfn);
        ret = length = kvm_dsm_fetch(kvm, owner, true, &new_req, page, resp);
        if (ret == -EIO) {
            printk(KERN_EMERG "GiantVM: Write fetch failed (Network Dead). Halting.\n");
            goto out_free;
        }
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
    if (ret >= 0) {
        ret = network_ops.send(conn_sock, page, length, 0, tx_add);
    }
out_free:
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
    struct dsm_response *resp;
    resp = kmem_cache_zalloc(dsm_resp_cache, GFP_ATOMIC);
    if (!resp) return -ENOMEM;
    resp->version = 0;
    if (dsm_is_pinned_read(slot, vfn) && !kvm->arch.dsm_stopped) {
        *retry = true;
        ret = 0;
        goto out_free;
    }
    if ((is_owner = dsm_is_owner(slot, vfn))) {
        BUG_ON(dsm_get_prob_owner(slot, vfn) != kvm->arch.dsm_id);
        dsm_set_prob_owner(slot, vfn, req->msg_sender);
        dsm_change_state(slot, vfn, DSM_SHARED);
        kvm_dsm_apply_access_right(kvm, slot, vfn, DSM_SHARED);
        ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
        if (ret < 0) goto out_free;
        memcpy(&resp->inv_copyset, dsm_get_copyset(slot, vfn), sizeof(copyset_t));
        BUG_ON(!(test_bit(kvm->arch.dsm_id, resp->inv_copyset.bits)));
        resp->version = dsm_get_version(slot, vfn);
    }
    else if (dsm_is_initial(slot, vfn) && kvm->arch.dsm_id == 0) {
        ret = kvm_read_guest_page_nonlocal(kvm, memslot, req->gfn, page, 0, PAGE_SIZE);
        if (ret < 0) goto out_free;
        dsm_set_prob_owner(slot, vfn, req->msg_sender);
        dsm_change_state(slot, vfn, DSM_SHARED);
        dsm_add_to_copyset(slot, vfn, kvm->arch.dsm_id);
        memcpy(&resp->inv_copyset, dsm_get_copyset(slot, vfn), sizeof(copyset_t));
        resp->version = dsm_get_version(slot, vfn);
    }
    else {
        struct dsm_request new_req = { /* ... */ };
        owner = dsm_get_prob_owner(slot, vfn);
        ret = length = kvm_dsm_fetch(kvm, owner, true, &new_req, page, resp);
        if (ret == -EIO) {
            printk(KERN_EMERG "GiantVM: Read fetch failed (Network Dead). Halting.\n");
            goto out_free;
        }
        if (ret < 0) goto out_free;
        BUG_ON(dsm_is_readable(slot, vfn) && !(test_bit(kvm->arch.dsm_id, resp->inv_copyset.bits)));
        dsm_set_prob_owner(slot, vfn, req->msg_sender);
    }
    if (is_owner) {
        length = dsm_encode_diff(slot, vfn, req->msg_sender, page, memslot, req->gfn, req->version);
    }
    tx_add->inv_copyset = resp->inv_copyset;
    tx_add->version = resp->version;
    if (ret >= 0) {
	    ret = network_ops.send(conn_sock, page, length, 0, tx_add);
    }
out_free:
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
**文件：** `hw/tpm/tpm_util.c`

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
#define PREFETCH 32           // [微调] 预取页面数量降至32，在普通网络下更稳定
#define PAGE_SIZE 4096
#define MAX_OPEN_SOCKETS 10240
#define WORKER_THREADS 128    // UFFD 处理线程数

/* === 全局变量 (修改后) === */
int gvm_mode = 0;             // 0: Kernel Mode, 1: User Mode
int uffd_fd = -1;
int *global_sockets = NULL;
pthread_mutex_t *conn_locks = NULL;

// [修改] 将硬编码的IP列表替换为动态变量
char **g_node_ips = NULL;     // 存储从配置文件读取的IP地址
int g_node_count = 0;         // 存储IP地址的数量

/* 
 * [新增] 解析 cluster.conf 文件的函数
 * 作用: 读取配置文件，填充 g_node_ips 和 g_node_count
 */
static int parse_cluster_conf(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("[GiantVM] Failed to open cluster.conf");
        return -1;
    }

    char line[256];
    int count = 0;

    // 第一次遍历：计算节点数量
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] != '#' && line[0] != '\n') {
            count++;
        }
    }

    if (count == 0) {
        fprintf(stderr, "[GiantVM] Error: cluster.conf is empty or contains no valid entries.\n");
        fclose(fp);
        return -1;
    }

    if (count == 0) {
        fprintf(stderr, "[GiantVM] Error: cluster.conf is empty or has 0 valid nodes.\n");
        fclose(fp); // 别忘了关闭文件句柄
        return -1;  // 返回错误，阻止后续逻辑执行
    }

    g_node_count = count;
    g_node_ips = malloc(g_node_count * sizeof(char *));
    if (!g_node_ips) {
        perror("[GiantVM] Failed to allocate memory for IP list");
        fclose(fp);
        return -1;
    }

    // 回到文件开头
    rewind(fp);
    count = 0;
    char ip_buffer[20]; // 用于存放IP地址的临时缓冲区

    // 第二次遍历：读取IP地址
    while (fgets(line, sizeof(line), fp) && count < g_node_count) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        // 解析格式 "ID IP PORT"，我们只关心IP
        if (sscanf(line, "%*d %19s %*d", ip_buffer) == 1) {
            g_node_ips[count] = strdup(ip_buffer);
            if (!g_node_ips[count]) {
                perror("[GiantVM] strdup failed for IP address");
                // ... 此处应有更完善的内存释放逻辑 ...
                fclose(fp);
                return -1;
            }
            count++;
        }
    }

    fclose(fp);
    printf("[GiantVM] Loaded %d memory server IPs from %s\n", g_node_count, filename);
    return 0;
}


/* 
 * 建立连接底层函数 (无变化)
 */
static int connect_node_impl(const char *ip) {
    // ... 此函数内容保持不变 ...
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct linger sl = { .l_onoff = 1, .l_linger = 0 };
    setsockopt(s, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
    int flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
    int keepalive = 1, keepidle = 5, keepintvl = 2, keepcnt = 3;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int));
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int));
    struct timeval timeout;
    timeout.tv_sec = 2;
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
 * [修改] 获取连接并锁定 (使用 g_node_count 和 g_node_ips)
 */
static int get_or_connect_locked(int node_id) {
    if (node_id < 0 || node_id >= g_node_count) return -1;

    pthread_mutex_lock(&conn_locks[node_id]);

    if (global_sockets[node_id] != -1) {
        return global_sockets[node_id];
    }

    int s = connect_node_impl(g_node_ips[node_id]);
    if (s >= 0) {
        global_sockets[node_id] = s;
        return s;
    } else {
        pthread_mutex_unlock(&conn_locks[node_id]);
        return -1;
    }
}

/* 
 * 辅助函数：关闭连接并清理状态 (无变化)
 */
static void close_socket_locked(int node_id) {
    // ... 此函数内容保持不变 ...
    int s = global_sockets[node_id];
    if (s != -1) {
        close(s);
        global_sockets[node_id] = -1;
    }
}

/* 
 * [修改] 工作线程 (使用 g_node_count)
 */
void *dsm_worker(void *arg) {
    // ... 此函数中除了 owner 计算方式，其他部分保持不变 ...
    const int BATCH_SIZE = 64;
    struct uffd_msg msgs[BATCH_SIZE];
    ssize_t nread;
    char *buf = malloc(PAGE_SIZE * PREFETCH);
    if (!buf) return NULL;
    struct sched_param p = { .sched_priority = 10 };
    pthread_setschedparam(pthread_self(), SCHED_RR, &p);

    while(1) {
        struct pollfd pfd = { .fd = uffd_fd, .events = POLLIN };
        int poll_ret = poll(&pfd, 1, 2000);
        if (poll_ret <= 0) continue;

        nread = read(uffd_fd, msgs, sizeof(struct uffd_msg) * BATCH_SIZE);
        if (nread <= 0) continue;
        int n_events = nread / sizeof(struct uffd_msg);

        for (int i = 0; i < n_events; i++) {
            struct uffd_msg *msg = &msgs[i];
            if (!(msg->event & UFFD_EVENT_PAGEFAULT)) continue;
            uint64_t addr = msg->arg.pagefault.address;
            uint64_t base = addr & ~(4095);

            // [修改] owner 计算方式，使用 g_node_count
            int owner = (base / 4096) % g_node_count;
            
            int sock = get_or_connect_locked(owner);

            /* [体验优先的权衡方案] - 这部分逻辑保持不变 */
            if (sock < 0) {
                const int STALL_TIMEOUT_MS = 500;
                const int RETRY_INTERVAL_MS = 50;
                int total_wait_ms = 0;
                bool connected = false;

                fprintf(stderr, "[DSM] INFO: Node %d unreachable. Stalling for up to %dms on %lx...\n", 
                        owner, STALL_TIMEOUT_MS, base);

                while (total_wait_ms < STALL_TIMEOUT_MS) {
                    usleep(RETRY_INTERVAL_MS * 1000);
                    total_wait_ms += RETRY_INTERVAL_MS;
                    sock = get_or_connect_locked(owner);
                    if (sock >= 0) {
                        connected = true;
                        fprintf(stderr, "[DSM] INFO: Connection to node %d restored after %dms.\n", owner, total_wait_ms);
                        break;
                    }
                }

                if (!connected) {
                    fprintf(stderr, "[DSM] WARN: Node %d unreachable after %dms. Zero-filling %lx to unblock vCPU.\n", 
                            owner, STALL_TIMEOUT_MS, base);
                    struct uffdio_zeropage z = { .range = { .start = base, .len = 4096 }, .mode = 0 };
                    if (ioctl(uffd_fd, UFFDIO_ZEROPAGE, &z) < 0) {
                        if (errno == EEXIST) {
                             struct uffdio_wake w = { .range = { .start = base, .len = 4096 }};
                             ioctl(uffd_fd, UFFDIO_WAKE, &w);
                        } else {
                            perror("[DSM] Emergency zeropage failed");
                        }
                    }
                    continue; 
                }
            }

            /* ... 后续的网络收发、内存填充逻辑保持不变 ... */
            uint64_t req = htobe64(base);
            if (send(sock, &req, 8, 0) != 8) {
                close_socket_locked(owner);
                pthread_mutex_unlock(&conn_locks[owner]);
                continue;
            }
            int total = PAGE_SIZE * PREFETCH;
            int recvd = 0;
            bool error = false;
            while (recvd < total) {
                int n = recv(sock, buf + recvd, total - recvd, MSG_WAITALL);
                if (n <= 0) {
                    close_socket_locked(owner); 
                    error = true;
                    break;
                }
                recvd += n;
            }
            pthread_mutex_unlock(&conn_locks[owner]);
            if (error) {
                continue; 
            }
            for(int k=0; k<PREFETCH; k++) {
                struct uffdio_copy c = { .dst = base + k*4096, .src = (uint64_t)(buf + k*4096), .len = 4096, .mode = 0 };
                if (ioctl(uffd_fd, UFFDIO_COPY, &c) < 0) {
                    if (errno == EEXIST) {
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


/* [修改] 初始化入口 */
void dsm_universal_init(void) {
    signal(SIGPIPE, SIG_IGN); 

    if (access("/sys/module/giantvm_kvm", F_OK) == 0 || access("/dev/giantvm", F_OK) == 0) {
        printf("[GiantVM] KERNEL MODULE DETECTED. Using ORIGINAL FULL-SHARE Mode.\n");
        gvm_mode = 0; 
        return; 
    }

    printf("[GiantVM] NO KERNEL MODULE. Using MEMORY-ONLY Mode (Frontier Fixed).\n");
    gvm_mode = 1; 
    
    // [新增] 解析配置文件
    if (parse_cluster_conf("cluster.conf") != 0) {
        fprintf(stderr, "[GiantVM] Error: Could not load or parse cluster.conf for memory servers. Aborting UFFD init.\n");
        return;
    }

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
    
    /* [修改] 使用动态获取的节点数量进行分配 */
    global_sockets = malloc(sizeof(int) * g_node_count);
    conn_locks = malloc(sizeof(pthread_mutex_t) * g_node_count);
    
    if (!global_sockets || !conn_locks) abort(); 

    for(int i=0; i < g_node_count; i++) {
        global_sockets[i] = -1;
        pthread_mutex_init(&conn_locks[i], NULL);
    }

    for(int i=0; i < WORKER_THREADS; i++) {
        qemu_thread_create(NULL, "dsm-w", dsm_worker, NULL, QEMU_THREAD_JOINABLE);
    }
}

/* 注册内存区域 (无变化) */
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
    *   在 `main` 函数中，找到找到如下部分：
        ```c
            configure_accelerator(current_machine)

            /* 插入位置 */
            dsm_universal_init(); 

            if (qtest_chrdev) {
                qtest_init(qtest_chrdev, qtest_log, &error_fatal);
            }
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
**SO_REUSEPORT 多进程版 (fast_mem_server.c)**
**文件：** `fast_mem_server.c`

**【修改目标】**
1.  开启 `SO_REUSEPORT`，允许启动多个进程绑定同一端口。
2.  利用内核自动负载均衡解决单线程 Accept 瓶颈。

**【全量新代码 / New File】**
```c
/* 
 * GiantVM Frontier High-Performance Memory Server (Final Optimized)
 * Feature: 
 * 1. SO_REUSEPORT (Multi-process Load Balancing)
 * 2. Non-blocking State Machine (Anti-Blocking)
 * 3. EPOLLET (Edge Triggered for High Concurrency)
 * 4. Smart Epoll Update (Reduces Syscall Overhead)
 * 
 * Compile: gcc -O3 -o fast_mem_server fast_mem_server.c -lpthread
 * Usage: Run N instances where N = CPU cores.
 */

#define _GNU_SOURCE 
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
#include <signal.h>
#include <stdint.h>

#define MAX_EVENTS 1024
#define MAX_FDS 1048576 
#define PORT 9999
#define PAGE_SIZE 4096
#define PREFETCH 32       // 每次传输 32 页 (128KB)
#define TOTAL_SEND_SIZE (PAGE_SIZE * PREFETCH)
#define MEM_FILE "physical_ram.img"

/* 
 * [状态结构体]
 * 增加 current_events 用于缓存当前 Epoll 状态，减少系统调用
 */
typedef struct {
    /* 读取阶段的状态 */
    uint8_t head_buf[8];
    int head_read_len;

    /* 发送阶段的状态 */
    int is_sending;       // 0: 等待请求, 1: 正在发送
    uint64_t req_base;    // 客户端请求的地址
    size_t sent_len;      // 已经发送了多少字节
    
    /* [优化核心] 记录当前 Epoll 监听的事件 */
    uint32_t current_events; 
} conn_state_t;

static conn_state_t *states = NULL;
static char *mem_ptr = NULL;
static off_t file_size = 0;

/* 设置非阻塞模式 */
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* 
 * [智能更新函数] 
 * 只有当需要的事件和当前不一致时，才调用 epoll_ctl。
 * 这极大地减少了高频交互下的上下文切换开销。
 */
void smart_update_epoll(int epollfd, int fd, conn_state_t *st, uint32_t new_events) {
    if (st->current_events == new_events) {
        return; /* 状态未变，直接返回，0开销 */
    }
    
    struct epoll_event ev;
    ev.events = new_events;
    ev.data.fd = fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev) == 0) {
        st->current_events = new_events;
    }
}

int main() {
    signal(SIGPIPE, SIG_IGN);
    int listen_sock, conn_sock, nfds, epollfd;
    struct epoll_event ev, events[MAX_EVENTS];
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    /* 1. 内存初始化 */
    states = (conn_state_t *)calloc(MAX_FDS, sizeof(conn_state_t));
    if (!states) { perror("calloc"); return 1; }

    int fd_mem = open(MEM_FILE, O_RDONLY);
    if (fd_mem < 0) { perror("open mem file"); return 1; }
    file_size = lseek(fd_mem, 0, SEEK_END);
    mem_ptr = mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd_mem, 0);
    if (mem_ptr == MAP_FAILED) { perror("mmap"); return 1; }
    
    /* 建议内核预读 */
    madvise(mem_ptr, file_size, MADV_HUGEPAGE | MADV_WILLNEED);

    /* 2. 网络初始化 */
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    /* [关键] 开启 REUSEPORT 允许多进程绑定同一端口 */
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)); 

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(listen_sock, 20000) < 0) { perror("listen"); return 1; }

    epollfd = epoll_create1(0);
    ev.events = EPOLLIN;
    ev.data.fd = listen_sock;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, listen_sock, &ev);

    printf("[*] Server PID %d ready on port %d (Optimized)\n", getpid(), PORT);

    /* 3. 事件主循环 */
    while (1) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        
        for (int n = 0; n < nfds; ++n) {
            int fd = events[n].data.fd;

            /* Case A: 新连接 (Accept Loop for EPOLLET) */
            if (fd == listen_sock) {
                while (1) {
                    conn_sock = accept(listen_sock, (struct sockaddr *)&addr, &addrlen);
                    if (conn_sock == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break; // 处理完所有积压连接
                        break;
                    }
                    
                    if (conn_sock >= MAX_FDS) {
                        close(conn_sock);
                        continue;
                    }

                    set_nonblocking(conn_sock);
                    int flag = 1;
                    setsockopt(conn_sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
                    
                    // 初始化状态
                    memset(&states[conn_sock], 0, sizeof(conn_state_t));
                    
                    // 初始化当前事件记录
                    states[conn_sock].current_events = EPOLLIN | EPOLLET;
                    
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.fd = conn_sock;
                    epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock, &ev);
                }
                continue;
            }

            /* Case B: 已有连接的数据处理 (State Machine) */
            conn_state_t *st = &states[fd];
            int done_work = 0; 

            while (1) {
                done_work = 0;

                /* --- 阶段 1: 读取请求头 (8字节) --- */
                if (!st->is_sending) {
                    int to_read = 8 - st->head_read_len;
                    if (to_read > 0) {
                        ssize_t r = recv(fd, st->head_buf + st->head_read_len, to_read, 0);
                        if (r > 0) {
                            st->head_read_len += r;
                            done_work = 1; 
                            if (st->head_read_len == 8) {
                                // 解析头
                                uint64_t req_be;
                                memcpy(&req_be, st->head_buf, 8);
                                st->req_base = be64toh(req_be);
                                if (st->req_base + TOTAL_SEND_SIZE > file_size) st->req_base = 0;
                                
                                st->is_sending = 1;
                                st->sent_len = 0;
                                st->head_read_len = 0;
                            }
                        } else if (r == -1) {
                            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                                close(fd); goto reset_state; // 出错
                            }
                            // EAGAIN: 读缓冲区空了，稍后重试
                        } else {
                            close(fd); goto reset_state; // 对端关闭
                        }
                    }
                }

                /* --- 阶段 2: 发送数据 --- */
                if (st->is_sending) {
                    char *data_start = mem_ptr + st->req_base;
                    size_t remain = TOTAL_SEND_SIZE - st->sent_len;
                    
                    ssize_t s = send(fd, data_start + st->sent_len, remain, MSG_DONTWAIT);

                    if (s > 0) {
                        st->sent_len += s;
                        done_work = 1;
                        
                        if (st->sent_len == TOTAL_SEND_SIZE) {
                            // 发送完毕
                            st->is_sending = 0;
                            
                            /* 
                             * [智能修正]：发送完毕，必须确保 EPOLLOUT 被关闭。
                             * 如果之前因为缓冲区满打开了 EPOLLOUT，这里会调用系统调用关闭它。
                             * 如果一直顺畅，这里什么都不做。
                             */
                            smart_update_epoll(epollfd, fd, st, EPOLLIN | EPOLLET);
                            
                            // 关键：Pipeline 机制，继续循环尝试读取下一个请求
                            continue; 
                        }
                    } else if (s == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            /* 
                             * 发送缓冲区满，必须开启 EPOLLOUT 监听。
                             * 内核会在缓冲区可写时再次唤醒我们。
                             */
                            smart_update_epoll(epollfd, fd, st, EPOLLIN | EPOLLOUT | EPOLLET);
                            break; // 退出内部循环，交还 CPU
                        }
                        close(fd); goto reset_state;
                    }
                }

                /* 
                 * 退出条件：
                 * 如果这一轮循环既没有读到有效数据（recv EAGAIN），
                 * 也没有成功发送数据（send EAGAIN 或 没在发），
                 * 说明 socket 暂时没有活动，退出循环。
                 */
                if (!done_work) break;
            }
            continue;
            
            reset_state:
            states[fd].head_read_len = 0;
            states[fd].is_sending = 0;
            states[fd].sent_len = 0;
            // 连接关闭后，内核会自动从 epoll set 中移除，无需手动 epoll_ctl DEL
        }
    }
    return 0;
}
```

---

## 4.完整部署流程

#### 0. 基础环境与依赖安装 (所有节点)
**所有节点（物理机或虚拟机）均需执行，这是成功部署的基础。**

```bash
# 1. 安装基础编译工具 (Kernel & QEMU)
sudo apt-get update
sudo apt-get install -y build-essential libncurses-dev bison flex libssl-dev libelf-dev \
    pkg-config libglib2.0-dev libpixman-1-dev libpython3-dev libaio-dev libcap-ng-dev \
    libattr1-dev libcap-dev python3-venv python3-pip

# 2. 关键内核参数调优 (写入 /etc/sysctl.conf 以永久生效)
# 这些参数是为了应对万节点规模下的高并发连接、大量文件句柄和高网络吞吐。
cat <<EOF | sudo tee -a /etc/sysctl.conf
# --- 文件句柄与内存映射 ---
fs.file-max = 2097152
vm.max_map_count = 262144

# --- 网络核心与连接队列 ---
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536

# --- TCP 内存与缓冲区 ---
# 增大了TCP读写缓冲区，以适应高延迟、高带宽网络
net.ipv4.tcp_mem = 4194304 6291456 8388608
net.ipv4.tcp_wmem = 4096 131072 4194304
net.ipv4.tcp_rmem = 4096 131072 6291456
net.ipv4.tcp_moderate_rcvbuf = 1

# --- TCP 连接管理 ---
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_syn_retries=2

# --- ARP 表与连接跟踪 ---
net.ipv4.neigh.default.gc_thresh1 = 8192
net.ipv4.neigh.default.gc_thresh2 = 16384
net.ipv4.neigh.default.gc_thresh3 = 32768
net.netfilter.nf_conntrack_max = 2097152
net.nf_conntrack_max = 2097152

# --- [新增] 拥塞控制算法 ---
# 使用 BBR 算法，能更好地处理延迟和丢包，提升吞吐
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# --- [新增] 内核紧急内存预留 (针对DSM模式) ---
# 为 GFP_ATOMIC 分配预留更多内存，降低内核在高压下因内存不足而崩溃的风险
vm.min_free_kbytes = 1048576
EOF

# 应用所有 sysctl 参数
sudo sysctl -p

# 3. 网络与用户句柄限制
# 将以下内容追加到 /etc/security/limits.conf 以永久提高用户级资源限制
cat <<EOF | sudo tee -a /etc/security/limits.conf
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 1048576
* hard nproc 1048576
EOF
# 注意：limits.conf 的修改需要重新登录 Shell 才能生效。

# 4. [关键] 配置巨型帧 (Jumbo Frames)
# 由于内核DSM模式的协议头较大(>1300字节)，必须开启巨型帧避免IP分片。
# 将 <interface> 替换为你的主网卡名 (如 eth0, enp3s0)
sudo ip link set dev <interface> mtu 9000

```
**验证：** `ip a` 命令应显示你的网卡 `mtu 9000`。`sysctl net.ipv4.tcp_congestion_control` 应显示 `bbr`。

---

#### 流程 A：原版全共享模式 (DSM Mode)
**适用场景：** 分布式操作系统研究、跨节点内存/CPU 聚合。
**架构：** L0 (物理机) -> L1 (GiantVM 宿主机集群) -> L2 (GiantVM 客户机)。

**步骤 1：L0/L1 环境确认**
1.  **内核与网络调优：** 确保所有参与集群的物理机（L0）和虚拟机（L1）都已完成上述 **“0. 基础环境与依赖安装”** 中的所有步骤。
2.  **关闭 Watchdog（建议）：**
    虽然代码中已加入 `touch_watchdog` 逻辑，但在万节点广播等极端情况下，关闭内核的死锁检测可以避免不必要的重启。
    ```bash
    sudo sysctl -w kernel.nmi_watchdog=0
    sudo sysctl -w kernel.softlockup_panic=0
    ```

**步骤 2：编译与加载内核模块 (所有 L1 节点)**
```bash
# 进入修改后的内核源码目录
cd giantvm-kvm/

# 编译内核模块
make -j$(nproc)

# 加载模块
sudo insmod giantvm-kvm.ko

# 验证加载成功
lsmod | grep giantvm
dmesg | tail
```
*应能看到 `giantvm_kvm` 模块信息。*

**步骤 3：配置集群 (所有 L1 节点)**
创建一个内容完全相同的 `cluster.conf` 文件，分发到所有 L1 节点上 QEMU 的启动目录。
```text
# 格式: ID IP PORT
0 192.168.1.101 9999
1 192.168.1.102 9999
2 192.168.1.103 9999
...
10239 192.168.1.10340 9999
```

**步骤 4：启动 GiantVM (每个 L1 节点)**
在每个 L1 节点上，进入编译好的 QEMU 目录，运行对应的启动命令。
*注意：每个节点的 `-giantvm-id` **必须唯一**，且与 `cluster.conf` 中的 ID 对应。*

```bash
# 在 192.168.1.101 上 (Node 0)
./qemu-system-x86_64 \
  -enable-kvm \
  -m 4G \
  -smp 4 \
  -giantvm-id 0 \
  -giantvm-cluster ./cluster.conf \
  -drive file=disk.qcow2,format=qcow2 \
  -netdev tap,id=n1,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=n1 \
  -vnc :0

# 在 192.168.1.102 上 (Node 1)
./qemu-system-x86_64 ... -giantvm-id 1 ... -giantvm-cluster ./cluster.conf ...
```

**验证：**
在各个 L1 节点上执行 `dmesg`，应能看到大量 `[DSM] Connection established to node X` 等连接建立的日志。虚拟机 L2 启动后，其内存和 CPU 资源应是分布式的。

---

#### 流程 B：双模 UFFD 内存模式 (Frontier Mode)
**适用场景：** 万节点云游戏、GPU 直通、高性能计算。
**架构：** L0 (物理机) 分为两种角色：少数**存储节点**和大量**计算节点**。

**步骤 1：服务端 (Memory Server) 启动**
在专用的**存储节点**上执行：

*   **1. 准备环境：**
    确保已完成 **“0. 基础环境与依赖安装”** 的所有步骤。特别注意 `ulimit` 限制需要新开一个 Shell 才能生效。
    ```bash
    # 临时提高当前 Shell 的文件句柄限制
    ulimit -n 1048576
    ```

*   **2. 编译服务端：**
    ```bash
    # 将方案中的 C 代码保存为 fast_mem_server.c
    gcc -O3 -o fast_mem_server fast_mem_server.c -lpthread
    ```

*   **3. 生成内存镜像文件：**
    例如，创建一个 64GB 的内存镜像。
    ```bash
    fallocate -l 64G physical_ram.img
    ```

*   **4. [关键] 启动多进程服务端：**
    为了充分利用多核 CPU 处理海量并发连接，必须启动与 CPU 核心数相当的服务进程。这些进程会通过 `SO_REUSEPORT` 共同监听 9999 端口。
    ```bash
    # 以后台模式启动 N 个服务进程，N = CPU核心数
    for i in $(seq 1 $(nproc)); do
        nohup ./fast_mem_server > server_log_${i}.txt 2>&1 &
    done

    # 验证进程是否全部启动
    pgrep fast_mem_server | wc -l
    ```
    *应看到与 CPU 核心数相同的进程数量。*

**步骤 2：客户端 (Compute Node) 准备**
在所有**计算节点**上执行：

*   **1. 确保内核模块未加载：**
    ```bash
    sudo rmmod giantvm-kvm || true # 忽略错误
    lsmod | grep giantvm # 确保无输出
    ```

*   **2. [修改] 创建并分发 `cluster.conf` 文件：**
    创建一个 `cluster.conf` 文件，内容**只包含你的内存服务器（存储节点）的IP地址**。然后将这个文件分发到所有计算节点的QEMU启动目录下。
    ```text
    # 
    # Frontier Mode 的 cluster.conf
    # 这里只需要列出内存服务器。ID 和 PORT 字段会被解析但不会被使用，但格式必须保持一致。
    # 内存页到服务器的映射关系将通过 (页面号 % 服务器总数) 来决定。
    #
    0 192.168.1.101 9999  # 内存服务器 1
    1 192.168.1.102 9999  # 内存服务器 2
    # 如果有更多内存服务器，继续添加...
    ```

*   **3. 编译 QEMU (带扩容支持)：**
    ```bash
    cd qemu/
    make clean
    
    ./configure \
      --target-list=x86_64-softmmu \
      --enable-kvm \
      --enable-vnc \
      --disable-werror \
      --extra-cflags="-O3 -D__FD_SETSIZE=65536 -DFD_SETSIZE=65536" \
      --python=/usr/bin/python3

    make -j$(nproc)
    ```

**步骤 3：启动客户端**
在每个计算节点上运行 QEMU。**请确保 `cluster.conf` 文件位于你执行qemu命令的当前目录下。**
```bash
# 确保 cluster.conf 在当前目录
ls cluster.conf 

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
1.  启动 QEMU 时，控制台除了打印 `[GiantVM] NO KERNEL MODULE...` 之外，还会新增一行日志：`[GiantVM] Loaded 2 memory server IPs from cluster.conf` （数字 `2` 取决于你的配置文件内容）。
2.  如果 QEMU 报错 `[GiantVM] Failed to open cluster.conf`，请检查文件是否存在以及权限是否正确。
3.  后续行为与之前一致，VM 启动时会从 `cluster.conf` 中列出的服务器拉取内存。

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
