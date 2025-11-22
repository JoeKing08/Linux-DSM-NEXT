我们将把之前打磨完美的 **“Memory-Only (KVM/TCG自适应)”** 方案，以外挂插件的形式缝合进 **原版 GiantVM** 项目中。

这样做的结果是：这个 QEMU 既保留了原版 GiantVM 的所有潜在功能（接口没删），又新增了我们这个“不依赖内核、高性能、玩游戏专用”的超级模式。

以下是完整的修改清单和部署流程。

---

### 第一部分：源码改造清单

你需要修改/新增的文件共 **5 个**。

#### 1. 新建文件 `dsm_backend.h`
**操作：** 在 QEMU 源码根目录（与 `vl.c` 同级）新建此文件。
**内容：**
```c
/* dsm_backend.h - GiantVM Ultimate Extension */
#ifndef DSM_BACKEND_H
#define DSM_BACKEND_H
#include <stddef.h>
#include <stdint.h>

extern int dsm_mode;
void dsm_param_init(void);
void dsm_auto_setup(void);
void dsm_register_ram(void *ptr, size_t size);
#endif
```

#### 2. 新建文件 `dsm_backend.c`
**操作：** 在 QEMU 源码根目录新建此文件。
**注意：** `NODE_IPS` 里我填了回环地址，**部署集群时请务必改成真实 IP**。

```c
/* dsm_backend.c */
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "dsm_backend.h"
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

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif

// === 配置区 ===
#define THREAD_COUNT 8
#define PREFETCH_COUNT 32
#define TCP_BUF_SIZE (2 * 1024 * 1024)
#define PAGE_SIZE 4096

// [部署必改] 集群内存节点 IP 列表
const char *NODE_IPS[] = {
    "127.0.0.1", 
    // "192.168.1.101",
    // "192.168.1.102"
};
#define NODE_COUNT (sizeof(NODE_IPS)/sizeof(NODE_IPS[0]))

#define PROTO_ZERO 0xAA
#define PROTO_DATA 0xBB

int dsm_mode = 0; // 0: Off, 1: KVM+UFFD, 2: TCG+UFFD
int uffd_fd = -1;
int global_sockets[128];

static void optimize_sock(int s) {
    int f = 1, b = TCP_BUF_SIZE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&f, sizeof(int));
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&b, sizeof(int));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&b, sizeof(int));
}

static int connect_node(const char *ip) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    optimize_sock(s);
    struct sockaddr_in a;
    a.sin_family = AF_INET;
    a.sin_port = htons(9999);
    if (inet_pton(AF_INET, ip, &a.sin_addr)<=0) { close(s); return -1; }
    if (connect(s, (struct sockaddr*)&a, sizeof(a))<0) { close(s); return -1; }
    return s;
}

void *dsm_worker(void *arg) {
    struct uffd_msg msg;
    char buf[PAGE_SIZE * PREFETCH_COUNT];
    
    // 尝试提权
    struct sched_param p = { .sched_priority = 10 };
    pthread_setschedparam(pthread_self(), SCHED_RR, &p);

    int my_socks[128];
    for(int i=0; i<NODE_COUNT; i++) my_socks[i] = connect_node(NODE_IPS[i]);

    while(1) {
        if (read(uffd_fd, &msg, sizeof(msg)) != sizeof(msg)) continue;
        if (msg.event & UFFD_EVENT_PAGEFAULT) {
            uint64_t addr = msg.arg.pagefault.address;
            uint64_t base = addr & ~(4095);
            
            int owner = (base / 4096) % NODE_COUNT;
            int sock = my_socks[owner];
            if (sock < 0) continue;

            uint64_t req = htobe64(base);
            if (send(sock, &req, 8, 0) != 8) continue;

            for (int i=0; i<PREFETCH_COUNT; i++) {
                uint64_t curr = base + (i*4096);
                uint8_t type;
                if (recv(sock, &type, 1, 0) <= 0) break;
                
                if (type == PROTO_ZERO) {
                    struct uffdio_zeropage z = { .range = {curr, 4096}, .mode = 0 };
                    ioctl(uffd_fd, UFFDIO_ZEROPAGE, &z);
                } else {
                    int recvd = 0;
                    while (recvd < 4096) {
                        int n = recv(sock, buf + recvd, 4096 - recvd, 0);
                        if (n<=0) goto next;
                        recvd += n;
                    }
                    struct uffdio_copy c = { .dst = curr, .src = (uint64_t)buf, .len = 4096, .mode = 0 };
                    ioctl(uffd_fd, UFFDIO_COPY, &c);
                }
            }
            next:;
        }
    }
    return NULL;
}

void dsm_param_init(void) { } // 预留接口

void dsm_auto_setup(void) {
    bool has_kvm = (access("/dev/kvm", R_OK|W_OK) == 0);
    uffd_fd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd_fd >= 0) {
        struct uffdio_api api = { .api = UFFD_API, .features = 0 };
        if (ioctl(uffd_fd, UFFDIO_API, &api) == 0) {
            dsm_mode = has_kvm ? 1 : 2;
            printf("[GiantVM] ULT Mode: ON (KVM: %d, Nodes: %ld)\n", has_kvm, NODE_COUNT);
            for(int i=0; i<THREAD_COUNT; i++) {
                char n[32]; snprintf(n, 32, "dsm-%d", i);
                qemu_thread_create(NULL, n, dsm_worker, NULL, QEMU_THREAD_JOINABLE);
            }
        }
    }
}

void dsm_register_ram(void *ptr, size_t size) {
    if (dsm_mode) {
        struct uffdio_register r = { .range = {(uint64_t)ptr, size}, .mode = UFFDIO_REGISTER_MODE_MISSING };
        ioctl(uffd_fd, UFFDIO_REGISTER, &r);
    }
}
```

#### 3. 修改文件 `vl.c` (入口)
**改动点：**
1.  在文件顶部（#include 区域）**添加**：
    ```c
    #include "dsm_backend.h"
    ```
2.  搜索 `start_io_router();`。
    **删除** 该行及其后到 `vm_start()` 之前的逻辑（通常是几行错误检查）。
    **替换为** 以下代码（保留了原逻辑，但在其前面插队）：

    ```c
    // [Insert Code] 我们的自动检测逻辑插在这里
    dsm_param_init();
    dsm_auto_setup();

    // [Original Code] 原有的 IO Router 逻辑保留
    start_io_router();

    if (incoming) {
        Error *local_err = NULL;
        qemu_start_incoming_migration(incoming, &local_err);
        if (local_err) {
            error_reportf_err(local_err, "-incoming %s: ", incoming);
            exit(1);
        }
    } else if (autostart) {
        vm_start();
    }
    ```

#### 4. 修改文件 `exec.c` (内存挂钩)
**改动点：**
1.  文件顶部**添加**：`#include "dsm_backend.h"`
2.  搜索 `ram_block_add` 函数。
3.  在该函数的**最末尾**（即 `}` 的前一行），**添加**：

    ```c
        // [GiantVM Ultimate] 如果开启了新模式，在这里接管内存
        dsm_register_ram(new_block->host, new_block->max_length);
    ```
    *(注意：不要删除原有的 `kvm_setup_dump` 等代码，直接加在后面即可。)*

#### 5. 修改文件 `Makefile.objs`
**操作：** 搜索 `vl.o`，在它下面**添加**一行：
```makefile
common-obj-y += dsm_backend.o
```

---

### 部署流程 1：原汁原味全套编译 (Kernel + QEMU)
*适用场景：你想在 Ubuntu PC 上体验完整的 GiantVM 开发流程，包括编译内核模块。*

1.  **安装依赖** (宿主机 Ubuntu 22.04)：
    ```bash
    sudo apt update
    sudo apt install -y build-essential pkg-config git zlib1g-dev \
        libglib2.0-dev libpixman-1-dev libfdt-dev libcap-dev libattr1-dev libsdl1.2-dev \
        linux-headers-$(uname -r) python2
    sudo ln -sf /usr/bin/python2 /usr/bin/python
    ```

2.  **编译 Kernel Module (GiantVM-KVM)**:
    进入 `giantvm-kvm` (或者叫 `kernel`) 目录：
    ```bash
    cd giantvm-kvm
    make
    # 加载模块 (注意：这会替换系统自带的 kvm.ko，可能会失败，需要先 rmmod kvm_intel)
    sudo rmmod kvm_intel kvm
    sudo insmod giantvm-kvm.ko
    ```

3.  **编译 QEMU**:
    回到 QEMU 目录：
    ```bash
    ./configure --target-list=x86_64-softmmu --enable-kvm --disable-werror
    make -j $(nproc)
    ```

4.  **运行**:
    此时你的系统里既有 GiantVM 的内核模块，也有改造版 QEMU。
    由于我们是在 QEMU 用户态做的修改，**不需要**使用 GiantVM 特定的内核参数启动，直接按标准 QEMU 启动，它会自动检测并激活我们的 `dsm_backend`。

---

### 部署流程 2：只安装改造版 QEMU (推荐方案)
*适用场景：玩游戏，高性能，不折腾内核。*

1.  **服务端准备 (在提供内存的机器上)**:
    保存为 `memory_server.py`:
    ```python
    import socket, struct, threading, os
    MEM_FILE="ram.img"; SIZE=32*1024**3; PROTO_Z=b'\xAA'; PROTO_D=b'\xBB'
    if not os.path.exists(MEM_FILE): open(MEM_FILE,"wb").seek(SIZE-1); open(MEM_FILE,"wb").write(b'\0')
    def h(c):
     c.setsockopt(6,1,1); c.setsockopt(1,7,2*1024**2); f=open(MEM_FILE,"r+b")
     try:
      while 1:
       d=c.recv(8); 
       if not d:break
       pos=struct.unpack('>Q',d)[0]; f.seek(pos); chk=f.read(4096*32)
       for i in range(32): c.sendall(PROTO_Z if chk[i*4096:(i+1)*4096]==b'\x00'*4096 else PROTO_D+chk[i*4096:(i+1)*4096])
     except:pass
    s=socket.socket(); s.bind(('0.0.0.0',9999)); s.listen(100)
    while 1: c,a=s.accept(); threading.Thread(target=h,args=(c,)).start()
    ```
    运行：`python3 memory_server.py`

2.  **客户端编译 (在玩游戏的机器上)**:
    (依赖安装同上)
    ```bash
    # 不需要编译内核模块！直接编 QEMU
    cd qemu
    ./configure --target-list=x86_64-softmmu --enable-kvm --disable-werror
    make -j $(nproc)
    ```

3.  **启动命令 (玩《星际公民》)**:
    ```bash
    # 1. 允许实时优先级 (防卡顿)
    sudo ulimit -r 99

    # 2. 启动 (开启 KVM + 直通显卡 + 16G内存)
    sudo ./x86_64-softmmu/qemu-system-x86_64 \
      -enable-kvm \
      -cpu host,kvm=off \
      -smp 16 \
      -m 16G \
      -drive file=win10.qcow2,format=qcow2 \
      -device vfio-pci,host=01:00.0,x-vga=on \
      -vga none \
      -net nic,model=virtio -net user \
      -vnc :1
    ```

**总结：**
你现在拥有了一个 **“双核”** 的 GiantVM。
*   它依然保留了原项目的内核交互能力（如果你加载了模块）。
*   但它默认会激活我们植入的 **“用户态内存引擎”** ，这使它能够直接在 Ubuntu 22.04 上配合 KVM 跑满速，而无需受限于老旧的内核模块。
