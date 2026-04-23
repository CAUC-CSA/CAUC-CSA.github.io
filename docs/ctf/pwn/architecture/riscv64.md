# RISC-V 64位架构基础知识

!!! tip "Pwn 速查"
    - 函数参数：`a0-a7`，返回值：`a0`（128 位返回值可用 `a0:a1`）。
    - Linux 系统调用：调用号放 `a7`，参数放 `a0-a5`，指令为 `ecall`。
    - `ra` 会被 `call` / `jal` 覆盖；非叶子函数必须保存自己的返回地址。

!!! note
    RISC-V 基础指令通常为 4 字节；启用 RVC 压缩扩展时也会出现 2 字节指令。

## RISC-V 64位寄存器详解

### 通用寄存器 (`x0-x31`)

| 寄存器 | ABI 名 | 用途 |
|---|---|---|
| `x0` | `zero` | 硬件零寄存器 |
| `x1` | `ra` | 返回地址 |
| `x2` | `sp` | 栈指针 |
| `x3` | `gp` | 全局指针 |
| `x4` | `tp` | 线程指针 |
| `x5-x7` | `t0-t2` | 临时寄存器 |
| `x8` | `s0/fp` | 保存寄存器 / 帧指针 |
| `x9` | `s1` | 保存寄存器 |
| `x10-x11` | `a0-a1` | 参数 / 返回值 |
| `x12-x17` | `a2-a7` | 参数；`a7` 也放 Linux syscall number |
| `x18-x27` | `s2-s11` | 保存寄存器 |
| `x28-x31` | `t3-t6` | 临时寄存器 |

### 寄存器别名和用途

| 寄存器 | 别名 | 主要用途 | 调用约定 |
|---|---|---|---|
| `x0` | `zero` | 硬件零常量 | 常数 0 |
| `x1` | `ra` | 返回地址 | 调用者保存 |
| `x2` | `sp` | 栈指针 | 特殊 / 保持对齐 |
| `x3` | `gp` | 全局指针 | ABI 相关 |
| `x4` | `tp` | 线程指针 | ABI 相关 |
| `x5-x7` | `t0-t2` | 临时寄存器 | 调用者保存 |
| `x8-x9` | `s0/fp`, `s1` | 保存寄存器 / 帧指针 | 被调用者保存 |
| `x10-x17` | `a0-a7` | 参数 / 返回值；`a7` 为 syscall number | 调用者保存 |
| `x18-x27` | `s2-s11` | 保存寄存器 | 被调用者保存 |
| `x28-x31` | `t3-t6` | 临时寄存器 | 调用者保存 |

### 特殊寄存器

| 寄存器 | 作用 |
|---|---|
| `pc` | 程序计数器 |
| `mstatus` | 机器状态寄存器 |
| `mtvec` | 机器陷阱向量基地址 |
| `mcause` | 机器陷阱原因 |
| `mtval` | 机器陷阱值 |
| `mip` | 机器中断挂起 |
| `mie` | 机器中断使能 |

!!! warning
    用户态 Pwn 通常不能直接读写 `mstatus`、`mtvec` 这类机器态 CSR；这里只是说明体系结构中存在这些寄存器。

## Linux RISC-V 64位系统调用表

### 常用系统调用号

??? info "常用系统调用号（展开查看）"
    ```c
    #define __NR_io_setup                0
    #define __NR_io_destroy              1
    #define __NR_io_submit               2
    #define __NR_io_cancel               3
    #define __NR_io_getevents            4
    #define __NR_setxattr                5
    #define __NR_lsetxattr               6
    #define __NR_fsetxattr               7
    #define __NR_getxattr                8
    #define __NR_lgetxattr               9
    #define __NR_fgetxattr              10
    #define __NR_listxattr              11
    #define __NR_llistxattr             12
    #define __NR_flistxattr             13
    #define __NR_removexattr            14
    #define __NR_lremovexattr           15
    #define __NR_fremovexattr           16
    #define __NR_getcwd                 17
    #define __NR_lookup_dcookie         18
    #define __NR_eventfd2               19
    #define __NR_epoll_create1          20
    #define __NR_epoll_ctl              21
    #define __NR_epoll_pwait            22
    #define __NR_dup                    23
    #define __NR_dup3                   24
    #define __NR_fcntl                  25
    #define __NR_inotify_init1          26
    #define __NR_inotify_add_watch      27
    #define __NR_inotify_rm_watch       28
    #define __NR_ioctl                  29
    #define __NR_ioprio_set             30
    #define __NR_ioprio_get             31
    #define __NR_flock                  32
    #define __NR_mknodat                33
    #define __NR_mkdirat                34
    #define __NR_unlinkat               35
    #define __NR_symlinkat              36
    #define __NR_linkat                 37
    #define __NR_umount2                39
    #define __NR_mount                  40
    #define __NR_pivot_root             41
    #define __NR_nfsservctl             42
    #define __NR_statfs                 43
    #define __NR_fstatfs                44
    #define __NR_truncate               45
    #define __NR_ftruncate              46
    #define __NR_fallocate              47
    #define __NR_faccessat              48
    #define __NR_chdir                  49
    #define __NR_fchdir                 50
    #define __NR_chroot                 51
    #define __NR_fchmod                 52
    #define __NR_fchmodat               53
    #define __NR_fchownat               54
    #define __NR_fchown                 55
    #define __NR_openat                 56
    #define __NR_close                  57
    #define __NR_vhangup                58
    #define __NR_pipe2                  59
    #define __NR_quotactl               60
    #define __NR_getdents64             61
    #define __NR_lseek                  62
    #define __NR_read                   63
    #define __NR_write                  64
    #define __NR_readv                  65
    #define __NR_writev                 66
    #define __NR_pread64                67
    #define __NR_pwrite64               68
    #define __NR_preadv                 69
    #define __NR_pwritev                70
    #define __NR_sendfile               71
    #define __NR_pselect6               72
    #define __NR_ppoll                  73
    #define __NR_signalfd4              74
    #define __NR_vmsplice               75
    #define __NR_splice                 76
    #define __NR_tee                    77
    #define __NR_readlinkat             78
    #define __NR_fstatat                79
    #define __NR_fstat                  80
    #define __NR_sync                   81
    #define __NR_fsync                  82
    #define __NR_fdatasync              83
    #define __NR_sync_file_range        84
    #define __NR_timerfd_create         85
    #define __NR_timerfd_settime        86
    #define __NR_timerfd_gettime        87
    #define __NR_utimensat              88
    #define __NR_acct                   89
    #define __NR_capget                 90
    #define __NR_capset                 91
    #define __NR_personality            92
    #define __NR_exit                   93
    #define __NR_exit_group             94
    #define __NR_waitid                 95
    #define __NR_set_tid_address        96
    #define __NR_unshare                97
    #define __NR_futex                  98
    #define __NR_set_robust_list        99
    #define __NR_get_robust_list       100
    #define __NR_nanosleep             101
    #define __NR_getitimer             102
    #define __NR_setitimer             103
    #define __NR_kexec_load            104
    #define __NR_init_module           105
    #define __NR_delete_module         106
    #define __NR_timer_create          107
    #define __NR_timer_gettime         108
    #define __NR_timer_getoverrun      109
    #define __NR_timer_settime         110
    #define __NR_timer_delete          111
    #define __NR_clock_settime         112
    #define __NR_clock_gettime         113
    #define __NR_clock_getres          114
    #define __NR_clock_nanosleep       115
    #define __NR_syslog                116
    #define __NR_ptrace                117
    #define __NR_sched_setparam        118
    #define __NR_sched_setscheduler    119
    #define __NR_sched_getscheduler    120
    #define __NR_sched_getparam        121
    #define __NR_sched_setaffinity     122
    #define __NR_sched_getaffinity     123
    #define __NR_sched_yield           124
    #define __NR_sched_get_priority_max 125
    #define __NR_sched_get_priority_min 126
    #define __NR_sched_rr_get_interval 127
    #define __NR_restart_syscall       128
    #define __NR_kill                  129
    #define __NR_tkill                 130
    #define __NR_tgkill                131
    #define __NR_sigaltstack           132
    #define __NR_rt_sigsuspend         133
    #define __NR_rt_sigaction          134
    #define __NR_rt_sigprocmask        135
    #define __NR_rt_sigpending         136
    #define __NR_rt_sigtimedwait       137
    #define __NR_rt_sigqueueinfo       138
    #define __NR_rt_sigreturn          139
    #define __NR_setpriority           140
    #define __NR_getpriority           141
    #define __NR_reboot                142
    #define __NR_setregid              143
    #define __NR_setgid                144
    #define __NR_setreuid              145
    #define __NR_setuid                146
    #define __NR_setresuid             147
    #define __NR_getresuid             148
    #define __NR_setresgid             149
    #define __NR_getresgid             150
    #define __NR_setfsuid              151
    #define __NR_setfsgid              152
    #define __NR_times                 153
    #define __NR_setpgid               154
    #define __NR_getpgid               155
    #define __NR_getsid                156
    #define __NR_setsid                157
    #define __NR_getgroups             158
    #define __NR_setgroups             159
    #define __NR_uname                 160
    #define __NR_sethostname           161
    #define __NR_setdomainname         162
    #define __NR_getrlimit             163
    #define __NR_setrlimit             164
    #define __NR_getrusage             165
    #define __NR_umask                 166
    #define __NR_prctl                 167
    #define __NR_getcpu                168
    #define __NR_gettimeofday          169
    #define __NR_settimeofday          170
    #define __NR_adjtimex              171
    #define __NR_getpid                172
    #define __NR_getppid               173
    #define __NR_getuid                174
    #define __NR_geteuid               175
    #define __NR_getgid                176
    #define __NR_getegid               177
    #define __NR_gettid                178
    #define __NR_sysinfo               179
    #define __NR_mq_open               180
    #define __NR_mq_unlink             181
    #define __NR_mq_timedsend          182
    #define __NR_mq_timedreceive       183
    #define __NR_mq_notify             184
    #define __NR_mq_getsetattr         185
    #define __NR_msgget                186
    #define __NR_msgctl                187
    #define __NR_msgrcv                188
    #define __NR_msgsnd                189
    #define __NR_semget                190
    #define __NR_semctl                191
    #define __NR_semtimedop            192
    #define __NR_semop                 193
    #define __NR_shmget                194
    #define __NR_shmctl                195
    #define __NR_shmat                 196
    #define __NR_shmdt                 197
    #define __NR_socket                198
    #define __NR_socketpair            199
    #define __NR_bind                  200
    #define __NR_listen                201
    #define __NR_accept                202
    #define __NR_connect               203
    #define __NR_getsockname           204
    #define __NR_getpeername           205
    #define __NR_sendto                206
    #define __NR_recvfrom              207
    #define __NR_setsockopt            208
    #define __NR_getsockopt            209
    #define __NR_shutdown              210
    #define __NR_sendmsg               211
    #define __NR_recvmsg               212
    #define __NR_readahead             213
    #define __NR_brk                   214
    #define __NR_munmap                215
    #define __NR_mremap                216
    #define __NR_add_key               217
    #define __NR_request_key           218
    #define __NR_keyctl                219
    #define __NR_clone                 220
    #define __NR_execve                221
    #define __NR_mmap                  222
    #define __NR_fadvise64             223
    #define __NR_swapon                224
    #define __NR_swapoff               225
    #define __NR_mprotect              226
    #define __NR_msync                 227
    #define __NR_mlock                 228
    #define __NR_munlock               229
    #define __NR_mlockall              230
    #define __NR_munlockall            231
    #define __NR_mincore               232
    #define __NR_madvise               233
    #define __NR_remap_file_pages      234
    #define __NR_mbind                 235
    #define __NR_get_mempolicy         236
    #define __NR_set_mempolicy         237
    #define __NR_migrate_pages         238
    #define __NR_move_pages            239
    #define __NR_rt_tgsigqueueinfo     240
    #define __NR_perf_event_open       241
    #define __NR_accept4               242
    #define __NR_recvmmsg              243
    #define __NR_arch_specific_syscall 244
    #define __NR_wait4                 260
    #define __NR_prlimit64             261
    #define __NR_fanotify_init         262
    #define __NR_fanotify_mark         263
    #define __NR_name_to_handle_at     264
    #define __NR_open_by_handle_at     265
    #define __NR_clock_adjtime         266
    #define __NR_syncfs                267
    #define __NR_setns                 268
    #define __NR_sendmmsg              269
    #define __NR_process_vm_readv      270
    #define __NR_process_vm_writev     271
    #define __NR_kcmp                  272
    #define __NR_finit_module          273
    #define __NR_sched_setattr         274
    #define __NR_sched_getattr         275
    #define __NR_renameat2             276
    #define __NR_seccomp               277
    #define __NR_getrandom             278
    #define __NR_memfd_create          279
    #define __NR_bpf                   280
    #define __NR_execveat              281
    #define __NR_userfaultfd           282
    #define __NR_membarrier            283
    #define __NR_mlock2                284
    #define __NR_copy_file_range       285
    #define __NR_preadv2               286
    #define __NR_pwritev2              287
    #define __NR_pkey_mprotect         288
    #define __NR_pkey_alloc            289
    #define __NR_pkey_free             290
    #define __NR_statx                 291
    #define __NR_io_pgetevents         292
    #define __NR_rseq                  293
    #define __NR_kexec_file_load       294
    #define __NR_pidfd_send_signal     424
    #define __NR_io_uring_setup        425
    #define __NR_io_uring_enter        426
    #define __NR_io_uring_register     427
    #define __NR_open_tree             428
    #define __NR_move_mount            429
    #define __NR_fsopen                430
    #define __NR_fsconfig              431
    #define __NR_fsmount               432
    #define __NR_fspick                433
    #define __NR_pidfd_open            434
    #define __NR_clone3                435
    #define __NR_close_range           436
    #define __NR_openat2               437
    #define __NR_pidfd_getfd           438
    #define __NR_faccessat2            439
    #define __NR_process_madvise       440
    #define __NR_epoll_pwait2          441
    #define __NR_mount_setattr         442
    #define __NR_quotactl_fd           443
    #define __NR_landlock_create_ruleset 444
    #define __NR_landlock_add_rule     445
    #define __NR_landlock_restrict_self 446
    #define __NR_memfd_secret          447
    #define __NR_process_mrelease      448
    #define __NR_futex_waitv           449
    #define __NR_set_mempolicy_home_node 450
    ```

### 系统调用约定

[系统调用查询](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)

| 项目 | 约定 |
|---|---|
| 系统调用号 | `a7` (`x17`) |
| 参数 1-6 | `a0-a5` (`x10-x15`) |
| 返回值 | `a0` (`x10`) |
| 错误 | Linux 通常在 `a0` 返回 `-errno`（约 `-4095` 到 `-1`）表示失败 |
| 触发指令 | `ecall` |

### 系统调用示例

```asm
; write(1, "Hello", 5)
li a0, 1            ; fd = 1 (stdout)
la a1, hello_str    ; buf = "Hello"
li a2, 5            ; count = 5
li a7, 64           ; __NR_write
ecall               ; 系统调用

; exit(0)
li a0, 0            ; status = 0
li a7, 93           ; __NR_exit
ecall
```

## 函数调用约定 (RISC-V ABI)

### 参数传递

| 项目 | RISC-V ABI 约定 |
|---|---|
| 前 8 个参数 | `a0-a7` (`x10-x17`) |
| 更多参数 | 通过栈上传参区域传递 |
| 返回值 | `a0` (`x10`) (64 位), `a0:a1` (`x10:x11`) (128 位) |
| 栈对齐 | 函数入口 `sp` 保持 16 字节对齐 |

!!! note
    `call` 会覆盖 `ra`，所以只要当前函数之后还要返回上一级，就要先保存 `ra`。

### 栈帧结构

```text
高地址
+------------------+
| 第n个参数        |  <- 超过a0-a7的参数
| ...              |
| 第9个参数        |
+------------------+
| 返回地址 (ra)    |  <- 函数调用时保存
| 老的帧指针(fp)   |  <- 可选
| 局部变量         |
| 保存的寄存器     |  <- s0-s11需要保存
+------------------+  <- sp (当前栈指针)
低地址
```

### 函数调用流程

```asm
; 调用者函数 (Caller，非叶子函数示例)
addi sp, sp, -32    ; 分配栈空间并保持16字节对齐
sd ra, 24(sp)       ; call 会覆盖 ra，非叶子函数必须保存自己的返回地址
sd s0, 16(sp)       ; 如果调用者自己使用了 s 寄存器，也要保存
li a0, arg1         ; 设置参数1
li a1, arg2         ; 设置参数2
call function       ; 调用函数
; a0 包含返回值
ld ra, 24(sp)       ; 恢复返回地址
ld s0, 16(sp)       ; 恢复寄存器
addi sp, sp, 32     ; 释放栈空间
ret                 ; 返回

; 被调用者 (Callee)
function:
addi sp, sp, -32    ; 分配栈空间
sd ra, 24(sp)       ; 保存返回地址
sd s0, 16(sp)       ; 保存需要使用的寄存器
; 函数体
li a0, return_val   ; 设置返回值
ld ra, 24(sp)       ; 恢复返回地址
ld s0, 16(sp)       ; 恢复寄存器
addi sp, sp, 32     ; 释放栈空间
ret                 ; 返回
```

### 指令集合

> RISC-V 基础指令通常为 4 字节；启用压缩指令扩展（RVC）时也会出现 2 字节指令。

#### 指令格式

RISC-V 使用多种指令格式：

```text
R-type: funct7 | rs2 | rs1 | funct3 | rd | opcode
I-type: imm\[11:0\] | rs1 | funct3 | rd | opcode
S-type: imm\[11:5\] | rs2 | rs1 | funct3 | imm\[4:0\] | opcode
B-type: imm\[12|10:5\] | rs2 | rs1 | funct3 | imm\[4:1|11\] | opcode
U-type: imm\[31:12\] | rd | opcode
J-type: imm\[20|10:1|11|19:12\] | rd | opcode
```

一般汇编格式：

```asm
MNEMONIC rd, rs1, rs2/imm
助记符 目的寄存器, 源寄存器1, 源寄存器2/立即数
```

#### 指令分类

RISC-V指令可以分为以下几类：

!!! note
    `MUL/DIV/REM` 等乘除法指令来自 M 扩展；多数 Linux 发行版目标会包含该扩展，但阅读极简内核或裸机题时仍需确认 ELF/CPU 支持情况。

##### 整数计算指令（XLEN / 64 位）

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| ADD | 寄存器相加 | `add rd, rs1, rs2` | rd = rs1 + rs2 |
| ADDI | 立即数相加 | `addi rd, rs1, imm` | rd = rs1 + imm |
| SUB | 寄存器相减 | `sub rd, rs1, rs2` | rd = rs1 - rs2 |
| MUL | 乘法 | `mul rd, rs1, rs2` | rd = rs1 * rs2 |
| MULH | 高位乘法 | `mulh rd, rs1, rs2` | rd = (rs1 * rs2) >> 64 |
| DIV | 有符号除法 | `div rd, rs1, rs2` | rd = rs1 / rs2 |
| DIVU | 无符号除法 | `divu rd, rs1, rs2` | rd = rs1 / rs2 (无符号) |
| REM | 有符号求余 | `rem rd, rs1, rs2` | rd = rs1 % rs2 |
| REMU | 无符号求余 | `remu rd, rs1, rs2` | rd = rs1 % rs2 (无符号) |

##### 字运算指令（32 位结果符号扩展）

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| ADDW | 字相加 | `addw rd, rs1, rs2` | rd = sext((rs1 + rs2)\[31:0\]) |
| ADDIW | 立即数字相加 | `addiw rd, rs1, imm` | rd = sext((rs1 + imm)\[31:0\]) |
| SUBW | 字相减 | `subw rd, rs1, rs2` | rd = sext((rs1 - rs2)\[31:0\]) |
| MULW | 字乘法 | `mulw rd, rs1, rs2` | rd = sext((rs1 * rs2)\[31:0\]) |
| DIVW | 有符号字除法 | `divw rd, rs1, rs2` | rd = sext(rs1\[31:0\] / rs2\[31:0\]) |
| DIVUW | 无符号字除法 | `divuw rd, rs1, rs2` | rd = sext(rs1\[31:0\] / rs2\[31:0\]) |
| REMW | 有符号字求余 | `remw rd, rs1, rs2` | rd = sext(rs1\[31:0\] % rs2\[31:0\]) |
| REMUW | 无符号字求余 | `remuw rd, rs1, rs2` | rd = sext(rs1\[31:0\] % rs2\[31:0\]) |

##### 逻辑运算指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| AND | 位与 | `and rd, rs1, rs2` | rd = rs1 & rs2 |
| ANDI | 立即数位与 | `andi rd, rs1, imm` | rd = rs1 & imm |
| OR | 位或 | `or rd, rs1, rs2` | rd = rs1 \| rs2 |
| ORI | 立即数位或 | `ori rd, rs1, imm` | rd = rs1 \| imm |
| XOR | 位异或 | `xor rd, rs1, rs2` | rd = rs1 ^ rs2 |
| XORI | 立即数位异或 | `xori rd, rs1, imm` | rd = rs1 ^ imm |

##### 移位指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| SLL | 逻辑左移 | `sll rd, rs1, rs2` | rd = rs1 << rs2 |
| SLLI | 立即数逻辑左移 | `slli rd, rs1, shamt` | rd = rs1 << shamt |
| SRL | 逻辑右移 | `srl rd, rs1, rs2` | rd = rs1 >> rs2 (逻辑) |
| SRLI | 立即数逻辑右移 | `srli rd, rs1, shamt` | rd = rs1 >> shamt (逻辑) |
| SRA | 算术右移 | `sra rd, rs1, rs2` | rd = rs1 >> rs2 (算术) |
| SRAI | 立即数算术右移 | `srai rd, rs1, shamt` | rd = rs1 >> shamt (算术) |

##### 移位指令 (64位)

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| SLLW | 字逻辑左移 | `sllw rd, rs1, rs2` | rd = sext((rs1 << rs2\[4:0\])\[31:0\]) |
| SLLIW | 立即数字逻辑左移 | `slliw rd, rs1, shamt` | rd = sext((rs1 << shamt)\[31:0\]) |
| SRLW | 字逻辑右移 | `srlw rd, rs1, rs2` | rd = sext(rs1\[31:0\] >> rs2\[4:0\]) |
| SRLIW | 立即数字逻辑右移 | `srliw rd, rs1, shamt` | rd = sext(rs1\[31:0\] >> shamt) |
| SRAW | 字算术右移 | `sraw rd, rs1, rs2` | rd = sext(rs1\[31:0\] >> rs2\[4:0\]) |
| SRAIW | 立即数字算术右移 | `sraiw rd, rs1, shamt` | rd = sext(rs1\[31:0\] >> shamt) |

##### 比较指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| SLT | 小于设置 | `slt rd, rs1, rs2` | rd = (rs1 < rs2) ? 1 : 0 |
| SLTI | 立即数小于设置 | `slti rd, rs1, imm` | rd = (rs1 < imm) ? 1 : 0 |
| SLTU | 无符号小于设置 | `sltu rd, rs1, rs2` | rd = (rs1 < rs2) ? 1 : 0 (无符号) |
| SLTIU | 立即数无符号小于设置 | `sltiu rd, rs1, imm` | rd = (rs1 < imm) ? 1 : 0 (无符号) |

##### 分支指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| BEQ | 相等分支 | `beq rs1, rs2, label` | 如果 rs1 == rs2 跳转 |
| BNE | 不等分支 | `bne rs1, rs2, label` | 如果 rs1 != rs2 跳转 |
| BLT | 小于分支 | `blt rs1, rs2, label` | 如果 rs1 < rs2 跳转 |
| BGE | 大于等于分支 | `bge rs1, rs2, label` | 如果 rs1 >= rs2 跳转 |
| BLTU | 无符号小于分支 | `bltu rs1, rs2, label` | 如果 rs1 < rs2 跳转 (无符号) |
| BGEU | 无符号大于等于分支 | `bgeu rs1, rs2, label` | 如果 rs1 >= rs2 跳转 (无符号) |

##### 跳转指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| JAL | 跳转并链接 | `jal rd, label` | rd = pc + 4; pc = pc + offset |
| JALR | 寄存器跳转并链接 | `jalr rd, rs1, imm` | rd = pc + 4; pc = (rs1 + imm) & ~1 |

##### 加载/存储指令 (32位)

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LW | 加载字 | `lw rd, offset(rs1)` | rd = M\[rs1 + offset\] |
| LH | 加载半字 | `lh rd, offset(rs1)` | rd = M\[rs1 + offset\] (符号扩展) |
| LHU | 加载无符号半字 | `lhu rd, offset(rs1)` | rd = M\[rs1 + offset\] (零扩展) |
| LB | 加载字节 | `lb rd, offset(rs1)` | rd = M\[rs1 + offset\] (符号扩展) |
| LBU | 加载无符号字节 | `lbu rd, offset(rs1)` | rd = M\[rs1 + offset\] (零扩展) |
| SW | 存储字 | `sw rs2, offset(rs1)` | M\[rs1 + offset\] = rs2 |
| SH | 存储半字 | `sh rs2, offset(rs1)` | M\[rs1 + offset\] = rs2\[15:0\] |
| SB | 存储字节 | `sb rs2, offset(rs1)` | M\[rs1 + offset\] = rs2\[7:0\] |

##### 加载/存储指令 (64位)

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LD | 加载双字 | `ld rd, offset(rs1)` | rd = M\[rs1 + offset\] |
| LWU | 加载无符号字 | `lwu rd, offset(rs1)` | rd = M\[rs1 + offset\] (零扩展到64位) |
| SD | 存储双字 | `sd rs2, offset(rs1)` | M\[rs1 + offset\] = rs2 |

##### 立即数加载指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LUI | 加载高位立即数 | `lui rd, imm` | rd = imm << 12 |
| AUIPC | PC相对高位立即数 | `auipc rd, imm` | rd = pc + (imm << 12) |

##### 系统指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| ECALL | 环境调用 | `ecall` | 触发系统调用 |
| EBREAK | 环境断点 | `ebreak` | 触发调试断点 |
| FENCE | 内存屏障 | `fence` | 内存操作排序 |

##### 伪指令

RISC-V 汇编器支持许多伪指令，简化编程：

| 伪指令 | 实际指令 | 示例 | 描述 |
|--------|----------|------|------|
| NOP | `addi x0, x0, 0` | `nop` | 空操作 |
| LI | `addi rd, x0, imm` 或多条指令 | `li t0, 100` | 加载立即数 |
| MV | `addi rd, rs, 0` | `mv t0, t1` | 寄存器移动 |
| NOT | `xori rd, rs, -1` | `not t0, t1` | 按位取反 |
| NEG | `sub rd, x0, rs` | `neg t0, t1` | 取负数 |
| NEGW | `subw rd, x0, rs` | `negw t0, t1` | 取负数(32位) |
| LA | 多条指令 | `la t0, symbol` | 加载地址 |
| J | `jal x0, offset` | `j label` | 无条件跳转 |
| JR | `jalr x0, rs, 0` | `jr ra` | 寄存器跳转 |
| CALL | `auipc ra, offset[31:12]` + `jalr ra, ra, offset[11:0]` | `call func` | 函数调用 |
| RET | `jalr x0, ra, 0` | `ret` | 函数返回 |

#### 寻址模式

RISC-V 支持以下寻址模式：

##### 立即数寻址

```asm
addi t0, zero, 100  # t0 = 0 + 100
li t0, 100          # 伪指令，等价于上面
```

##### 寄存器寻址

```asm
add t0, t1, t2      # t0 = t1 + t2
mv t0, t1           # t0 = t1 (伪指令)
```

##### 基址+偏移寻址

```asm
ld t0, 8(sp)        # t0 = M[sp + 8]
sd t0, -8(t1)       # M[t1 - 8] = t0
```

##### PC相对寻址

```asm
auipc t0, 0x10000   # t0 = pc + (0x10000 << 12)
```

##### 符号地址寻址

```asm
la t0, symbol       # 加载符号地址
lui t0, %hi(symbol) # 加载符号高位
addi t0, t0, %lo(symbol) # 加载符号低位
```

#### 重点指令详解

##### 算术运算指令

| 指令 | 计算公式 | 示例 | 备注 |
|------|----------|------|------|
| ADD rd, rs1, rs2 | rd = rs1 + rs2 | `add t0, t1, t2` | 64位加法 |
| ADDI rd, rs1, imm | rd = rs1 + imm | `addi t0, t1, 100` | 立即数加法 |
| SUB rd, rs1, rs2 | rd = rs1 - rs2 | `sub t0, t1, t2` | 64位减法 |
| ADDW rd, rs1, rs2 | rd = sext((rs1 + rs2)\[31:0\]) | `addw t0, t1, t2` | 32位加法，符号扩展 |
| SUBW rd, rs1, rs2 | rd = sext((rs1 - rs2)\[31:0\]) | `subw t0, t1, t2` | 32位减法，符号扩展 |
| MUL rd, rs1, rs2 | rd = (rs1 * rs2)\[63:0\] | `mul t0, t1, t2` | 乘法低64位 |
| MULH rd, rs1, rs2 | rd = (rs1 * rs2)\[127:64\] | `mulh t0, t1, t2` | 有符号乘法高64位 |
| MULHU rd, rs1, rs2 | rd = (rs1 * rs2)\[127:64\] | `mulhu t0, t1, t2` | 无符号乘法高64位 |
| MULHSU rd, rs1, rs2 | rd = (rs1 * rs2)\[127:64\] | `mulhsu t0, t1, t2` | 有符号×无符号乘法高64位 |
| DIV rd, rs1, rs2 | rd = rs1 / rs2 | `div t0, t1, t2` | 有符号除法 |
| DIVU rd, rs1, rs2 | rd = rs1 / rs2 | `divu t0, t1, t2` | 无符号除法 |
| REM rd, rs1, rs2 | rd = rs1 % rs2 | `rem t0, t1, t2` | 有符号求余 |
| REMU rd, rs1, rs2 | rd = rs1 % rs2 | `remu t0, t1, t2` | 无符号求余 |

##### 数据传输指令示例

| 指令 | 目的 | 源 | 描述 |
|------|------|----|----- |
| MV | t0 | t1 | 将 t1 里面的数据复制到 t0 中 |
| LI | t0 | 0x1234 | 将立即数0x1234加载到t0中 |
| LA | t0 | symbol | 将符号地址加载到t0中 |
| LD | t0 | 0(t1) | 从t1指向的地址加载双字到t0 |
| LW | t0 | 4(t1) | 从t1+4地址加载字到t0 |
| SD | t1 | 0(t0) | 将 t1 中的值写入到 t0 中所保存的地址中 |

##### 栈操作指令

RISC-V 没有专门的栈指令，使用加载/存储指令操作栈：

| 操作 | 指令序列 | 描述 | 等价效果 |
|------|----------|------|----------|
| PUSH t0 | `addi sp, sp, -8` + `sd t0, 0(sp)` | 将 t0 压栈 | 减少栈指针，存储值 |
| POP t0 | `ld t0, 0(sp)` + `addi sp, sp, 8` | 从栈中弹出到 t0 | 加载值，增加栈指针 |
| 保存返回地址 | `addi sp, sp, -8` + `sd ra, 0(sp)` | 保存返回地址 | 函数序言 |
| 恢复返回地址 | `ld ra, 0(sp)` + `addi sp, sp, 8` | 恢复返回地址 | 函数结尾 |

#### 常用编程模式

##### 循环结构

```asm
# for循环示例: for(int i=0; i<10; i++)
li t0, 0            # i = 0
li t1, 10           # 循环上界
loop:
    bge t0, t1, loop_end    # 如果 i >= 10 跳出循环
    # 循环体代码
    addi t0, t0, 1  # i++
    j loop          # 跳回循环开始
loop_end:

# while循环示例: while(condition)
while_loop:
    # 检查条件的代码
    beq t0, zero, while_end   # 条件为假则退出
    # 循环体代码
    j while_loop    # 继续循环
while_end:
```

##### 条件判断

```asm
# if-else 结构
li t1, 5
blt t0, t1, else_branch     # 如果 t0 < 5 跳到 else
    # if 分支代码
    li t2, 1
    j endif
else_branch:
    # else 分支代码
    li t2, 0
endif:

# switch-case 结构
li t1, 1
beq t0, t1, case1
li t1, 2
beq t0, t1, case2
li t1, 3
beq t0, t1, case3
j default_case

case1:
    # case 1 代码
    j switch_end
case2:
    # case 2 代码
    j switch_end
case3:
    # case 3 代码
    j switch_end
default_case:
    # 默认情况代码
switch_end:
```

##### 函数调用模板

```asm
# 标准函数模板
function_name:
    addi sp, sp, -32    # 为局部变量分配栈空间
    sd ra, 24(sp)       # 保存返回地址
    sd s0, 16(sp)       # 保存需要使用的寄存器
    sd s1, 8(sp)

    # 函数体
    # 参数在 a0-a7 中
    # 局部变量使用栈空间

    li a0, return_val   # 设置返回值

    ld ra, 24(sp)       # 恢复返回地址
    ld s0, 16(sp)       # 恢复寄存器
    ld s1, 8(sp)
    addi sp, sp, 32     # 释放栈空间
    ret                 # 返回

# 调用函数
    li a0, arg1         # 第一个参数
    li a1, arg2         # 第二个参数
    li a2, arg3         # 第三个参数
    li a3, arg4         # 第四个参数
    call function_name  # 调用函数
    # 返回值在 a0 中
```

##### 数组操作

```asm
# 数组遍历示例
la t0, array_base       # 数组基地址
li t1, 0                # 索引 i = 0
li t2, array_size       # 数组大小

array_loop:
    bge t1, t2, array_end   # i >= size 则结束

    slli t3, t1, 3      # t3 = i * 8 (假设long数组)
    add t3, t0, t3      # t3 = 数组基地址 + i*8
    ld t4, 0(t3)        # 加载 array[i]
    # 处理 t4 中的数据

    addi t1, t1, 1      # i++
    j array_loop
array_end:

# 字符串长度计算
la t0, string_ptr       # 字符串指针
li t1, 0                # 长度计数器

strlen_loop:
    add t2, t0, t1      # t2 = 字符串地址 + 偏移
    lb t3, 0(t2)        # 加载当前字符
    beq t3, zero, strlen_end    # 检查是否为'\0'
    addi t1, t1, 1      # 长度++
    j strlen_loop
strlen_end:
    # t1 包含字符串长度
```

##### 位操作技巧

```asm
# 检查第n位是否为1
li t1, 1
sll t1, t1, t0      # t1 = 1 << n
and t3, t2, t1      # 测试 t2 的第n位
bne t3, zero, bit_is_set    # 如果位为1则跳转

# 设置第n位为1
li t1, 1
sll t1, t1, t0      # t1 = 1 << n
or t2, t2, t1       # t2 |= (1 << n)

# 清除第n位
li t1, 1
sll t1, t1, t0      # t1 = 1 << n
not t1, t1          # t1 = ~(1 << n)
and t2, t2, t1      # t2 &= ~(1 << n)

# 切换第n位
li t1, 1
sll t1, t1, t0      # t1 = 1 << n
xor t2, t2, t1      # t2 ^= (1 << n)

# 计算2的幂次
li t1, 1
sll t1, t1, t0      # t1 = 2^t0

# 除以2的幂次(无符号)
srl t1, t2, t0      # t1 = t2 / (2^t0)

# 除以2的幂次(有符号)
sra t1, t2, t0      # t1 = t2 / (2^t0) (保持符号)
```

##### 内存对齐和优化

```asm
# 8字节对齐检查
andi t1, t0, 7      # 检查低3位
bne t1, zero, not_aligned   # 如果不为0则未对齐

# 向上对齐到8字节边界
addi t0, t0, 7      # t0 += 7
andi t0, t0, -8     # t0 &= ~7

# 向下对齐到8字节边界
andi t0, t0, -8     # t0 &= ~7

# 快速清零内存块
mv t1, t0           # 保存起始地址
add t2, t0, t3      # 计算结束地址
clear_loop:
    bge t1, t2, clear_end
    sd zero, 0(t1)  # 存储0
    addi t1, t1, 8  # 递增地址
    j clear_loop
clear_end:
```

##### 64位特有操作

```asm
# 32位运算并符号扩展
addw t0, t1, t2     # 32位加法，结果符号扩展到64位
subw t0, t1, t2     # 32位减法，结果符号扩展到64位
mulw t0, t1, t2     # 32位乘法，结果符号扩展到64位

# 64位立即数加载
li t0, 0x123456789abcdef0   # 加载64位立即数

# 混合32位和64位操作
lwu t0, 0(t1)       # 加载32位值，零扩展到64位
lw t0, 0(t1)        # 加载32位值，符号扩展到64位
sw t0, 0(t1)        # 存储32位值
sd t0, 0(t1)        # 存储64位值

# 字移位操作
slliw t0, t1, 5     # 32位左移5位，符号扩展到64位
srliw t0, t1, 5     # 32位逻辑右移5位，符号扩展到64位
sraiw t0, t1, 5     # 32位算术右移5位，符号扩展到64位
```

这些编程模式涵盖了RISC-V 64位汇编中最常用的结构和技巧，可以作为编写RISC-V 64位汇编程序的参考模板。
