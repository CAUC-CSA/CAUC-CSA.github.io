# MIPS64 架构基础知识

!!! tip "Pwn 速查"
    - n64/n32 函数参数：`$a0-$a7`；系统调用参数通常只用 `$a0-$a5`。
    - Linux MIPS 各 ABI 的 syscall 错误由 `$a3` 标记，出错时 `$v0` 通常是正 errno。
    - n64/n32 栈对齐为 16 字节；MIPS64 仍有延迟槽。

## MIPS64 寄存器详解

### 通用寄存器 (`$0-$31`)

| 寄存器 | 别名 | 用途 |
|---|---|---|
| `$0` | `$zero` | 硬件零寄存器，永远为 0 |
| `$1` | `$at` | 汇编器临时寄存器 |
| `$2-$3` | `$v0-$v1` | 函数返回值；`$v0` 也放系统调用号 |
| `$4-$11` | `$a0-$a7` | n32/n64 函数参数 |
| `$12-$15` | `$t4-$t7` | n32/n64 临时寄存器 |
| `$16-$23` | `$s0-$s7` | 保存寄存器 |
| `$24-$25` | `$t8-$t9` | 临时寄存器 |
| `$26-$27` | `$k0-$k1` | 内核保留 |
| `$28` | `$gp` | 全局指针 |
| `$29` | `$sp` | 栈指针 |
| `$30` | `$fp` / `$s8` | 帧指针 / 保存寄存器 |
| `$31` | `$ra` | 返回地址 |

### 寄存器别名和用途

| 寄存器 | 别名 | 主要用途 | 调用约定 |
|---|---|---|---|
| `$0` | `$zero` | 硬件零寄存器 | 常数 0 |
| `$1` | `$at` | 汇编器临时寄存器 | 汇编器保留 |
| `$2` | `$v0` | 函数返回值 / 系统调用号 | 调用者保存 |
| `$3` | `$v1` | 函数返回值 | 调用者保存 |
| `$4-$7` | `$a0-$a3` | 第 1-4 个参数 | 调用者保存 |
| `$8-$11` | `$a4-$a7` | 第 5-8 个参数（n32/n64） | 调用者保存 |
| `$12-$15` | `$t4-$t7` | 临时寄存器（n32/n64） | 调用者保存 |
| `$16-$23` | `$s0-$s7` | 保存寄存器 | 被调用者保存 |
| `$24-$25` | `$t8-$t9` | 临时寄存器 | 调用者保存 |
| `$26-$27` | `$k0-$k1` | 内核保留 | 不应在用户态随意使用 |
| `$28` | `$gp` | 全局指针 | ABI 相关 |
| `$29` | `$sp` | 栈指针 | 特殊 |
| `$30` | `$fp` / `$s8` | 帧指针 / 保存寄存器 | 被调用者保存 |
| `$31` | `$ra` | 返回地址 | 特殊：非叶子函数需先保存自己的返回地址 |

### 特殊寄存器

| 寄存器 | 作用 |
|---|---|
| `PC` | 程序计数器（64 位） |
| `HI` | 乘法 / 除法结果高位（64 位） |
| `LO` | 乘法 / 除法结果低位（64 位） |

## 字节序

MIPS64 (big-endian) 与 MIPS64EL (little-endian) 主要区别在内存中字节排列，上层寄存器与 ABI 规则相同。

| 架构 | 端序 | `0x1122334455667788` 在内存中的字节序（地址递增） |
|---|---|---|
| MIPS64 | Big-endian | `11 22 33 44 55 66 77 88` |
| MIPS64EL | Little-endian | `88 77 66 55 44 33 22 11` |

!!! tip "Exploit 提醒"
    地址泄漏、栈覆盖和 ROP payload 写入时要同时确认 ABI 与端序；MIPS64 的“64 位 CPU”不等于一定是 n64 ABI。

### 三种主要 ABI

| ABI | 指针 / `long` | 参数寄存器 | 栈对齐 | Pwn 关注点 |
|---|---|---|---|---|
| o32 | 32 位 | `$a0-$a3` | 8 字节 | 兼容 MIPS32，syscall 基址 `4000` |
| n32 | 32 位指针 + 64 位寄存器 | `$a0-$a7` | 16 字节 | 指针仍是 32 位，但可使用 64 位运算 |
| n64 | 64 位 | `$a0-$a7` | 16 字节 | 现代 64 位 MIPS 主要 ABI，syscall 基址 `5000` |

!!! warning
    同一个 MIPS64 ELF 不能只看“64 位 CPU”，还要看 ABI：o32/n32/n64 的系统调用号、参数数量和栈布局都不同。

### 函数调用约定详解

#### 参数传递

不同 ABI 的参数传递规则：

| ABI | 参数寄存器 | 更多参数 | 返回值 | 栈对齐 |
|---|---|---|---|---|
| n64 | `$a0-$a7` (`$4-$11`) | 栈传递 | `$v0`, `$v1` (`$2`, `$3`) | 16 字节 |
| n32 | `$a0-$a7` (`$4-$11`) | 栈传递 | `$v0`, `$v1` (`$2`, `$3`) | 16 字节 |
| o32 | `$a0-$a3` (`$4-$7`) | 栈传递 | `$v0`, `$v1` (`$2`, `$3`) | 8 字节 |

!!! note
    `$ra` 不是普通“被调用者保存”寄存器：非叶子函数执行新的 `jal` 前必须先保存自己的返回地址。

### 栈帧结构 (n64)

```text
高地址
┌─────────────────┐ <- 调用者栈帧
│   第10个参数     │  $sp + 8
├─────────────────┤
│   第9个参数      │  $sp + 0
├─────────────────┤ <- $sp (调用时)
│   返回地址       │  被调用者保存 $ra
├─────────────────┤
│   保存的$fp      │  被调用者保存 $fp
├─────────────────┤
│   局部变量       │  被调用者分配
├─────────────────┤
│   保存的寄存器   │  $s0-$s7等
└─────────────────┘ <- 新的$sp
低地址
```

### 函数调用流程

```asm
# 调用者 (Caller) - n64 ABI
# 保存临时寄存器 (如果需要)
daddiu $sp, $sp, -16    # 分配栈空间
sd $t0, 0($sp)          # 保存寄存器
sd $t1, 8($sp)

li $a0, arg1            # 设置参数1
li $a1, arg2            # 设置参数2
li $a2, arg3            # 设置参数3
jal function            # 调用函数
nop                     # 延迟槽

# $v0 包含返回值
ld $t1, 8($sp)          # 恢复寄存器
ld $t0, 0($sp)
daddiu $sp, $sp, 16     # 恢复栈

# 被调用者 (Callee) - n64 ABI
function:
daddiu $sp, $sp, -64    # 分配栈空间
sd $ra, 56($sp)         # 保存返回地址
sd $fp, 48($sp)         # 保存帧指针
sd $s0, 40($sp)         # 保存需要使用的寄存器
sd $s1, 32($sp)
move $fp, $sp           # 设置新的帧指针

# 函数体

li $v0, return_val      # 设置返回值
ld $s1, 32($sp)         # 恢复寄存器
ld $s0, 40($sp)
ld $fp, 48($sp)         # 恢复帧指针
ld $ra, 56($sp)         # 恢复返回地址
daddiu $sp, $sp, 64     # 释放栈空间
jr $ra                  # 返回
nop                     # 延迟槽
```

### 返回值寄存器

| 寄存器 | 用途 | 说明 |
|--------|------|------|
| $v0 ($2) | 主要返回值 | 64位整数或指针 |
| $v1 ($3) | 辅助返回值 | 128位整数返回值的高64位；浮点返回值通常走浮点寄存器 |

## Linux MIPS64 系统调用表

### 系统调用号 ABI 对比

MIPS64 支持三种 ABI，每种都有不同的系统调用号基址：

| ABI | 系统调用号基址 | 说明 |
|---|---:|---|
| o32 | `4000` | 兼容 MIPS32 |
| n32 | `6000` | 32 位指针 + 64 位寄存器 |
| n64 | `5000` | 64 位 ABI |

### 常用系统调用号

#### n64 ABI 系统调用约定

```c
#define __NR_N64_Linux              5000
#define __NR_read        0   /* 5000 */
#define __NR_write       1   /* 5001 */
#define __NR_open        2   /* 5002 */
#define __NR_close       3   /* 5003 */
#define __NR_stat        4   /* 5004 */
#define __NR_fstat       5   /* 5005 */
#define __NR_lstat       6   /* 5006 */
#define __NR_poll        7   /* 5007 */
#define __NR_lseek       8   /* 5008 */
#define __NR_mmap        9   /* 5009 */
#define __NR_mprotect   10   /* 5010 */
#define __NR_munmap     11   /* 5011 */
#define __NR_brk        12   /* 5012 */
#define __NR_rt_sigprocmask 14 /* 5014 */
#define __NR_ioctl      16   /* 5016 */
#define __NR_pipe       22   /* 5022 */
#define __NR_dup        32   /* 5032 */
#define __NR_dup2       33   /* 5033 */
#define __NR_getpid     39   /* 5039 */
#define __NR_socket     41   /* 5041 */
#define __NR_connect    42   /* 5042 */
#define __NR_bind       49   /* 5049 */
#define __NR_listen     50   /* 5050 */
#define __NR_clone      56   /* 5056 */
#define __NR_execve     57   /* 5057 */
#define __NR_exit       58   /* 5058 */
#define __NR_wait4      61   /* 5061 */
#define __NR_kill       62   /* 5062 */
#define __NR_mkdir      83   /* 5083 */
#define __NR_rmdir      84   /* 5084 */
```

#### n32 ABI 系统调用号

```c
#define __NR_N32_Linux              6000
#define __NR_read        0   /* 6000 */
#define __NR_write       1   /* 6001 */
#define __NR_open        2   /* 6002 */
#define __NR_close       3   /* 6003 */
#define __NR_stat        4   /* 6004 */
#define __NR_fstat       5   /* 6005 */
#define __NR_lstat       6   /* 6006 */
#define __NR_poll        7   /* 6007 */
#define __NR_lseek       8   /* 6008 */
#define __NR_mmap        9   /* 6009 */
```

#### o32 ABI (MIPS32 兼容)

```c
#define __NR_O32_Linux              4000
#define __NR_read        3   /* 4003 */
#define __NR_write       4   /* 4004 */
#define __NR_open        5   /* 4005 */
#define __NR_close       6   /* 4006 */
#define __NR_waitpid     7   /* 4007 */
#define __NR_creat       8   /* 4008 */
#define __NR_link        9   /* 4009 */
#define __NR_unlink     10   /* 4010 */
#define __NR_execve     11   /* 4011 */
#define __NR_mmap       90   /* 4090 */
```

### 系统调用约定

不同 ABI 的系统调用约定略有差异：

| ABI | 调用号 | 参数 | 返回值 / errno | 错误指示 | 指令 |
|---|---|---|---|---|---|
| n64 | `$v0` (`$2`) | `$a0-$a5` (`$4-$9`) | `$v0` | `$a3 != 0` 表示错误 | `syscall` |
| n32 | `$v0` (`$2`) | `$a0-$a5` (`$4-$9`) | `$v0` | `$a3 != 0` 表示错误 | `syscall` |
| o32 | `$v0` (`$2`) | `$a0-$a3`，第 5-6 参数走栈 | `$v0` | `$a3 != 0` 表示错误 | `syscall` |

!!! note
    出错时 `$v0` 通常为正 errno，不要按 x86/AArch64/RISC-V 的 `-errno` 模型判断。

### 系统调用示例（基本用法）

#### n64 ABI 示例

```asm
# write(1, "Hello", 5) - n64 ABI
li $v0, 5001        # __NR_write
li $a0, 1           # fd = 1 (stdout)
dla $a1, hello      # buf = "Hello" (64位地址加载)
li $a2, 5           # count = 5
syscall             # 系统调用

# exit(0) - n64 ABI
li $v0, 5058        # __NR_exit
li $a0, 0           # status = 0
syscall
```

#### o32 ABI 示例

```asm
# write(1, "Hello", 5) - o32 ABI
li $v0, 4004        # __NR_write
li $a0, 1           # fd = 1 (stdout)
la $a1, hello       # buf = "Hello" (32位地址加载)
li $a2, 5           # count = 5
syscall             # 系统调用

# 错误检查 (o32)
bnez $a3, error     # $a3 非零表示错误
nop

# exit(0) - o32 ABI
li $v0, 4001        # __NR_exit
li $a0, 0           # status = 0
syscall
```

## 系统调用详解

### 系统调用寄存器约定

#### 系统调用号寄存器

| 寄存器 | ABI | 说明 |
|--------|-----|------|
| $v0 ($2) | o32 | MIPS32兼容模式系统调用号 |
| $v0 ($2) | n32 | n32 ABI系统调用号 |
| $v0 ($2) | n64 | n64 ABI系统调用号 |

#### 参数传递寄存器 (系统调用)

不同 ABI 的系统调用参数传递方式：

##### o32 ABI 系统调用

```asm
# o32 系统调用参数 (最多6个)
# $v0: 系统调用号
# $a0-$a3: 前4个参数
# 栈: 第5-6个参数

li      $v0, 4004        # write 系统调用号 (o32)
li      $a0, 1           # fd = 1 (stdout)
la      $a1, msg         # buffer 地址
li      $a2, msg_len     # count
syscall                  # 执行系统调用
```

##### n32 ABI 系统调用

```asm
# n32 系统调用参数 (最多6个)
# $v0: 系统调用号
# $a0-$a5: 前6个参数

li      $v0, 6001        # write 系统调用号 (n32)
li      $a0, 1           # fd = 1
dla     $a1, msg         # buffer 地址 (64位加载)
li      $a2, msg_len     # count
syscall                  # 执行系统调用
```

##### n64 ABI 系统调用

```asm
# n64 系统调用参数 (最多6个)
# $v0: 系统调用号
# $a0-$a5: 前6个参数

li      $v0, 5001        # write 系统调用号 (n64)
li      $a0, 1           # fd = 1
dla     $a1, msg         # buffer 地址 (64位)
li      $a2, msg_len     # count
syscall                  # 执行系统调用
```

### 系统调用返回值

| 寄存器 | 用途 | 说明 |
|--------|------|------|
| $v0 ($2) | 返回值 / errno | 成功时为返回值；失败时通常为正 errno |
| $a3 ($7) | 错误指示 | Linux MIPS 各 ABI 中，非零表示错误 |

### 常用系统调用号对比

| 系统调用 | o32 | n32 | n64 | 参数 |
|----------|-----|-----|-----|------|
| read | 4003 | 6000 | 5000 | fd, buf, count |
| write | 4004 | 6001 | 5001 | fd, buf, count |
| open | 4005 | 6002 | 5002 | pathname, flags, mode |
| close | 4006 | 6003 | 5003 | fd |
| mmap | 4090 | 6009 | 5009 | addr, len, prot, flags, fd, offset |
| execve | 4011 | 6057 | 5057 | filename, argv, envp |

### 系统调用示例

#### 完整的 write 系统调用 (n64)

```asm
.section .data
msg:    .ascii "Hello, World!\n"
msg_len = . - msg

.section .text
.globl _start

_start:
    # write(1, msg, msg_len)
    li      $v0, 5001        # write 系统调用号
    li      $a0, 1           # fd = 1 (stdout)
    dla     $a1, msg         # buffer 地址
    li      $a2, msg_len     # count = 14
    syscall                  # 执行系统调用

    # 检查返回值
    bnez    $a3, error       # Linux MIPS 使用 $a3 标记 syscall 错误
    nop

    # exit(0)
    li      $v0, 5058        # exit 系统调用号
    li      $a0, 0           # exit_code = 0
    syscall

error:
    # exit(1)
    li      $v0, 5058        # exit 系统调用号
    li      $a0, 1           # exit_code = 1
    syscall
```

### 系统调用错误处理

```asm
# 错误检查模式1：检查 $a3 错误标志（o32/n32/n64 通用）
syscall
bnez    $a3, error_handler  # $a3 != 0 表示错误
nop

# 错误处理
error_handler:
    # $v0 通常包含正 errno
    move    $t0, $v0
    # 进行错误处理...
```

## 指令集特性

### 64 位专用指令

MIPS64 在 MIPS32 基础上增加了 64 位操作指令：

| 指令 | 功能 | 示例 | 描述 |
|------|------|------|------|
| ld | 64 位加载 | `ld $t0, 0($sp)` | 从内存加载64位数据 |
| sd | 64 位存储 | `sd $t0, 8($sp)` | 向内存存储64位数据 |
| daddi | 64 位立即数加法 | `daddi $t0, $t1, 100` | 64位有符号加法 |
| daddiu | 64 位无符号立即数加法 | `daddiu $t0, $t1, 100` | 64位无符号加法 |
| daddu | 64 位无符号加法 | `daddu $t0, $t1, $t2` | 64位寄存器加法 |
| dsubu | 64 位无符号减法 | `dsubu $t0, $t1, $t2` | 64位寄存器减法 |
| dsll | 64 位逻辑左移 | `dsll $t0, $t1, 16` | 64位数据左移 |
| dsrl | 64 位逻辑右移 | `dsrl $t0, $t1, 8` | 64位数据右移 |
| dsra | 64 位算术右移 | `dsra $t0, $t1, 4` | 64位算术右移 |
| dsllv | 64 位变量左移 | `dsllv $t0, $t1, $t2` | 根据寄存器左移 |
| dsrlv | 64 位变量右移 | `dsrlv $t0, $t1, $t2` | 根据寄存器右移 |
| dsrav | 64 位变量算术右移 | `dsrav $t0, $t1, $t2` | 根据寄存器算术右移 |
| dmult | 64 位乘法 | `dmult $t0, $t1` | 64位有符号乘法 |
| dmultu | 64 位无符号乘法 | `dmultu $t0, $t1` | 64位无符号乘法 |
| ddiv | 64 位除法 | `ddiv $t0, $t1` | 64位有符号除法 |
| ddivu | 64 位无符号除法 | `ddivu $t0, $t1` | 64位无符号除法 |

### 兼容的 32 位指令

32 位指令在 64 位寄存器上执行时，结果会进行符号扩展：

| 指令 | 64位结果 | 示例 | 说明 |
|------|----------|------|------|
| lw | 符号扩展到64位 | `lw $t0, 0($sp)` | 加载32位，符号扩展 |
| addiu | 符号扩展到64位 | `addiu $t0, $t1, 100` | 32位加法，符号扩展 |
| sll | 符号扩展到64位 | `sll $t0, $t1, 4` | 32位左移，符号扩展 |
| addu | 符号扩展到64位 | `addu $t0, $t1, $t2` | 32位加法，符号扩展 |

### 地址计算与64位立即数加载

#### 64位立即数加载技术

```asm
# 方法1: 完整64位立即数加载
# 加载 0x123456789ABCDEF0
lui     $t0, 0x1234          # 加载高 16 位到 $t0[31:16]
ori     $t0, $t0, 0x5678     # 或运算低 16 位 -> $t0 = 0x12345678
dsll    $t0, $t0, 16         # 左移 16 位 -> $t0 = 0x123456780000
ori     $t0, $t0, 0x9ABC     # 继续构造 -> $t0 = 0x123456789ABC
dsll    $t0, $t0, 16         # 再次左移 -> $t0 = 0x123456789ABC0000
ori     $t0, $t0, 0xDEF0     # 完成 64 位立即数 -> $t0 = 0x123456789ABCDEF0

# 方法2: 简化版64位立即数加载（较小数值）
# 加载 0x0000000012345678
lui     $t0, 0x1234          # $t0 = 0x12340000
ori     $t0, $t0, 0x5678     # $t0 = 0x12345678 (自动符号扩展)

# 方法3: 使用 dli 伪指令（编译器会自动选择最优方式）
dli     $t0, 0x123456789ABCDEF0

# 方法4: 负数立即数加载
# 加载 -1 (0xFFFFFFFFFFFFFFFF)
daddiu  $t0, $zero, -1       # 最简单的方式

# 方法5: 地址计算优化
# 如果只需要高32位有值
lui     $t0, 0x1234          # $t0 = 0x12340000
dsll    $t0, $t0, 16         # $t0 = 0x123400000000
```

#### 常用地址计算模式

```asm
# 数组索引计算: array[index]
# 假设: $a0 = array_base, $a1 = index, 每个元素8字节
dsll    $t0, $a1, 3          # index * 8
daddu   $t0, $a0, $t0        # array_base + index*8
ld      $t1, 0($t0)          # 加载 array[index]

# 结构体成员访问: struct->member
# 假设: $a0 = struct_ptr, 成员偏移为24字节
ld      $t0, 24($a0)         # 加载成员值

# 多维数组: array[i][j] (假设每行10个8字节元素)
# $a1 = i, $a2 = j
li      $t0, 10              # 每行元素数
dmult   $a1, $t0             # i * 10
mflo    $t0                  # 获取乘法结果
daddu   $t0, $t0, $a2        # i*10 + j
dsll    $t0, $t0, 3          # (i*10+j) * 8
daddu   $t0, $a0, $t0        # array_base + offset
ld      $t1, 0($t0)          # 加载 array[i][j]
```

## 指令格式与指令集合

### 指令格式

MIPS64 继承了 MIPS32 的三种指令格式，指令长度仍为 32 位：

#### R-Type (寄存器类型)

```text
31    26 25   21 20   16 15   11 10    6 5     0
+--------+-------+-------+-------+-------+-------+
|   op   |  rs   |  rt   |  rd   | shamt | funct |
+--------+-------+-------+-------+-------+-------+
  6 bits  5 bits  5 bits  5 bits  5 bits  6 bits
```

#### I-Type (立即数类型)

```text
31    26 25   21 20   16 15                    0
+--------+-------+-------+------------------------+
|   op   |  rs   |  rt   |      immediate         |
+--------+-------+-------+------------------------+
  6 bits  5 bits  5 bits       16 bits
```

#### J-Type (跳转类型)

```text
31    26 25                                     0
+--------+-----------------------------------------+
|   op   |              address                  |
+--------+-----------------------------------------+
  6 bits              26 bits
```

### 指令分类

#### 算术运算指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| dadd | dadd rd, rs, rt | rd = rs + rt | `dadd $t0, $t1, $t2` | 64位有符号加法 |
| daddu | daddu rd, rs, rt | rd = rs + rt | `daddu $t0, $t1, $t2` | 64位无符号加法 |
| daddi | daddi rt, rs, imm | rt = rs + imm | `daddi $t0, $t1, 100` | 64位立即数加法 |
| daddiu | daddiu rt, rs, imm | rt = rs + imm | `daddiu $t0, $t1, 100` | 64位无符号立即数加法 |
| dsub | dsub rd, rs, rt | rd = rs - rt | `dsub $t0, $t1, $t2` | 64位有符号减法 |
| dsubu | dsubu rd, rs, rt | rd = rs - rt | `dsubu $t0, $t1, $t2` | 64位无符号减法 |
| dmult | dmult rs, rt | HI:LO = rs * rt | `dmult $t0, $t1` | 64位有符号乘法 |
| dmultu | dmultu rs, rt | HI:LO = rs * rt | `dmultu $t0, $t1` | 64位无符号乘法 |
| ddiv | ddiv rs, rt | LO=rs/rt, HI=rs%rt | `ddiv $t0, $t1` | 64位有符号除法 |
| ddivu | ddivu rs, rt | LO=rs/rt, HI=rs%rt | `ddivu $t0, $t1` | 64位无符号除法 |
| add | add rd, rs, rt | rd = rs + rt | `add $t0, $t1, $t2` | 32位有符号加法(符号扩展) |
| addu | addu rd, rs, rt | rd = rs + rt | `addu $t0, $t1, $t2` | 32位无符号加法(符号扩展) |
| addi | addi rt, rs, imm | rt = rs + imm | `addi $t0, $t1, 100` | 32位立即数加法(符号扩展) |
| addiu | addiu rt, rs, imm | rt = rs + imm | `addiu $t0, $t1, 100` | 32位无符号立即数加法(符号扩展) |
| sub | sub rd, rs, rt | rd = rs - rt | `sub $t0, $t1, $t2` | 32位有符号减法(符号扩展) |
| subu | subu rd, rs, rt | rd = rs - rt | `subu $t0, $t1, $t2` | 32位无符号减法(符号扩展) |
| mult | mult rs, rt | HI:LO = rs * rt | `mult $t0, $t1` | 32位有符号乘法 |
| multu | multu rs, rt | HI:LO = rs * rt | `multu $t0, $t1` | 32位无符号乘法 |
| div | div rs, rt | LO=rs/rt, HI=rs%rt | `div $t0, $t1` | 32位有符号除法 |
| divu | divu rs, rt | LO=rs/rt, HI=rs%rt | `divu $t0, $t1` | 32位无符号除法 |

#### 逻辑运算指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| and | and rd, rs, rt | rd = rs & rt | `and $t0, $t1, $t2` | 64位按位与 |
| andi | andi rt, rs, imm | rt = rs & imm | `andi $t0, $t1, 0xFF` | 立即数按位与 |
| or | or rd, rs, rt | rd = rs \| rt | `or $t0, $t1, $t2` | 64位按位或 |
| ori | ori rt, rs, imm | rt = rs \| imm | `ori $t0, $t1, 0xFF` | 立即数按位或 |
| xor | xor rd, rs, rt | rd = rs ^ rt | `xor $t0, $t1, $t2` | 64位按位异或 |
| xori | xori rt, rs, imm | rt = rs ^ imm | `xori $t0, $t1, 0xFF` | 立即数按位异或 |
| nor | nor rd, rs, rt | rd = ~(rs \| rt) | `nor $t0, $t1, $t2` | 64位按位或非 |

#### 移位指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| dsll | dsll rd, rt, shamt | rd = rt << shamt | `dsll $t0, $t1, 2` | 64位逻辑左移 |
| dsllv | dsllv rd, rt, rs | rd = rt << rs | `dsllv $t0, $t1, $t2` | 64位变量逻辑左移 |
| dsrl | dsrl rd, rt, shamt | rd = rt >> shamt | `dsrl $t0, $t1, 2` | 64位逻辑右移 |
| dsrlv | dsrlv rd, rt, rs | rd = rt >> rs | `dsrlv $t0, $t1, $t2` | 64位变量逻辑右移 |
| dsra | dsra rd, rt, shamt | rd = rt >> shamt | `dsra $t0, $t1, 2` | 64位算术右移 |
| dsrav | dsrav rd, rt, rs | rd = rt >> rs | `dsrav $t0, $t1, $t2` | 64位变量算术右移 |
| dsll32 | dsll32 rd, rt, shamt | rd = rt << (shamt+32) | `dsll32 $t0, $t1, 0` | 64位左移32+shamt位 |
| dsrl32 | dsrl32 rd, rt, shamt | rd = rt >> (shamt+32) | `dsrl32 $t0, $t1, 0` | 64位右移32+shamt位 |
| dsra32 | dsra32 rd, rt, shamt | rd = rt >> (shamt+32) | `dsra32 $t0, $t1, 0` | 64位算术右移32+shamt位 |
| sll | sll rd, rt, shamt | rd = rt << shamt | `sll $t0, $t1, 2` | 32位逻辑左移(符号扩展) |
| sllv | sllv rd, rt, rs | rd = rt << rs | `sllv $t0, $t1, $t2` | 32位变量逻辑左移(符号扩展) |
| srl | srl rd, rt, shamt | rd = rt >> shamt | `srl $t0, $t1, 2` | 32位逻辑右移(符号扩展) |
| srlv | srlv rd, rt, rs | rd = rt >> rs | `srlv $t0, $t1, $t2` | 32位变量逻辑右移(符号扩展) |
| sra | sra rd, rt, shamt | rd = rt >> shamt | `sra $t0, $t1, 2` | 32位算术右移(符号扩展) |
| srav | srav rd, rt, rs | rd = rt >> rs | `srav $t0, $t1, $t2` | 32位变量算术右移(符号扩展) |

#### 数据传输指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| ld | ld rt, offset(rs) | rt = Memory[rs+offset] | `ld $t0, 0($sp)` | 加载64位字 |
| lw | lw rt, offset(rs) | rt = Memory[rs+offset] | `lw $t0, 0($sp)` | 加载32位字(符号扩展) |
| lwu | lwu rt, offset(rs) | rt = Memory[rs+offset] | `lwu $t0, 0($sp)` | 加载32位字(零扩展) |
| lh | lh rt, offset(rs) | rt = Memory[rs+offset] | `lh $t0, 0($sp)` | 加载16位半字(有符号) |
| lhu | lhu rt, offset(rs) | rt = Memory[rs+offset] | `lhu $t0, 0($sp)` | 加载16位半字(无符号) |
| lb | lb rt, offset(rs) | rt = Memory[rs+offset] | `lb $t0, 0($sp)` | 加载8位字节(有符号) |
| lbu | lbu rt, offset(rs) | rt = Memory[rs+offset] | `lbu $t0, 0($sp)` | 加载8位字节(无符号) |
| sd | sd rt, offset(rs) | Memory[rs+offset] = rt | `sd $t0, 0($sp)` | 存储64位字 |
| sw | sw rt, offset(rs) | Memory[rs+offset] = rt | `sw $t0, 0($sp)` | 存储32位字 |
| sh | sh rt, offset(rs) | Memory[rs+offset] = rt | `sh $t0, 0($sp)` | 存储16位半字 |
| sb | sb rt, offset(rs) | Memory[rs+offset] = rt | `sb $t0, 0($sp)` | 存储8位字节 |

#### 立即数加载指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| lui | lui rt, imm | rt = imm << 16 | `lui $t0, 0x1234` | 加载立即数到高16位 |
| li | li rt, imm | rt = imm | `li $t0, 100` | 加载立即数(伪指令) |
| la | la rt, label | rt = &label | `la $t0, string` | 加载地址(伪指令) |
| dla | dla rt, label | rt = &label | `dla $t0, string` | 加载64位地址(伪指令) |
| dli | dli rt, imm | rt = imm | `dli $t0, 0x123456789ABCDEF0` | 加载64位立即数(伪指令) |

#### 比较指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| slt | slt rd, rs, rt | rd = (rs < rt) ? 1 : 0 | `slt $t0, $t1, $t2` | 64位有符号小于设置 |
| sltu | sltu rd, rs, rt | rd = (rs < rt) ? 1 : 0 | `sltu $t0, $t1, $t2` | 64位无符号小于设置 |
| slti | slti rt, rs, imm | rt = (rs < imm) ? 1 : 0 | `slti $t0, $t1, 100` | 立即数64位有符号小于设置 |
| sltiu | sltiu rt, rs, imm | rt = (rs < imm) ? 1 : 0 | `sltiu $t0, $t1, 100` | 立即数64位无符号小于设置 |

#### 分支跳转指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| beq | beq rs, rt, label | if (rs == rt) PC = label | `beq $t0, $t1, loop` | 相等则分支 |
| bne | bne rs, rt, label | if (rs != rt) PC = label | `bne $t0, $t1, end` | 不相等则分支 |
| bgtz | bgtz rs, label | if (rs > 0) PC = label | `bgtz $t0, positive` | 大于0则分支 |
| blez | blez rs, label | if (rs <= 0) PC = label | `blez $t0, nonpos` | 小于等于0则分支 |
| bltz | bltz rs, label | if (rs < 0) PC = label | `bltz $t0, negative` | 小于0则分支 |
| bgez | bgez rs, label | if (rs >= 0) PC = label | `bgez $t0, nonneg` | 大于等于0则分支 |
| j | j target | PC = target | `j main` | 无条件跳转 |
| jal | jal target | $ra = PC+8; PC = target | `jal function` | 跳转并链接；返回地址跳过延迟槽 |
| jr | jr rs | PC = rs | `jr $ra` | 寄存器跳转 |
| jalr | jalr rd, rs | rd = PC+8; PC = rs | `jalr $ra, $t0` | 寄存器跳转并链接；返回地址跳过延迟槽 |

#### 特殊指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| nop | nop | 空操作 | `nop` | 无操作(sll $0,$0,0) |
| move | move rd, rs | rd = rs | `move $t0, $t1` | 数据移动(伪指令) |
| mfhi | mfhi rd | rd = HI | `mfhi $t0` | 从HI寄存器移动 |
| mflo | mflo rd | rd = LO | `mflo $t0` | 从LO寄存器移动 |
| mthi | mthi rs | HI = rs | `mthi $t0` | 移动到HI寄存器 |
| mtlo | mtlo rs | LO = rs | `mtlo $t0` | 移动到LO寄存器 |
| syscall | syscall | 系统调用 | `syscall` | 触发系统调用 |
| break | break | 断点异常 | `break` | 触发断点异常 |

### 寻址模式详解

#### 立即数寻址

```asm
dli $t0, 0x123456789ABCDEF0  # 将64位立即数加载到$t0
daddiu $t1, $t0, 5           # $t1 = $t0 + 5 (64位)
addiu $t2, $t0, 5            # $t2 = $t0 + 5 (32位结果符号扩展)
```

#### 寄存器寻址

```asm
move $t0, $t1               # 将$t1的值复制到$t0
daddu $t0, $t1, $t2         # $t0 = $t1 + $t2 (64位)
addu $t0, $t1, $t2          # $t0 = $t1 + $t2 (32位结果符号扩展)
```

#### 基址加偏移寻址

```asm
ld $t0, 0($sp)              # 从$sp+0地址加载64位数据到$t0
ld $t0, 8($sp)              # 从$sp+8地址加载64位数据到$t0
sd $t0, 16($sp)             # 将$t0的64位数据存储到$sp+16地址
lw $t1, 4($sp)              # 从$sp+4地址加载32位数据(符号扩展)
lwu $t2, 4($sp)             # 从$sp+4地址加载32位数据(零扩展)
```

#### PC相对寻址(分支指令)

```asm
beq $t0, $t1, label         # 如果$t0==$t1则跳转到label
bne $t0, $zero, loop        # 如果$t0!=0则跳转到loop
```

#### 绝对寻址(跳转指令)

```asm
j main                      # 无条件跳转到main标签
jal function                # 跳转到function并保存返回地址
```

### 数据类型支持

MIPS64支持多种数据类型的操作：

#### 数据类型表

| 数据类型 | 大小 | 后缀 | 有符号后缀 | 描述 |
|----------|------|------|------------|------|
| 字节 (Byte) | 8位 | b | b/bu | 有符号/无符号字节 |
| 半字 (Halfword) | 16位 | h | h/hu | 有符号/无符号半字 |
| 字 (Word) | 32位 | w | w/wu | 32位数据 |
| 双字 (Doubleword) | 64位 | d | 无 | 64位数据 |

#### 加载指令示例

```asm
lb  $t0, 0($sp)             # 加载有符号字节，符号扩展到64位
lbu $t0, 0($sp)             # 加载无符号字节，高56位清零
lh  $t0, 0($sp)             # 加载有符号半字，符号扩展到64位
lhu $t0, 0($sp)             # 加载无符号半字，高48位清零
lw  $t0, 0($sp)             # 加载32位字，符号扩展到64位
lwu $t0, 0($sp)             # 加载32位字，高32位清零
ld  $t0, 0($sp)             # 加载64位双字
```

#### 存储指令示例

```asm
sb  $t0, 0($sp)             # 存储$t0的低8位
sh  $t0, 0($sp)             # 存储$t0的低16位
sw  $t0, 0($sp)             # 存储$t0的低32位
sd  $t0, 0($sp)             # 存储$t0的64位
```

#### 数据类型范围

| 类型 | 范围 | 用途 |
|------|------|------|
| 无符号字节 | 0 ~ 255 | 字符、小整数 |
| 有符号字节 | -128 ~ 127 | 有符号小整数 |
| 无符号半字 | 0 ~ 65535 | 较大整数、Unicode |
| 有符号半字 | -32768 ~ 32767 | 有符号整数 |
| 无符号字 | 0 ~ 4294967295 | 32位整数、地址(o32) |
| 有符号字 | -2147483648 ~ 2147483647 | 32位有符号整数 |
| 无符号双字 | 0 ~ 18446744073709551615 | 64位整数、地址 |
| 有符号双字 | -9223372036854775808 ~ 9223372036854775807 | 64位有符号整数 |

### 常用编程模式

!!! note "延迟槽提示"
    为了突出控制流，下面部分示例按“易读伪汇编”书写。若在 `.set noreorder`、shellcode 或手写 gadget 中使用，请为每条分支/跳转后的延迟槽显式填入 `nop` 或一条确定安全的指令。

#### 循环结构

```asm
# for循环示例: for(long i=0; i<10; i++)
dli $t0, 0                  # i = 0 (64位)
dli $t1, 10                 # 循环上限
loop:
    slt $t2, $t0, $t1       # 检查 i < 10
    beq $t2, $zero, loop_end # 如果 i >= 10 跳出循环
    nop
    # 循环体代码
    daddiu $t0, $t0, 1      # i++ (64位)
    j loop                  # 跳回循环开始
    nop
loop_end:

# while循环示例: while(condition)
while_loop:
    # 检查条件的代码
    beq $t0, $zero, while_end   # 条件为假则退出
    nop
    # 循环体代码
    j while_loop                # 继续循环
    nop
while_end:
```

#### 条件判断

```asm
# if-else 结构
bne $t0, $t1, else_branch   # 如果 $t0 != $t1 跳到 else
nop
    # if 分支代码
    dli $t2, 1
    j endif
    nop
else_branch:
    # else 分支代码
    dli $t2, 0
endif:

# switch-case 结构
dli $t1, 1
beq $t0, $t1, case1
nop
dli $t1, 2
beq $t0, $t1, case2
nop
dli $t1, 3
beq $t0, $t1, case3
nop
j default_case
nop

case1:
    # case 1 代码
    j switch_end
    nop
case2:
    # case 2 代码
    j switch_end
    nop
case3:
    # case 3 代码
    j switch_end
    nop
default_case:
    # 默认情况代码
switch_end:
```

#### 函数调用模板

```asm
# 标准函数模板 (n64 ABI)
function_name:
    daddiu $sp, $sp, -64    # 分配栈空间(64位对齐)
    sd $ra, 56($sp)         # 保存返回地址
    sd $fp, 48($sp)         # 保存帧指针
    sd $s0, 40($sp)         # 保存需要的寄存器
    sd $s1, 32($sp)
    sd $s2, 24($sp)
    sd $s3, 16($sp)
    move $fp, $sp           # 设置新的帧指针

    # 函数体
    # 参数在 $a0-$a7 中
    # 局部变量使用栈空间

    dli $v0, return_val     # 设置返回值(64位)
    ld $s3, 16($sp)         # 恢复寄存器
    ld $s2, 24($sp)
    ld $s1, 32($sp)
    ld $s0, 40($sp)
    ld $fp, 48($sp)         # 恢复帧指针
    ld $ra, 56($sp)         # 恢复返回地址
    daddiu $sp, $sp, 64     # 释放栈空间
    jr $ra                  # 返回
    nop                     # 延迟槽

# 调用函数 (n64 ABI)
    dli $a0, arg1           # 第一个参数(64位)
    dli $a1, arg2           # 第二个参数
    dli $a2, arg3           # 第三个参数
    dli $a3, arg4           # 第四个参数
    dli $a4, arg5           # 第五个参数
    dli $a5, arg6           # 第六个参数
    dli $a6, arg7           # 第七个参数
    dli $a7, arg8           # 第八个参数
    jal function_name       # 调用函数
    nop                     # 延迟槽
    # 返回值在 $v0 中
```

#### 数组操作

```asm
# 64位数组遍历示例
dla $t0, array              # 数组基地址(64位)
dli $t1, 0                  # 索引 i = 0
dli $t2, array_size         # 数组大小

array_loop:
    slt $t3, $t1, $t2       # i < size ?
    beq $t3, $zero, array_end # i >= size 则结束
    nop

    dsll $t3, $t1, 3        # t3 = i * 8 (假设long数组)
    daddu $t3, $t0, $t3     # t3 = &array[i]
    ld $t4, 0($t3)          # 加载 array[i] (64位)
    # 处理 $t4 中的数据

    daddiu $t1, $t1, 1      # i++
    j array_loop
    nop
array_end:

# 字符串长度计算(64位指针)
dla $t0, string             # 字符串指针(64位)
dli $t1, 0                  # 长度计数器

strlen_loop:
    daddu $t2, $t0, $t1     # 计算当前字符地址(64位)
    lbu $t3, 0($t2)         # 加载当前字符
    beq $t3, $zero, strlen_end # 检查是否为'\0'
    nop
    daddiu $t1, $t1, 1      # 长度++
    j strlen_loop
    nop
strlen_end:
    # $t1 包含字符串长度
```

#### 位操作技巧

```asm
# 检查第n位是否为1 (64位版本)
dli $t1, 1
dsllv $t1, $t1, $t0         # $t1 = 1 << n (64位左移)
and $t2, $t3, $t1           # 测试 $t3 的第n位
bne $t2, $zero, bit_is_set
nop

# 设置第n位为1
dli $t1, 1
dsllv $t1, $t1, $t0         # $t1 = 1 << n
or $t2, $t2, $t1            # $t2 |= (1 << n)

# 清除第n位
dli $t1, 1
dsllv $t1, $t1, $t0         # $t1 = 1 << n
nor $t1, $t1, $zero         # $t1 = ~(1 << n)
and $t2, $t2, $t1           # $t2 &= ~(1 << n)

# 切换第n位
dli $t1, 1
dsllv $t1, $t1, $t0         # $t1 = 1 << n
xor $t2, $t2, $t1           # $t2 ^= (1 << n)

# 计算2的幂次 (64位)
dli $t1, 1
dsllv $t1, $t1, $t0         # $t1 = 2^$t0

# 除以2的幂次(无符号, 64位)
dsrlv $t1, $t2, $t0         # $t1 = $t2 / (2^$t0)

# 除以2的幂次(有符号, 64位)
dsrav $t1, $t2, $t0         # $t1 = $t2 / (2^$t0) (保持符号)

# 64位位计数
# 计算$t0中1的个数
move $t1, $t0               # 保存原值
dli $t2, 0                  # 计数器
popcount_loop:
    beq $t1, $zero, popcount_end
    nop
    andi $t3, $t1, 1        # 检查最低位
    daddu $t2, $t2, $t3     # 累加
    dsrl $t1, $t1, 1        # 右移一位
    j popcount_loop
    nop
popcount_end:
    # $t2 包含1的个数
```

#### 内存对齐和优化

```asm
# 8字节对齐检查(64位)
andi $t1, $t0, 7            # 检查低3位
bne $t1, $zero, not_aligned
nop

# 向上对齐到8字节边界
daddiu $t0, $t0, 7          # $t0 += 7
dli $t9, -8                 # 0xfffffffffffffff8
and $t0, $t0, $t9           # $t0 &= ~7

# 向下对齐到8字节边界
dli $t9, -8
and $t0, $t0, $t9           # $t0 &= ~7

# 快速清零内存块(64位)
move $t1, $zero             # 清零值
move $t2, $t0               # 保存起始地址
daddu $t3, $t0, $t4         # 计算结束地址
clear_loop:
    sltu $t5, $t2, $t3      # $t2 < $t3 ?
    beq $t5, $zero, clear_end
    nop
    sd $t1, 0($t2)          # 存储0 (64位)
    daddiu $t2, $t2, 8      # 递增地址
    j clear_loop
    nop
clear_end:
```

### 延迟槽 (Delay Slot)

MIPS64架构继承了MIPS的分支延迟槽特性：

```asm
# 分支指令后的一条指令总是会被执行
beq $t0, $t1, target
daddu $t2, $t3, $t4         # 延迟槽：无论分支是否发生都会执行

# 跳转指令也有延迟槽
jal function
move $a0, $t0               # 延迟槽：设置参数

# 如果延迟槽没有有用的指令，使用nop
j loop
nop                         # 延迟槽：空操作

# 利用延迟槽优化
# 不好的写法：
    beq $t0, $t1, skip
    nop                     # 浪费的延迟槽
    addu $t2, $t3, $t4      # 需要跳过的指令
skip:

# 好的写法：
    bne $t0, $t1, continue  # 反转条件
    addu $t2, $t3, $t4      # 延迟槽：有用的指令
    # 原本要跳过的代码块
continue:
```

### 内存模型与字节序特性

#### 字节序示例

```text
值: 0x123456789ABCDEF0

大端序 (BE) 内存布局:
地址:   +0  +1  +2  +3  +4  +5  +6  +7
数据:   12  34  56  78  9A  BC  DE  F0

小端序 (LE) 内存布局:
地址:   +0  +1  +2  +3  +4  +5  +6  +7
数据:   F0  DE  BC  9A  78  56  34  12
```

#### 内存布局

```text
高地址  0xFFFFFFFFFFFFFFFF
┌─────────────────┐
│     内核空间     │  0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF
├─────────────────┤
│     用户栈      │  向下增长
├─────────────────┤
│       堆       │  向上增长
├─────────────────┤
│   .bss 段      │  未初始化数据
├─────────────────┤
│   .data 段     │  已初始化数据
├─────────────────┤
│   .text 段     │  程序代码
└─────────────────┘  0x0000000000000000
低地址
```

## 实际编程示例

### 简单的Hello World程序

```asm
# MIPS64 Hello World (n64 ABI)
.section .data
msg:    .ascii "Hello, MIPS64 World!\n"
msg_len = . - msg

.section .text
.globl _start

_start:
    # write(1, msg, msg_len)
    li      $v0, 5001        # write 系统调用号 (n64)
    li      $a0, 1           # fd = 1 (stdout)
    dla     $a1, msg         # buffer 地址 (64位)
    li      $a2, msg_len     # count
    syscall                  # 执行系统调用

    # 检查返回值
    bnez    $a3, error       # $a3 非零表示 syscall 出错
    nop

    # exit(0)
    li      $v0, 5058        # exit 系统调用号 (n64)
    li      $a0, 0           # exit_code = 0
    syscall

error:
    # exit(1)
    li      $v0, 5058        # exit 系统调用号 (n64)
    li      $a0, 1           # exit_code = 1
    syscall
```

### 函数调用汇编示例

```c
// C 代码
long add_numbers(long a, long b, long c, long d, long e, long f, long g, long h, long i, long j) {
    return a + b + c + d + e + f + g + h + i + j;
}

int main() {
    long result = add_numbers(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    return (int)result;
}
```

对应的汇编代码：

```asm
# MIPS64 函数调用示例 (n64 ABI)
.section .text
.globl add_numbers
.globl main

add_numbers:
    # 参数 a-h 在 $a0-$a7 中
    # 参数 i, j 在栈中 0($sp), 8($sp)

    ld      $t0, 0($sp)      # 加载第9个参数 i
    ld      $t1, 8($sp)      # 加载第10个参数 j

    daddu   $v0, $a0, $a1    # a + b
    daddu   $v0, $v0, $a2    # + c
    daddu   $v0, $v0, $a3    # + d
    daddu   $v0, $v0, $a4    # + e
    daddu   $v0, $v0, $a5    # + f
    daddu   $v0, $v0, $a6    # + g
    daddu   $v0, $v0, $a7    # + h
    daddu   $v0, $v0, $t0    # + i
    daddu   $v0, $v0, $t1    # + j

    jr      $ra              # 返回
    nop

main:
    daddiu  $sp, $sp, -32    # 分配栈空间
    sd      $ra, 24($sp)     # 保存返回地址

    dli     $a0, 1           # 第1个参数
    dli     $a1, 2           # 第2个参数
    dli     $a2, 3           # 第3个参数
    dli     $a3, 4           # 第4个参数
    dli     $a4, 5           # 第5个参数
    dli     $a5, 6           # 第6个参数
    dli     $a6, 7           # 第7个参数
    dli     $a7, 8           # 第8个参数
    dli     $t0, 9           # 第9个参数
    dli     $t1, 10          # 第10个参数
    sd      $t0, 0($sp)      # 第9个参数入栈
    sd      $t1, 8($sp)      # 第10个参数入栈

    jal     add_numbers      # 调用函数
    nop

    # 转换64位结果为32位(如果需要)
    sll     $a0, $v0, 0      # 截断为32位并符号扩展
    ld      $ra, 24($sp)     # 恢复返回地址
    daddiu  $sp, $sp, 32     # 恢复栈指针
    jr      $ra              # 返回
    nop
```

### 字符串处理示例

```asm
# 字符串长度计算函数
.section .text
.globl strlen64

strlen64:
    # 参数: $a0 = 字符串指针 (64位)
    # 返回: $v0 = 字符串长度 (64位)

    move    $v0, $zero       # 长度计数器 = 0
    move    $t0, $a0         # 当前指针

strlen_loop:
    lbu     $t1, 0($t0)      # 加载当前字符
    beq     $t1, $zero, strlen_done # 如果是'\0'则结束
    nop
    daddiu  $v0, $v0, 1      # 长度++
    daddiu  $t0, $t0, 1      # 指针++
    j       strlen_loop
    nop

strlen_done:
    jr      $ra
    nop

# 字符串复制函数
.globl strcpy64

strcpy64:
    # 参数: $a0 = dest (64位指针), $a1 = src (64位指针)
    # 返回: $v0 = dest

    move    $v0, $a0         # 保存dest作为返回值
    move    $t0, $a0         # dest指针
    move    $t1, $a1         # src指针

strcpy_loop:
    lbu     $t2, 0($t1)      # 加载src字符
    sb      $t2, 0($t0)      # 存储到dest
    beq     $t2, $zero, strcpy_done # 如果是'\0'则结束
    nop
    daddiu  $t0, $t0, 1      # dest++
    daddiu  $t1, $t1, 1      # src++
    j       strcpy_loop
    nop

strcpy_done:
    jr      $ra
    nop
```

### 数组操作示例

```asm
# 64位整数数组求和
.section .text
.globl array_sum64

array_sum64:
    # 参数: $a0 = 数组指针 (64位), $a1 = 数组长度 (64位)
    # 返回: $v0 = 数组元素之和 (64位)

    move    $v0, $zero       # 累加器 = 0
    move    $t0, $zero       # 索引 = 0
    move    $t1, $a0         # 数组指针
    move    $t2, $a1         # 数组长度

sum_loop:
    slt     $t3, $t0, $t2    # 检查 index < length
    beq     $t3, $zero, sum_done
    nop

    dsll    $t4, $t0, 3      # index * 8 (每个long占8字节)
    daddu   $t5, $t1, $t4    # 计算元素地址
    ld      $t6, 0($t5)      # 加载数组元素
    daddu   $v0, $v0, $t6    # 累加

    daddiu  $t0, $t0, 1      # index++
    j       sum_loop
    nop

sum_done:
    jr      $ra
    nop

# 查找数组中的最大值
.globl array_max64

array_max64:
    # 参数: $a0 = 数组指针 (64位), $a1 = 数组长度 (64位)
    # 返回: $v0 = 最大值 (64位)

    beq     $a1, $zero, max_empty # 空数组处理
    nop

    ld      $v0, 0($a0)      # 第一个元素作为初始最大值
    dli     $t0, 1           # 从第二个元素开始
    move    $t1, $a0         # 数组指针
    move    $t2, $a1         # 数组长度

max_loop:
    slt     $t3, $t0, $t2    # 检查 index < length
    beq     $t3, $zero, max_done
    nop

    dsll    $t4, $t0, 3      # index * 8
    daddu   $t5, $t1, $t4    # 计算元素地址
    ld      $t6, 0($t5)      # 加载数组元素

    slt     $t7, $v0, $t6    # max < current ?
    beq     $t7, $zero, max_continue
    nop
    move    $v0, $t6         # 更新最大值

max_continue:
    daddiu  $t0, $t0, 1      # index++
    j       max_loop
    nop

max_done:
    jr      $ra
    nop

max_empty:
    dli     $v0, 0           # 空数组返回0
    jr      $ra
    nop
```

### 递归函数示例

```asm
# 计算阶乘的递归函数
.section .text
.globl factorial64

factorial64:
    # 参数: $a0 = n (64位)
    # 返回: $v0 = n! (64位)

    daddiu  $sp, $sp, -32    # 分配栈空间
    sd      $ra, 24($sp)     # 保存返回地址
    sd      $a0, 16($sp)     # 保存参数n

    # 基础情况: n <= 1
    dli     $t0, 1
    slt     $t1, $t0, $a0    # 1 < n ?
    bne     $t1, $zero, factorial_recursive
    nop

    # n <= 1, 返回1
    dli     $v0, 1
    j       factorial_return
    nop

factorial_recursive:
    # 递归情况: n * factorial(n-1)
    daddiu  $a0, $a0, -1     # n-1
    jal     factorial64      # 递归调用
    nop

    ld      $t0, 16($sp)     # 恢复原来的n
    dmult   $t0, $v0         # n * factorial(n-1)
    mflo    $v0              # 获取乘法结果

factorial_return:
    ld      $ra, 24($sp)     # 恢复返回地址
    daddiu  $sp, $sp, 32     # 释放栈空间
    jr      $ra
    nop
```

### 完整的程序示例

```asm
# 完整的MIPS64程序：计算数组平均值
.section .data
    .align 3                 # 8字节对齐
numbers:
    .quad 10, 20, 30, 40, 50, 60, 70, 80, 90, 100  # 10个64位数
array_size:
    .quad 10
result_msg:
    .ascii "Average: "
result_msg_len = . - result_msg

.section .text
.globl _start

_start:
    # 计算数组平均值
    dla     $a0, numbers     # 数组地址
    ld      $a1, array_size  # 数组大小
    jal     calculate_average
    nop

    # 这里可以添加输出结果的代码
    # 为简化起见，直接退出

    # exit(0)
    li      $v0, 5058        # exit 系统调用号 (n64)
    move    $a0, $zero       # exit_code = 0
    syscall

calculate_average:
    # 参数: $a0 = 数组指针, $a1 = 数组大小
    # 返回: $v0 = 平均值

    daddiu  $sp, $sp, -32
    sd      $ra, 24($sp)
    sd      $s0, 16($sp)     # 保存数组指针
    sd      $s1, 8($sp)      # 保存数组大小

    move    $s0, $a0
    move    $s1, $a1

    # 计算数组和
    jal     array_sum64
    nop

    # 计算平均值: sum / count
    move    $t0, $v0         # sum
    move    $t1, $s1         # count
    ddiv    $t0, $t1         # sum / count
    mflo    $v0              # 获取除法结果

    ld      $s1, 8($sp)
    ld      $s0, 16($sp)
    ld      $ra, 24($sp)
    daddiu  $sp, $sp, 32
    jr      $ra
    nop

# array_sum64 函数 (前面已定义)
array_sum64:
    move    $v0, $zero       # 累加器 = 0
    move    $t0, $zero       # 索引 = 0
    move    $t1, $a0         # 数组指针
    move    $t2, $a1         # 数组长度

sum_loop:
    slt     $t3, $t0, $t2    # 检查 index < length
    beq     $t3, $zero, sum_done
    nop

    dsll    $t4, $t0, 3      # index * 8
    daddu   $t5, $t1, $t4    # 计算元素地址
    ld      $t6, 0($t5)      # 加载数组元素
    daddu   $v0, $v0, $t6    # 累加

    daddiu  $t0, $t0, 1      # index++
    j       sum_loop
    nop

sum_done:
    jr      $ra
    nop
```

这些示例展示了MIPS64汇编编程的核心概念，包括：

1. **系统调用**：使用n64 ABI进行系统调用
2. **函数调用**：正确的栈管理和参数传递
3. **64位运算**：使用64位指令处理长整型数据
4. **字符串处理**：基本的字符串操作函数
5. **数组操作**：遍历和计算数组元素
6. **递归**：栈管理和递归调用
7. **完整程序**：数据段、文本段和程序结构
