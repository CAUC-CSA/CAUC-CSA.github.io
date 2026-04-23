# ARMv7 / AArch32 架构基础知识

!!! tip "Pwn 速查"
    - 函数参数：`r0-r3`，返回值：`r0`（64 位返回值用 `r0:r1`）。
    - Linux EABI 系统调用：调用号放 `r7`，参数放 `r0-r5`，指令为 `svc #0`。
    - 返回地址通常先在 `lr` 中；非叶子函数或需要长期保存时会压到栈上。

!!! warning "易错点"
    AArch32 可能运行在 ARM 或 Thumb/Thumb-2 状态：ARM 指令固定 4 字节，Thumb 指令可能是 2/4 字节混合；做 ROP/JOP 时要确认地址最低位和指令状态。

## ARMv7 寄存器详解

### 通用寄存器 (r0-r15)

| 寄存器 | 用途 | 备注 |
|---|---|---|
| `r0-r3` | 参数寄存器 / 返回值寄存器 | 调用者保存 |
| `r4-r11` | 保存寄存器 | 被调用函数需保存 |
| `r12` / `IP` | 临时寄存器 | Intra-Procedure-call scratch |
| `r13` / `SP` | 栈指针 | 指向当前栈顶 |
| `r14` / `LR` | 链接寄存器 | 保存 `bl` 后的返回地址 |
| `r15` / `PC` | 程序计数器 | 控制执行流 |

### 寄存器别名和用途

| 寄存器 | 别名 | 主要用途 | 调用约定 |
|---|---|---|---|
| `r0` | `a1` | 第 1 个参数 / 返回值 | 调用者保存 |
| `r1` | `a2` | 第 2 个参数 | 调用者保存 |
| `r2` | `a3` | 第 3 个参数 | 调用者保存 |
| `r3` | `a4` | 第 4 个参数 | 调用者保存 |
| `r4` | `v1` | 局部变量 | 被调用者保存 |
| `r5` | `v2` | 局部变量 | 被调用者保存 |
| `r6` | `v3` | 局部变量 | 被调用者保存 |
| `r7` | `v4` | 局部变量；Linux EABI 中也放系统调用号 | 被调用者保存 |
| `r8` | `v5` | 局部变量 | 被调用者保存 |
| `r9` | `v6` | 平台寄存器 / 局部变量 | 被调用者保存，跨平台代码慎用 |
| `r10` | `v7` | 局部变量 | 被调用者保存 |
| `r11` | `v8` / `FP` | 帧指针 | 被调用者保存 |
| `r12` | `IP` | 临时 / 过程调用 | 调用者保存 |
| `r13` | `SP` | 栈指针 | 特殊寄存器 |
| `r14` | `LR` | 链接寄存器 | 特殊寄存器 |
| `r15` | `PC` | 程序计数器 | 特殊寄存器 |

### 特殊寄存器

| 寄存器 | 作用 |
|---|---|
| `CPSR` | 当前程序状态寄存器，保存条件标志和处理器状态 |
| `SPSR` | 异常模式下保存的程序状态寄存器 |

| CPSR 标志位 | 含义 |
|---|---|
| `N` | Negative，结果为负 |
| `Z` | Zero，结果为零 |
| `C` | Carry，进位 / 无借位 |
| `V` | Overflow，有符号溢出 |

## Linux ARMv7 系统调用表

### 常用系统调用号

??? info "常用系统调用号（展开查看）"
    ```c
    #define __NR_restart_syscall      0
    #define __NR_exit                 1
    #define __NR_fork                 2
    #define __NR_read                 3
    #define __NR_write                4
    #define __NR_open                 5
    #define __NR_close                6
    #define __NR_creat                8
    #define __NR_link                 9
    #define __NR_unlink              10
    #define __NR_execve              11
    #define __NR_chdir               12
    #define __NR_time                13
    #define __NR_mknod               14
    #define __NR_chmod               15
    #define __NR_lchown              16
    #define __NR_lseek               19
    #define __NR_getpid              20
    #define __NR_mount               21
    #define __NR_umount              22
    #define __NR_setuid              23
    #define __NR_getuid              24
    #define __NR_kill                37
    #define __NR_mkdir               39
    #define __NR_rmdir               40
    #define __NR_dup                 41
    #define __NR_pipe                42
    #define __NR_brk                 45
    #define __NR_ioctl               54
    #define __NR_mmap2               192
    #define __NR_munmap              91
    #define __NR_mprotect            125
    #define __NR_socket              281
    #define __NR_bind                282
    #define __NR_connect             283
    #define __NR_listen              284
    #define __NR_accept              285
    ```

### 系统调用约定

[系统调用查询](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)

| 项目 | 约定 |
|---|---|
| 系统调用号 | `r7` |
| 参数 1-6 | `r0`, `r1`, `r2`, `r3`, `r4`, `r5` |
| 返回值 | `r0` |
| 触发指令 | `svc #0` |

!!! note
    这里讨论 Linux EABI 用户态约定；老 OABI 或裸机异常处理的细节不同。

### 系统调用示例

```asm
; write(1, "Hello", 5)
mov r0, #1          ; fd = 1 (stdout)
ldr r1, =hello_str  ; buf = "Hello"
mov r2, #5          ; count = 5
mov r7, #4          ; __NR_write
svc #0              ; 系统调用

; exit(0)
mov r0, #0          ; status = 0
mov r7, #1          ; __NR_exit
svc #0
```

## 函数调用约定 (AAPCS)

### 参数传递

| 项目 | AAPCS 约定 |
|---|---|
| 前 4 个参数 | `r0`, `r1`, `r2`, `r3` |
| 更多参数 | 通过栈上传参区域传递；保持 8 字节对齐 |
| 32 位返回值 | `r0` |
| 64 位返回值 | `r0:r1` |

!!! warning
    不要简单照搬 x86 的“从右到左 push”模型；真实编译器会按 AAPCS 构造栈上传参区域。

### 栈帧结构

```text
高地址
+------------------+
| 第n个参数        |  <- 超过r0-r3的参数
| ...              |
| 第5个参数        |
+------------------+
| 返回地址 (LR)    |  <- 函数调用时保存
| 老的帧指针(r11)  |  <- 可选
| 局部变量         |
| 保存的寄存器     |  <- r4-r11需要保存
+------------------+  <- SP (当前栈指针)
低地址
```

### 函数调用流程

```asm
; 调用者 (Caller)
mov r0, #arg1       ; 设置参数1
mov r1, #arg2       ; 设置参数2
bl function         ; 调用函数
; r0 包含返回值

; 被调用者 (Callee)
function:
push {r4-r11, lr}   ; 保存需要使用的寄存器
; 函数体
mov r0, #return_val ; 设置返回值
pop {r4-r11, pc}    ; 恢复寄存器并返回
```

## 指令集合

> AArch32 的 ARM 状态指令字长为 4 字节；Thumb/Thumb-2 状态存在 2 字节和 4 字节指令混合的情况。

#### 指令格式

一般格式如下：

```asm
MNEMONIC{S}{condition} {Rd}, Operand1, Operand2
助记符{是否使用CPSR}{是否条件执行以及条件} {目的寄存器}, 操作符1, 操作符2
```

由于ARM指令的灵活性，不是全部的指令都满足这个模板，不过大部分都满足了。下面来说说模板中的含义:

```asm
MNEMONIC     - 指令的助记符如ADD
{S}          - 可选的扩展位，如果指令后加了S，则需要依据计算结果更新CPSR寄存器中的条件跳转相关的FLAG
{condition}  - 如果机器码要被条件执行，那它需要满足的条件标示
{Rd}         - 存储结果的目的寄存器
Operand1     - 第一个操作数，寄存器或者是一个立即数
Operand2     - 第二个(可变的)操作数，可以是一个立即数或者寄存器或者有偏移量的寄存器
```

#### 条件执行

ARM指令可以根据CPSR中的标志位进行条件执行：

| 条件码 | 助记符 | 含义 | CPSR标志位条件 |
|--------|--------|------|----------------|
| 0000 | EQ | 相等 | Z = 1 |
| 0001 | NE | 不相等 | Z = 0 |
| 0010 | CS/HS | 进位/无符号大于等于 | C = 1 |
| 0011 | CC/LO | 无进位/无符号小于 | C = 0 |
| 0100 | MI | 负数 | N = 1 |
| 0101 | PL | 正数或零 | N = 0 |
| 0110 | VS | 溢出 | V = 1 |
| 0111 | VC | 无溢出 | V = 0 |
| 1000 | HI | 无符号大于 | C=1且Z=0 |
| 1001 | LS | 无符号小于等于 | C=0或Z=1 |
| 1010 | GE | 有符号大于等于 | N = V |
| 1011 | LT | 有符号小于 | N ≠ V |
| 1100 | GT | 有符号大于 | Z=0且N=V |
| 1101 | LE | 有符号小于等于 | Z=1或N≠V |
| 1110 | AL | 总是执行 | 任何 |
| 1111 | NV/保留 | ARMv7 中多为保留或用于无条件扩展编码 | 不建议当作普通条件码使用 |

示例：

```asm
CMP r0, #5      @ 比较r0和5
ADDGT r1, r1, #1    @ 如果r0 > 5，则r1 = r1 + 1
MOVLE r2, #0        @ 如果r0 <= 5，则r2 = 0
```

#### 操作数类型

第二操作数是一个可变操作数，可以以各种形式使用：

```asm
#123                    @ 立即数
Rx                      @ 寄存器比如R1
Rx, ASR n               @ 对寄存器中的值进行算术右移n位后的值
Rx, LSL n               @ 对寄存器中的值进行逻辑左移n位后的值
Rx, LSR n               @ 对寄存器中的值进行逻辑右移n位后的值
Rx, ROR n               @ 对寄存器中的值进行循环右移n位后的值
Rx, RRX                 @ 对寄存器中的值进行带扩展的循环右移1位后的值
```

基本示例：

```asm
ADD   R0, R1, R2         @ 将第一操作数R1的内容与第二操作数R2的内容相加，将结果存储到R0中
ADD   R0, R1, #2         @ 将第一操作数R1的内容与第二操作数一个立即数相加，将结果存到R0中
MOVLE R0, #5             @ 当满足条件LE（上一次比较结果为有符号小于等于）时，将立即数5移动到R0中
MOV   R0, R1, LSL #1     @ 将第一操作数R1寄存器中的值逻辑左移1位后存入R0
```

#### 指令分类

ARM指令可以分为以下几类：

##### 数据处理指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| MOV | 移动数据 | `MOV r0, r1` | 将r1的值复制到r0 |
| MVN | 取反码移动数据 | `MVN r0, r1` | 将r1按位取反后移动到r0 |
| ADD | 数据相加 | `ADD r0, r1, r2` | r0 = r1 + r2 |
| SUB | 数据相减 | `SUB r0, r1, r2` | r0 = r1 - r2 |
| RSB | 反向减法 | `RSB r0, r1, r2` | r0 = r2 - r1 |
| MUL | 数据相乘 | `MUL r0, r1, r2` | r0 = r1 * r2 |
| AND | 比特位与 | `AND r0, r1, r2` | r0 = r1 & r2 |
| ORR | 比特位或 | `ORR r0, r1, r2` | r0 = r1 \| r2 |
| EOR | 比特位异或 | `EOR r0, r1, r2` | r0 = r1 ^ r2 |
| BIC | 位清除 | `BIC r0, r1, r2` | r0 = r1 & (~r2) |
| CMP | 比较操作 | `CMP r0, r1` | 比较r0和r1，设置标志位 |
| CMN | 负数比较 | `CMN r0, r1` | 比较r0和-r1，设置标志位 |
| TST | 测试 | `TST r0, r1` | 执行r0 & r1，仅设置标志位 |
| TEQ | 测试相等 | `TEQ r0, r1` | 执行r0 ^ r1，仅设置标志位 |

##### 移位操作指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LSL | 逻辑左移 | `MOV r0, r1, LSL #2` | 将r1左移2位后存入r0 |
| LSR | 逻辑右移 | `MOV r0, r1, LSR #2` | 将r1逻辑右移2位后存入r0 |
| ASR | 算术右移 | `MOV r0, r1, ASR #2` | 将r1算术右移2位后存入r0 |
| ROR | 循环右移 | `MOV r0, r1, ROR #2` | 将r1循环右移2位后存入r0 |
| RRX | 扩展右移 | `MOV r0, r1, RRX` | 将r1通过进位位扩展右移1位 |

##### 分支和跳转指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| B | 分支跳转 | `B label` | 无条件跳转到标签 |
| BL | 链接分支跳转 | `BL function` | 跳转并保存返回地址到LR |
| BX | 分支跳转切换 | `BX r0` | 跳转到r0地址，可能切换指令集 |
| BLX | 链接分支跳转切换 | `BLX r0` | 跳转到r0地址并保存返回地址 |

##### 加载/存储指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LDR | 加载字 | `LDR r0, [r1]` | 从r1地址加载32位数据到r0 |
| LDRB | 加载字节 | `LDRB r0, [r1]` | 从r1地址加载8位数据到r0 |
| LDRH | 加载半字 | `LDRH r0, [r1]` | 从r1地址加载16位数据到r0 |
| LDRSB | 加载有符号字节 | `LDRSB r0, [r1]` | 加载8位有符号数据并扩展 |
| LDRSH | 加载有符号半字 | `LDRSH r0, [r1]` | 加载16位有符号数据并扩展 |
| STR | 存储字 | `STR r0, [r1]` | 将r0的32位数据存储到r1地址 |
| STRB | 存储字节 | `STRB r0, [r1]` | 将r0的低8位存储到r1地址 |
| STRH | 存储半字 | `STRH r0, [r1]` | 将r0的低16位存储到r1地址 |

##### 多寄存器加载/存储指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| LDM | 多次加载 | `LDM r0, {r1-r3}` | 从r0地址加载多个寄存器 |
| STM | 多次存储 | `STM r0, {r1-r3}` | 将多个寄存器存储到r0地址 |
| PUSH | 压栈 | `PUSH {r0-r3}` | 将寄存器压入栈 |
| POP | 出栈 | `POP {r0-r3}` | 从栈中弹出到寄存器 |

##### 特殊指令

| 指令 | 含义 | 示例 | 描述 |
|------|------|------|------|
| MRS | 状态寄存器读取 | `MRS r0, CPSR` | 将CPSR内容复制到r0 |
| MSR | 状态寄存器写入 | `MSR CPSR, r0` | 将r0内容复制到CPSR |
| SWI/SVC | 系统调用 | `SVC #0` | 触发系统调用中断 |
| NOP | 空操作 | `NOP` | 不执行任何操作 |
| WFI | 等待中断 | `WFI` | 进入低功耗模式等待中断 |

#### 重点指令详解

##### 算术运算指令

| 指令 | 计算公式 | 示例 | 备注 |
|------|----------|------|------|
| ADD Rd, Rn, Rm | Rd = Rn + Rm | `ADD r0, r1, r2` | 加法运算 |
| ADD Rd, Rn, #immed | Rd = Rn + #immed | `ADD r0, r1, #5` | 立即数加法 |
| ADC Rd, Rn, Rm | Rd = Rn + Rm + C | `ADC r0, r1, r2` | 带进位的加法运算 |
| ADC Rd, Rn, #immed | Rd = Rn + #immed + C | `ADC r0, r1, #5` | 带进位的立即数加法 |
| SUB Rd, Rn, Rm | Rd = Rn – Rm | `SUB r0, r1, r2` | 减法 |
| SUB Rd, #immed | Rd = Rd - #immed | `SUB r0, #5` | 立即数减法 |
| SUB Rd, Rn, #immed | Rd = Rn - #immed | `SUB r0, r1, #5` | 立即数减法 |
| SBC Rd, Rn, #immed | Rd = Rn - #immed - (1-C) | `SBC r0, r1, #5` | 带借位的减法；ARM 中 C=1 表示无借位 |
| SBC Rd, Rn, Rm | Rd = Rn - Rm - (1-C) | `SBC r0, r1, r2` | 带借位的减法；ARM 中 C=1 表示无借位 |
| RSB Rd, Rn, Rm | Rd = Rm - Rn | `RSB r0, r1, r2` | 反向减法 |
| MUL Rd, Rn, Rm | Rd = Rn * Rm | `MUL r0, r1, r2` | 32位乘法 |
| UMULL RdLo, RdHi, Rn, Rm | RdHi:RdLo = Rn * Rm | `UMULL r0, r1, r2, r3` | 64位无符号乘法 |
| SMULL RdLo, RdHi, Rn, Rm | RdHi:RdLo = Rn * Rm | `SMULL r0, r1, r2, r3` | 64位有符号乘法 |
| UDIV Rd, Rn, Rm | Rd = Rn / Rm | `UDIV r0, r1, r2` | 无符号除法 |
| SDIV Rd, Rn, Rm | Rd = Rn / Rm | `SDIV r0, r1, r2` | 有符号除法 |

##### 数据传输指令示例

| 指令 | 目的 | 源 | 描述 |
|------|------|----|----- |
| MOV | R0 | R1 | 将 R1 里面的数据复制到 R0 中 |
| MOV | R0 | #0x1234 | 将立即数0x1234加载到R0中 |
| MRS | R0 | CPSR | 将特殊寄存器 CPSR 里面的数据复制到 R0 中 |
| MSR | CPSR | R1 | 将 R1 里面的数据复制到特殊寄存器 CPSR 中 |
| LDR | R0 | =0x0209C004 | 将地址 0x0209C004 加载到 R0 中 |
| LDR | R0 | [R1] | 从R1指向的地址加载数据到R0 |
| LDR | R0 | [R1, #4] | 从R1+4地址加载数据到R0 |
| LDR | R0 | [R1, R2] | 从R1+R2地址加载数据到R0 |
| LDR | R0 | [R1], #4 | 从R1地址加载数据到R0，然后R1=R1+4 |
| LDR | R0 | [R1, #4]! | R1=R1+4，然后从R1地址加载数据到R0 |
| STR | R1 | [R0] | 将 R1 中的值写入到 R0 中所保存的地址中 |

##### 栈操作指令

| 指令 | 操作数 | 描述 | 等价指令 |
|------|--------|------|----------|
| PUSH | {R0-R3, R12} | 将 R0-R3 和 R12 压栈 | `STMDB SP!, {R0-R3, R12}` |
| POP | {R0-R3, R12} | 从栈中弹出到 R0-R3, R12 | `LDMIA SP!, {R0-R3, R12}` |
| PUSH | {LR} | 保存返回地址 | `STR LR, [SP, #-4]!` |
| POP | {PC} | 返回到调用者 | `LDR PC, [SP], #4` |

##### 多寄存器传输指令

`STMFD`和`LDMFD`指令详解：

| 指令 | 目的 | 源 | 描述 |
|------|------|----|----- |
| STMFD | SP! | {R0-R3, R12} | R0-R3,R12 入栈（满递减栈） |
| LDMFD | SP! | {R0-R3, R12} | 从栈中出 R0-R3,R12（满递减栈） |
| STMIA | R0! | {R1-R4} | 将R1-R4存储到R0指向的内存，递增地址 |
| LDMIA | R0! | {R1-R4} | 从R0指向的内存加载到R1-R4，递增地址 |

多寄存器传输的寻址模式：

| 后缀 | 含义 | 描述 |
|------|------|------|
| IA | Increment After | 传输后地址递增 |
| IB | Increment Before | 传输前地址递增 |
| DA | Decrement After | 传输后地址递减 |
| DB | Decrement Before | 传输前地址递减 |
| FD | Full Descending | 满递减栈 |
| FA | Full Ascending | 满递增栈 |
| ED | Empty Descending | 空递减栈 |
| EA | Empty Ascending | 空递增栈 |

[LDM，STM详解](https://blog.csdn.net/stephenbruce/article/details/51151147)

`LDMIA R0!, {R4-R11, R14}`：

LDMIA 中的 I 是 increment 的缩写，A 是 after 的缩写，LDM 表示多寄存器加载。`R0!` 中的感叹号表示写回：按地址递增顺序从 `R0` 指向的内存加载数据到 `R4-R11` 和 `R14`，完成后更新 `R0`。

`STMDB R1!, {R0,R4-R12}`：

这条指令与上面方向相反。STM 表示多寄存器存储，D 是 decrement，B 是 before：先递减 `R1`，再把 `R0,R4-R12` 的内容按规则存到新地址，并将更新后的地址写回 `R1`。

#### 寻址模式详解

ARM支持多种灵活的寻址模式：

##### 立即数寻址

```asm
MOV r0, #100        @ 将立即数100加载到r0
ADD r1, r2, #4      @ r1 = r2 + 4
```

##### 寄存器寻址

```asm
MOV r0, r1          @ 将r1的值复制到r0
ADD r0, r1, r2      @ r0 = r1 + r2
```

##### 寄存器间接寻址

```asm
LDR r0, [r1]        @ 从r1指向的地址加载数据到r0
STR r0, [r1]        @ 将r0的数据存储到r1指向的地址
```

##### 基址加偏移寻址

```asm
LDR r0, [r1, #4]    @ 从r1+4地址加载数据，r1不变
LDR r0, [r1, r2]    @ 从r1+r2地址加载数据，r1不变
LDR r0, [r1, r2, LSL #2]  @ 从r1+(r2<<2)地址加载数据
```

##### 前索引寻址（预递增/递减）

```asm
LDR r0, [r1, #4]!   @ r1 = r1 + 4, 然后从r1地址加载数据
LDR r0, [r1, r2]!   @ r1 = r1 + r2, 然后从r1地址加载数据
```

##### 后索引寻址（后递增/递减）

```asm
LDR r0, [r1], #4    @ 从r1地址加载数据，然后r1 = r1 + 4
LDR r0, [r1], r2    @ 从r1地址加载数据，然后r1 = r1 + r2
```

重要说明：

- `ldr r3, [r1, r2, lsl #2]` - 不会改变寄存器r1的值
- `ldr r3, [r1, r2, lsl #2]!` - 感叹号代表事先更新，会改变r1的值为r1+(r2<<2)
- `ldr r2, [r1], r2, lsl #2` - 事后更新，先加载数据，然后改变r1的值

#### 数据类型支持

ARM支持多种数据类型的操作：

##### 数据类型表

| 数据类型 | 大小 | 后缀 | 有符号后缀 | 描述 |
|----------|------|------|------------|------|
| 字节 (Byte) | 8位 | B | SB | 无符号/有符号字节 |
| 半字 (Halfword) | 16位 | H | SH | 无符号/有符号半字 |
| 字 (Word) | 32位 | 无 | 无 | 32位数据 |
| 双字 (Doubleword) | 64位 | D | 无 | 64位数据 |

##### 加载指令示例

```asm
LDRB  r0, [r1]      @ 加载无符号字节，高24位清零
LDRSB r0, [r1]      @ 加载有符号字节，符号扩展到32位
LDRH  r0, [r1]      @ 加载无符号半字，高16位清零
LDRSH r0, [r1]      @ 加载有符号半字，符号扩展到32位
LDR   r0, [r1]      @ 加载32位字
LDRD  r0, r1, [r2]  @ 从r2指向的地址加载64位双字到r0和r1
```

##### 存储指令示例

```asm
STRB  r0, [r1]      @ 存储r0的低8位
STRH  r0, [r1]      @ 存储r0的低16位
STR   r0, [r1]      @ 存储r0的32位
STRD  r0, r1, [r2]  @ 将r0和r1组成的64位双字存储到r2指向的地址
```

##### 数据类型范围

| 类型 | 范围 | 用途 |
|------|------|------|
| 无符号字节 | 0 ~ 255 | 字符、小整数 |
| 有符号字节 | -128 ~ 127 | 有符号小整数 |
| 无符号半字 | 0 ~ 65535 | 较大整数、Unicode |
| 有符号半字 | -32768 ~ 32767 | 有符号整数 |
| 无符号字 | 0 ~ 4294967295 | 地址、大整数 |

#### 常用编程模式

##### 循环结构

```asm
@ for循环示例: for(int i=0; i<10; i++)
MOV r0, #0          @ i = 0
loop:
    CMP r0, #10     @ 比较 i 和 10
    BGE loop_end    @ 如果 i >= 10 跳出循环
    @ 循环体代码
    ADD r0, r0, #1  @ i++
    B loop          @ 跳回循环开始
loop_end:

@ while循环示例: while(condition)
while_loop:
    @ 检查条件的代码
    CMP r0, #0      @ 检查条件
    BEQ while_end   @ 条件为假则退出
    @ 循环体代码
    B while_loop    @ 继续循环
while_end:
```

##### 条件判断

```asm
@ if-else 结构
CMP r0, #5          @ 比较 r0 和 5
BLT else_branch     @ 如果 r0 < 5 跳到 else
    @ if 分支代码
    MOV r1, #1
    B endif
else_branch:
    @ else 分支代码
    MOV r1, #0
endif:

@ switch-case 结构
CMP r0, #1
BEQ case1
CMP r0, #2
BEQ case2
CMP r0, #3
BEQ case3
B default_case

case1:
    @ case 1 代码
    B switch_end
case2:
    @ case 2 代码
    B switch_end
case3:
    @ case 3 代码
    B switch_end
default_case:
    @ 默认情况代码
switch_end:
```

##### 函数调用模板

```asm
@ 标准函数模板
function_name:
    PUSH {r4-r11, lr}   @ 保存寄存器和返回地址
    SUB sp, sp, #16     @ 为局部变量分配栈空间

    @ 函数体
    @ 参数在 r0-r3 中
    @ 局部变量使用栈空间

    MOV r0, #return_val @ 设置返回值
    ADD sp, sp, #16     @ 释放栈空间
    POP {r4-r11, pc}    @ 恢复寄存器并返回

@ 调用函数
    MOV r0, #arg1       @ 第一个参数
    MOV r1, #arg2       @ 第二个参数
    MOV r2, #arg3       @ 第三个参数
    MOV r3, #arg4       @ 第四个参数
    BL function_name    @ 调用函数
    @ 返回值在 r0 中
```

##### 数组操作

```asm
@ 数组遍历示例
LDR r0, =array_base     @ 数组基地址
MOV r1, #0              @ 索引 i = 0
MOV r2, #array_size     @ 数组大小

array_loop:
    CMP r1, r2          @ 比较 i 和 size
    BGE array_end       @ i >= size 则结束

    LDR r3, [r0, r1, LSL #2]  @ 加载 array[i] (假设int数组)
    @ 处理 r3 中的数据

    ADD r1, r1, #1      @ i++
    B array_loop
array_end:

@ 字符串长度计算
LDR r0, =string_ptr     @ 字符串指针
MOV r1, #0              @ 长度计数器

strlen_loop:
    LDRB r2, [r0, r1]   @ 加载当前字符
    CMP r2, #0          @ 检查是否为'\0'
    BEQ strlen_end      @ 是则结束
    ADD r1, r1, #1      @ 长度++
    B strlen_loop
strlen_end:
    @ r1 包含字符串长度
```

##### 位操作技巧

```asm
@ 检查第n位是否为1
MOV r1, #1
LSL r1, r1, r0      @ r1 = 1 << n
TST r2, r1          @ 测试 r2 的第n位
BNE bit_is_set      @ 如果位为1则跳转

@ 设置第n位为1
MOV r1, #1
LSL r1, r1, r0      @ r1 = 1 << n
ORR r2, r2, r1      @ r2 |= (1 << n)

@ 清除第n位
MOV r1, #1
LSL r1, r1, r0      @ r1 = 1 << n
BIC r2, r2, r1      @ r2 &= ~(1 << n)

@ 切换第n位
MOV r1, #1
LSL r1, r1, r0      @ r1 = 1 << n
EOR r2, r2, r1      @ r2 ^= (1 << n)

@ 计算2的幂次
MOV r1, #1
LSL r1, r1, r0      @ r1 = 2^r0

@ 除以2的幂次(无符号)
LSR r1, r2, r0      @ r1 = r2 / (2^r0)

@ 除以2的幂次(有符号)
ASR r1, r2, r0      @ r1 = r2 / (2^r0) (保持符号)
```

##### 内存对齐和优化

```asm
@ 4字节对齐检查
TST r0, #3          @ 检查低2位
BNE not_aligned     @ 如果不为0则未对齐

@ 向上对齐到4字节边界
ADD r0, r0, #3      @ r0 += 3
BIC r0, r0, #3      @ r0 &= ~3

@ 向下对齐到4字节边界
BIC r0, r0, #3      @ r0 &= ~3

@ 快速清零内存块
MOV r1, #0          @ 清零值
MOV r2, r0          @ 保存起始地址
ADD r3, r0, r3      @ 计算结束地址
clear_loop:
    CMP r2, r3
    BGE clear_end
    STR r1, [r2], #4  @ 存储0并递增地址
    B clear_loop
clear_end:
```

这些编程模式涵盖了ARM汇编中最常用的结构和技巧，可以作为编写ARM汇编程序的参考模板。
