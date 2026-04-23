# MIPS32 架构基础知识

!!! tip "Pwn 速查"
    - O32 函数参数：`$a0-$a3`，返回值：`$v0` / `$v1`。
    - Linux O32 系统调用：调用号放 `$v0`，真实号通常是 `4000 + offset`；错误由 `$a3` 标记。
    - MIPS 有分支延迟槽；手写 shellcode 或 `.set noreorder` 时必须显式处理下一条指令。

## MIPS 寄存器详解

### 通用寄存器 (`$0-$31`)

| 寄存器 | 别名 | 用途 |
|---|---|---|
| `$0` | `$zero` | 硬件零寄存器，永远为 0 |
| `$1` | `$at` | 汇编器临时寄存器 |
| `$2-$3` | `$v0-$v1` | 函数返回值；`$v0` 也放系统调用号 |
| `$4-$7` | `$a0-$a3` | 函数参数 |
| `$8-$15` | `$t0-$t7` | 临时寄存器 |
| `$16-$23` | `$s0-$s7` | 保存寄存器 |
| `$24-$25` | `$t8-$t9` | 临时寄存器，PIC/函数调用中常见 |
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
| `$8-$15` | `$t0-$t7` | 临时寄存器 | 调用者保存 |
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
| `PC` | 程序计数器 |
| `HI` | 乘法 / 除法结果高位 |
| `LO` | 乘法 / 除法结果低位 |

## 字节序

MIPS (big-endian) 与 MIPSEL (little-endian) 主要区别在内存中字节排列，上层寄存器与 ABI 规则相同。

| 架构 | 端序 | `0x11223344` 在内存中的字节序（地址递增） |
|---|---|---|
| MIPS | Big-endian | `11 22 33 44` |
| MIPSEL | Little-endian | `44 33 22 11` |

!!! tip "Exploit 提醒"
    1. little-endian 写入 32 位立即数时需要按字节逆序，例如 `p32(0x4007c8)` 生成 `c8 07 40 00`。
    2. 在 GDB / hexdump 中解读栈内容时先确认端序，否则很容易把覆盖地址算反。
    3. ROP 链跨端迁移时，地址展示顺序和 payload 写入顺序要分开看。

## Linux MIPS 系统调用表

### 常用系统调用号 (偏移 / 实际 O32 号)

> 与 MIPSEL 一样, O32 ABI 真实号 = 4000 + 偏移; 下表保留偏移并在注释列写出实际值。

??? info "O32 常用系统调用号（展开查看）"
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
    #define __NR_chdir      12   /* 4012 */
    #define __NR_time       13   /* 4013 */
    #define __NR_mknod      14   /* 4014 */
    #define __NR_chmod      15   /* 4015 */
    #define __NR_lchown     16   /* 4016 */
    #define __NR_lseek      19   /* 4019 */
    #define __NR_getpid     20   /* 4020 */
    #define __NR_mount      21   /* 4021 */
    #define __NR_umount     22   /* 4022 */
    #define __NR_setuid     23   /* 4023 */
    #define __NR_getuid     24   /* 4024 */
    #define __NR_kill       37   /* 4037 */
    #define __NR_mkdir      39   /* 4039 */
    #define __NR_rmdir      40   /* 4040 */
    #define __NR_dup        41   /* 4041 */
    #define __NR_pipe       42   /* 4042 */
    #define __NR_brk        45   /* 4045 */
    #define __NR_ioctl      54   /* 4054 */
    #define __NR_mmap       90   /* 4090 */
    #define __NR_munmap     91   /* 4091 */
    #define __NR_mprotect  125   /* 4125 */
    #define __NR_socket   183   /* 4183 */
    #define __NR_bind     184   /* 4184 */
    #define __NR_connect  185   /* 4185 */
    #define __NR_listen   186   /* 4186 */
    #define __NR_accept   187   /* 4187 */
    ```

> N64 / N32 ABI: 基址分别 5000 / 6000。利用时请用反汇编或头文件确认。

### 系统调用约定

[系统调用查询](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)

| 项目 | O32 约定 |
|---|---|
| 系统调用号 | `$v0` (`$2`) |
| 参数 1-4 | `$a0-$a3` (`$4-$7`) |
| 参数 5-6 | 栈传递 |
| 返回值 / errno | `$v0` (`$2`) |
| 错误指示 | `$a3` (`$7`) 非零表示错误；出错时 `$v0` 通常为正 errno |
| 触发指令 | `syscall` |

### 系统调用示例

```asm
# write(1, "Hello", 5)
li $v0, 4004    # __NR_write (O32 ABI)
li $a0, 1       # fd = 1 (stdout)
la $a1, hello   # buf = "Hello"
li $a2, 5       # count = 5
syscall         # 系统调用

# exit(0)
li $v0, 4001    # __NR_exit (O32 ABI)
li $a0, 0       # status = 0
syscall
```

## 函数调用约定

### 参数传递

| 项目 | O32 函数调用约定 |
|---|---|
| 前 4 个参数 | `$a0-$a3` (`$4-$7`) |
| 更多参数 | 通过栈传递 |
| 返回值 | `$v0`, `$v1` (`$2`, `$3`) |
| 栈对齐 | 通常 8 字节 |

!!! note
    `$ra` 不是普通“被调用者保存”寄存器：非叶子函数执行新的 `jal` 前必须先保存自己的返回地址。

### 栈帧结构

```text
高地址
+------------------+
| 第n个参数        |  <- 超过$a0-$a3的参数
| ...              |
| 第5个参数        |
+------------------+
| 返回地址 ($ra)   |  <- 函数调用时保存
| 老的帧指针($fp)  |  <- 可选
| 保存的寄存器     |  <- $s0-$s7需要保存
| 局部变量         |
+------------------+  <- $sp (当前栈指针)
低地址
```

### 函数调用流程

```asm
# 调用者 (Caller)
# 保存临时寄存器 (如果需要)
addiu $sp, $sp, -8
sw $t0, 0($sp)
sw $t1, 4($sp)

li $a0, arg1        # 设置参数1
li $a1, arg2        # 设置参数2
jal function        # 调用函数
nop                 # 延迟槽

# $v0 包含返回值
lw $t0, 0($sp)
lw $t1, 4($sp)
addiu $sp, $sp, 8   # 恢复栈

# 被调用者 (Callee)
function:
addiu $sp, $sp, -32 # 分配栈空间
sw $ra, 28($sp)     # 保存返回地址
sw $fp, 24($sp)     # 保存帧指针
sw $s0, 20($sp)     # 保存需要使用的寄存器
move $fp, $sp       # 设置新的帧指针

# 函数体

li $v0, return_val  # 设置返回值
lw $s0, 20($sp)     # 恢复寄存器
lw $fp, 24($sp)     # 恢复帧指针
lw $ra, 28($sp)     # 恢复返回地址
addiu $sp, $sp, 32  # 释放栈空间
jr $ra              # 返回
nop                 # 延迟槽
```

## 指令集合

> MIPS 指令字长为 4 字节。

### 指令格式

MIPS 指令分为三种格式：

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
| add | add rd, rs, rt | rd = rs + rt | `add $t0, $t1, $t2` | 有符号加法 |
| addu | addu rd, rs, rt | rd = rs + rt | `addu $t0, $t1, $t2` | 无符号加法 |
| addi | addi rt, rs, imm | rt = rs + imm | `addi $t0, $t1, 100` | 立即数加法 |
| addiu | addiu rt, rs, imm | rt = rs + imm | `addiu $t0, $t1, 100` | 无符号立即数加法 |
| sub | sub rd, rs, rt | rd = rs - rt | `sub $t0, $t1, $t2` | 有符号减法 |
| subu | subu rd, rs, rt | rd = rs - rt | `subu $t0, $t1, $t2` | 无符号减法 |
| mult | mult rs, rt | HI:LO = rs * rt | `mult $t0, $t1` | 有符号乘法 |
| multu | multu rs, rt | HI:LO = rs * rt | `multu $t0, $t1` | 无符号乘法 |
| div | div rs, rt | LO=rs/rt, HI=rs%rt | `div $t0, $t1` | 有符号除法 |
| divu | divu rs, rt | LO=rs/rt, HI=rs%rt | `divu $t0, $t1` | 无符号除法 |

#### 逻辑运算指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| and | and rd, rs, rt | rd = rs & rt | `and $t0, $t1, $t2` | 按位与 |
| andi | andi rt, rs, imm | rt = rs & imm | `andi $t0, $t1, 0xFF` | 立即数按位与 |
| or | or rd, rs, rt | rd = rs \| rt | `or $t0, $t1, $t2` | 按位或 |
| ori | ori rt, rs, imm | rt = rs \| imm | `ori $t0, $t1, 0xFF` | 立即数按位或 |
| xor | xor rd, rs, rt | rd = rs ^ rt | `xor $t0, $t1, $t2` | 按位异或 |
| xori | xori rt, rs, imm | rt = rs ^ imm | `xori $t0, $t1, 0xFF` | 立即数按位异或 |
| nor | nor rd, rs, rt | rd = ~(rs \| rt) | `nor $t0, $t1, $t2` | 按位或非 |

#### 移位指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| sll | sll rd, rt, shamt | rd = rt << shamt | `sll $t0, $t1, 2` | 逻辑左移 |
| sllv | sllv rd, rt, rs | rd = rt << rs | `sllv $t0, $t1, $t2` | 变量逻辑左移 |
| srl | srl rd, rt, shamt | rd = rt >> shamt | `srl $t0, $t1, 2` | 逻辑右移 |
| srlv | srlv rd, rt, rs | rd = rt >> rs | `srlv $t0, $t1, $t2` | 变量逻辑右移 |
| sra | sra rd, rt, shamt | rd = rt >> shamt | `sra $t0, $t1, 2` | 算术右移 |
| srav | srav rd, rt, rs | rd = rt >> rs | `srav $t0, $t1, $t2` | 变量算术右移 |

#### 数据传输指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| lw | lw rt, offset(rs) | rt = Memory[rs+offset] | `lw $t0, 0($sp)` | 加载字 |
| lh | lh rt, offset(rs) | rt = Memory[rs+offset] | `lh $t0, 0($sp)` | 加载半字(有符号) |
| lhu | lhu rt, offset(rs) | rt = Memory[rs+offset] | `lhu $t0, 0($sp)` | 加载半字(无符号) |
| lb | lb rt, offset(rs) | rt = Memory[rs+offset] | `lb $t0, 0($sp)` | 加载字节(有符号) |
| lbu | lbu rt, offset(rs) | rt = Memory[rs+offset] | `lbu $t0, 0($sp)` | 加载字节(无符号) |
| sw | sw rt, offset(rs) | Memory[rs+offset] = rt | `sw $t0, 0($sp)` | 存储字 |
| sh | sh rt, offset(rs) | Memory[rs+offset] = rt | `sh $t0, 0($sp)` | 存储半字 |
| sb | sb rt, offset(rs) | Memory[rs+offset] = rt | `sb $t0, 0($sp)` | 存储字节 |

#### 立即数加载指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| lui | lui rt, imm | rt = imm << 16 | `lui $t0, 0x1234` | 加载立即数到高位 |
| li | li rt, imm | rt = imm | `li $t0, 100` | 加载立即数(伪指令) |
| la | la rt, label | rt = &label | `la $t0, string` | 加载地址(伪指令) |

#### 比较指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| slt | slt rd, rs, rt | rd = (rs < rt) ? 1 : 0 | `slt $t0, $t1, $t2` | 有符号小于设置 |
| sltu | sltu rd, rs, rt | rd = (rs < rt) ? 1 : 0 | `sltu $t0, $t1, $t2` | 无符号小于设置 |
| slti | slti rt, rs, imm | rt = (rs < imm) ? 1 : 0 | `slti $t0, $t1, 100` | 立即数有符号小于设置 |
| sltiu | sltiu rt, rs, imm | rt = (rs < imm) ? 1 : 0 | `sltiu $t0, $t1, 100` | 立即数无符号小于设置 |

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
| jalr | jalr rd, rs | rd = PC+8; PC = rs | `jalr $ra, $t0` == `jalr $t0` | 寄存器跳转链接；返回地址跳过延迟槽 |

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
li $t0, 100         # 将立即数100加载到$t0
addi $t1, $t0, 5    # $t1 = $t0 + 5
```

#### 寄存器寻址

```asm
move $t0, $t1       # 将$t1的值复制到$t0
add $t0, $t1, $t2   # $t0 = $t1 + $t2
```

#### 基址加偏移寻址

```asm
lw $t0, 0($sp)      # 从$sp+0地址加载数据到$t0
lw $t0, 4($sp)      # 从$sp+4地址加载数据到$t0
sw $t0, 8($sp)      # 将$t0的数据存储到$sp+8地址
```

#### PC相对寻址(分支指令)

```asm
beq $t0, $t1, label # 如果$t0==$t1则跳转到label
bne $t0, $zero, loop # 如果$t0!=0则跳转到loop
```

#### 绝对寻址(跳转指令)

```asm
j main              # 无条件跳转到main标签
jal function        # 跳转到function并保存返回地址
```

### 数据类型支持

MIPS支持多种数据类型的操作：

#### 数据类型表

| 数据类型 | 大小 | 后缀 | 有符号后缀 | 描述 |
|----------|------|------|------------|------|
| 字节 (Byte) | 8位 | b | b | 有符号/无符号字节 |
| 半字 (Halfword) | 16位 | h | h/hu | 有符号/无符号半字 |
| 字 (Word) | 32位 | w | 无 | 32位数据 |

#### 加载指令示例

```asm
lb  $t0, 0($sp)     # 加载有符号字节，符号扩展到32位
lbu $t0, 0($sp)     # 加载无符号字节，高24位清零
lh  $t0, 0($sp)     # 加载有符号半字，符号扩展到32位
lhu $t0, 0($sp)     # 加载无符号半字，高16位清零
lw  $t0, 0($sp)     # 加载32位字
```

#### 存储指令示例

```asm
sb  $t0, 0($sp)     # 存储$t0的低8位
sh  $t0, 0($sp)     # 存储$t0的低16位
sw  $t0, 0($sp)     # 存储$t0的32位
```

#### 数据类型范围

| 类型 | 范围 | 用途 |
|------|------|------|
| 无符号字节 | 0 ~ 255 | 字符、小整数 |
| 有符号字节 | -128 ~ 127 | 有符号小整数 |
| 无符号半字 | 0 ~ 65535 | 较大整数、Unicode |
| 有符号半字 | -32768 ~ 32767 | 有符号整数 |
| 无符号字 | 0 ~ 4294967295 | 地址、大整数 |

### 常用编程模式

!!! note "延迟槽提示"
    为了突出控制流，下面部分示例按“易读伪汇编”书写。若在 `.set noreorder`、shellcode 或手写 gadget 中使用，请为每条分支/跳转后的延迟槽显式填入 `nop` 或一条确定安全的指令。

#### 循环结构

```asm
# for循环示例: for(int i=0; i<10; i++)
li $t0, 0           # i = 0
li $t1, 10          # 循环上限
loop:
    bge $t0, $t1, loop_end  # 如果 i >= 10 跳出循环
    # 循环体代码
    addi $t0, $t0, 1        # i++
    j loop                  # 跳回循环开始
loop_end:

# while循环示例: while(condition)
while_loop:
    # 检查条件的代码
    beq $t0, $zero, while_end   # 条件为假则退出
    # 循环体代码
    j while_loop                # 继续循环
while_end:
```

#### 条件判断

```asm
# if-else 结构
bne $t0, $t1, else_branch   # 如果 $t0 != $t1 跳到 else
    # if 分支代码
    li $t2, 1
    j endif
else_branch:
    # else 分支代码
    li $t2, 0
endif:

# switch-case 结构
li $t1, 1
beq $t0, $t1, case1
li $t1, 2
beq $t0, $t1, case2
li $t1, 3
beq $t0, $t1, case3
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

#### 函数调用模板

```asm
# 标准函数模板
function_name:
    addiu $sp, $sp, -32     # 分配栈空间
    sw $ra, 28($sp)         # 保存返回地址
    sw $fp, 24($sp)         # 保存帧指针
    sw $s0, 20($sp)         # 保存需要的寄存器
    sw $s1, 16($sp)
    move $fp, $sp           # 设置新的帧指针

    # 函数体
    # 参数在 $a0-$a3 中
    # 局部变量使用栈空间

    li $v0, return_val      # 设置返回值
    lw $s1, 16($sp)         # 恢复寄存器
    lw $s0, 20($sp)
    lw $fp, 24($sp)         # 恢复帧指针
    lw $ra, 28($sp)         # 恢复返回地址
    addiu $sp, $sp, 32      # 释放栈空间
    jr $ra                  # 返回
    nop                     # 延迟槽

# 调用函数
    li $a0, arg1            # 第一个参数
    li $a1, arg2            # 第二个参数
    li $a2, arg3            # 第三个参数
    li $a3, arg4            # 第四个参数
    jal function_name       # 调用函数
    nop                     # 延迟槽
    # 返回值在 $v0 中
```

#### 数组操作

```asm
# 数组遍历示例
la $t0, array           # 数组基地址
li $t1, 0               # 索引 i = 0
li $t2, array_size      # 数组大小

array_loop:
    bge $t1, $t2, array_end     # i >= size 则结束

    sll $t3, $t1, 2             # t3 = i * 4 (假设int数组)
    add $t3, $t0, $t3           # t3 = &array[i]
    lw $t4, 0($t3)              # 加载 array[i]
    # 处理 $t4 中的数据

    addi $t1, $t1, 1            # i++
    j array_loop
array_end:

# 字符串长度计算
la $t0, string          # 字符串指针
li $t1, 0               # 长度计数器

strlen_loop:
    add $t2, $t0, $t1   # 计算当前字符地址
    lbu $t3, 0($t2)     # 加载当前字符
    beq $t3, $zero, strlen_end  # 检查是否为'\0'
    addi $t1, $t1, 1    # 长度++
    j strlen_loop
strlen_end:
    # $t1 包含字符串长度
```

#### 位操作技巧

```asm
# 检查第n位是否为1
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
and $t2, $t3, $t1       # 测试 $t3 的第n位
bne $t2, $zero, bit_is_set

# 设置第n位为1
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
or $t2, $t2, $t1        # $t2 |= (1 << n)

# 清除第n位
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
nor $t1, $t1, $zero     # $t1 = ~(1 << n)
and $t2, $t2, $t1       # $t2 &= ~(1 << n)

# 切换第n位
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 1 << n
xor $t2, $t2, $t1       # $t2 ^= (1 << n)

# 计算2的幂次
li $t1, 1
sllv $t1, $t1, $t0      # $t1 = 2^$t0

# 除以2的幂次(无符号)
srlv $t1, $t2, $t0      # $t1 = $t2 / (2^$t0)

# 除以2的幂次(有符号)
srav $t1, $t2, $t0      # $t1 = $t2 / (2^$t0) (保持符号)
```

#### 内存对齐和优化

```asm
# 4字节对齐检查
andi $t1, $t0, 3        # 检查低2位
bne $t1, $zero, not_aligned

# 向上对齐到4字节边界
addi $t0, $t0, 3        # $t0 += 3
li $t9, -4              # 0xfffffffc
and $t0, $t0, $t9       # $t0 &= ~3

# 向下对齐到4字节边界
li $t9, -4
and $t0, $t0, $t9       # $t0 &= ~3

# 快速清零内存块
move $t1, $zero         # 清零值
move $t2, $t0           # 保存起始地址
add $t3, $t0, $t4       # 计算结束地址
clear_loop:
    bge $t2, $t3, clear_end
    sw $t1, 0($t2)      # 存储0
    addi $t2, $t2, 4    # 递增地址
    j clear_loop
clear_end:
```

### 延迟槽 (Delay Slot)

MIPS架构的一个重要特性是分支延迟槽：

```asm
# 分支指令后的一条指令总是会被执行
beq $t0, $t1, target
add $t2, $t3, $t4       # 延迟槽：无论分支是否发生都会执行

# 跳转指令也有延迟槽
jal function
move $a0, $t0           # 延迟槽：设置参数

# 如果延迟槽没有有用的指令，使用nop
j loop
nop                     # 延迟槽：空操作
```

这些编程模式涵盖了MIPS汇编中最常用的结构和技巧，可以作为编写MIPS汇编程序的参考模板。
