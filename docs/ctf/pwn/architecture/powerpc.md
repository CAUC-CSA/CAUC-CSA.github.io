# PowerPC 架构基础知识

!!! tip "Pwn 速查"
    - 函数参数：`r3-r10`，返回值：`r3`。
    - Linux syscall：调用号放 `r0`，参数放 `r3-r8`，指令为 `sc`。
    - 间接跳转通常走 `mtctr Rx; bctr` 或 `mtctr Rx; bctrl`。

!!! warning "易错点"
    PowerPC Linux syscall 失败由 `CR0.SO` 标记，不能只按“返回值为负”判断。

## PowerPC 寄存器详解

### 通用寄存器 (`r0-r31`)

| 寄存器 | 用途 | 备注 |
|---|---|---|
| `r0` | 通用寄存器 | 某些编码形式里被解释为常量 0 / 省略寄存器，但不是硬连 0 |
| `r1` | 栈指针 | 帧首常保存上一帧 `r1` 形成回链 |
| `r2` | TOC / 小数据区锚 | ABI 相关，32-bit SysV 可保留 |
| `r3-r10` | 参数 / 返回值通用寄存器 | 整数 / 指针参数按序放置 |
| `r11-r12` | 调用者保存临时寄存器 | PLT / 跳板可用 |
| `r13` | 线程指针 / 小数据区指针 | 不要随意破坏 |
| `r14-r31` | 保存寄存器 | 被调用者保存 |

### 寄存器别名和用途

| 寄存器 | 别名 | 用途 / 备注 | 调用约定 |
|---|---|---|---|
| `r0` | - | 通用；某些形式伪零 | 调用者保存 |
| `r1` | `sp` | 栈指针 / 帧回链 | 特殊 |
| `r2` | `toc` | TOC / 小数据区锚 | 保留 |
| `r3` | - | 第 1 参数 / 返回值 | 调用者保存 |
| `r4-r10` | - | 第 2-8 参数 | 调用者保存 |
| `r11-r12` | - | 临时 / PLT 辅助 | 调用者保存 |
| `r13` | `tp` | 线程指针 / SDA2 | 保留 |
| `r14-r31` | - | 保存寄存器 | 被调用者保存 |

### 浮点寄存器 (`f0-f31`)

| 寄存器 | 用途 |
|---|---|
| `f0` | 临时浮点寄存器 |
| `f1` | 浮点参数 / 返回值 |
| `f2-f8` | 浮点参数寄存器 |
| `f9-f13` | 临时浮点寄存器 |
| `f14-f31` | 保存浮点寄存器 |

### 特殊寄存器

| 寄存器 | 作用 |
|---|---|
| `PC` | 程序计数器 |
| `LR` | 链接寄存器 |
| `CTR` | 计数寄存器，间接跳转常用 |
| `XER` | 定点异常寄存器 |
| `CR` | 条件寄存器 |
| `MSR` | 机器状态寄存器 |
| `FPSCR` | 浮点状态控制寄存器 |

### 条件寄存器详解

条件寄存器 `CR` 分为 8 个 4 位字段（`CR0-CR7`）：

| 字段 | 常见含义 |
|---|---|
| `CR0.LT` | 整数比较结果：小于 |
| `CR0.GT` | 整数比较结果：大于 |
| `CR0.EQ` | 整数比较结果：等于 |
| `CR0.SO` | Summary Overflow；Linux syscall 用它标记错误 |
| `CR1` | 浮点比较结果 |
| `CR2-CR7` | 用户定义或其他比较结果 |

## Linux PowerPC 系统调用表

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
    #define __NR_waitpid              7
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
    #define __NR_mmap                90
    #define __NR_munmap              91
    #define __NR_mprotect           125
    #define __NR_socket             326
    #define __NR_bind               327
    #define __NR_connect            328
    #define __NR_listen             329
    #define __NR_accept             330
    ```

### 系统调用约定

[系统调用查询](https://gpages.juszkiewicz.com.pl/syscalls-table/syscalls.html)

| 项目 | 约定 |
|---|---|
| 系统调用号 | `r0` |
| 参数 1-6 | `r3`, `r4`, `r5`, `r6`, `r7`, `r8` |
| 返回值 / errno | `r3` |
| 错误指示 | `CR0.SO` 置位表示失败；出错时 `r3` 通常为正 errno |
| 触发指令 | `sc` |

!!! warning
    不能只靠 `r3 < 0` 判断失败；手写 shellcode 或裸 `sc` 后应检查 `CR0.SO`。

### 系统调用示例

```asm
; write(1, "Hello", 5)
li r0, 4        ; __NR_write
li r3, 1        ; fd = 1 (stdout)
lis r4, hello@h ; buf = "Hello" (高16位)
ori r4, r4, hello@l  ; buf 完整地址
li r5, 5        ; count = 5
sc              ; 系统调用

; exit(0)
li r0, 1        ; __NR_exit
li r3, 0        ; status = 0
sc
```

## 函数调用约定

### 参数传递

| 项目 | 常见 PowerPC SysV 约定 |
|---|---|
| 前 8 个整数 / 指针参数 | `r3-r10` |
| 更多参数 | 通过栈传递 |
| 整数 / 指针返回值 | `r3` |
| 32 位 ABI 的 64 位返回值 | `r3:r4` |
| 复杂 / 聚合类型返回 | 通过隐藏指针（首参数）返回 |
| 浮点参数 | `f1-f8` |
| 浮点返回值 | `f1` |

### 栈帧结构

```text
高地址
+------------------+
| 第n个参数        |  <- 超过r3-r10的参数
| ...              |
| 第9个参数        |
+------------------+
| 链接寄存器保存   |  <- LR保存区域
| 帧指针保存       |  <- 前一帧指针
| 保存的寄存器     |  <- r14-r31按需保存；r13通常作线程/小数据区指针，避免破坏
| 局部变量         |
+------------------+  <- r1 (当前栈指针)
低地址
```

### 函数调用流程

```asm
; ---- 调用者 (Caller) ----
    li  r3, arg1        ; 参数1
    li  r4, arg2        ; 参数2
    bl  function        ; 跳转并链接
    ; 返回后 r3 = 返回值

; ---- 被调用者 (Callee) 标准栈帧 ----
function:
    mflr r0             ; 保存返回地址到 r0
    stwu r1,-32(r1)     ; 新建 32B 栈帧 (16B 对齐，可根据需要扩大)
    stw  r0, 8(r1)      ; 保存 LR (示例槽位)
    stw  r31,12(r1)     ; 保存被调用者保存寄存器
    mr  r31,r3          ; 例: 缓存第一个参数
    ; ... 函数主体 ...
    li  r3, return_val  ; 设置返回值
    lwz r31,12(r1)      ; 恢复寄存器
    lwz r0, 8(r1)       ; 取回 LR
    mtlr r0
    addi r1,r1,32       ; 弹栈
    blr                 ; 返回
```

> 说明: 原示例使用越界偏移保存 LR 且未体现回链布局，已修正为简洁且符合常见 ABI 习惯的形式。

## 指令集合

> PowerPC 指令字长为 4 字节。

### 指令格式

PowerPC 指令主要分为以下几种格式：

#### I-Form (立即数格式)

```text
31    26 25   21 20   16 15                    0
+--------+-------+-------+------------------------+
| OPCD   |  RT   |  RA   |          D             |
+--------+-------+-------+------------------------+
  6 bits  5 bits  5 bits       16 bits
```

#### X-Form (扩展格式)

```text
31    26 25   21 20   16 15   11 10    1 0
+--------+-------+-------+-------+-------+-+
| OPCD   |  RT   |  RA   |  RB   |  XO   |Rc|
+--------+-------+-------+-------+-------+-+
  6 bits  5 bits  5 bits  5 bits  10bits 1
```

#### B-Form (分支格式)

```text
31    26 25   21 20   16 15              2 1 0
+--------+-------+-------+----------------+-+-+
| OPCD   |  BO   |  BI   |      BD        |AA|LK|
+--------+-------+-------+----------------+-+-+
  6 bits  5 bits  5 bits     14 bits     1 1
```

### 指令分类

#### 算术运算指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| add | add rD, rA, rB | rD = rA + rB | `add r3, r4, r5` | 加法运算 |
| addi | addi rD, rA, SIMM | rD = rA + SIMM | `addi r3, r4, 100` | 立即数加法 |
| addis | addis rD, rA, SIMM | rD = rA + (SIMM<<16) | `addis r3, r4, 1` | 立即数左移后加法 |
| subf | subf rD, rA, rB | rD = rB - rA | `subf r3, r4, r5` | 减法(真实指令) |
| sub (伪) | sub rD, rA, rB | rD = rA - rB | `sub r3, r4, r5` | 伪指令 → subf rD, rB, rA |
| subi (伪) | subi rD, rA, SIMM | rD = rA - SIMM | `subi r3, r4, 100` | 伪指令 → addi rD, rA, -SIMM |
| mullw | mullw rD, rA, rB | rD = rA * rB | `mullw r3, r4, r5` | 32位乘法 |
| mulhw | mulhw rD, rA, rB | rD = (rA*rB)\[0:31\] | `mulhw r3, r4, r5` | 乘法高位 |
| divw | divw rD, rA, rB | rD = rA / rB | `divw r3, r4, r5` | 有符号除法 |
| divwu | divwu rD, rA, rB | rD = rA / rB | `divwu r3, r4, r5` | 无符号除法 |

#### 逻辑运算指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| and | and rA, rS, rB | rA = rS & rB | `and r3, r4, r5` | 按位与 |
| andi. | andi. rA, rS, UIMM | rA = rS & UIMM | `andi. r3, r4, 0xFF` | 立即数按位与 |
| or | or rA, rS, rB | rA = rS \| rB | `or r3, r4, r5` | 按位或 |
| ori | ori rA, rS, UIMM | rA = rS \| UIMM | `ori r3, r4, 0xFF` | 立即数按位或 |
| xor | xor rA, rS, rB | rA = rS ^ rB | `xor r3, r4, r5` | 按位异或 |
| xori | xori rA, rS, UIMM | rA = rS ^ UIMM | `xori r3, r4, 0xFF` | 立即数按位异或 |
| nand | nand rA, rS, rB | rA = ~(rS & rB) | `nand r3, r4, r5` | 与非 |
| nor | nor rA, rS, rB | rA = ~(rS \| rB) | `nor r3, r4, r5` | 或非 |

#### 移位指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| slw | slw rA, rS, rB | rA = rS << rB | `slw r3, r4, r5` | 逻辑左移 |
| srw | srw rA, rS, rB | rA = rS >> rB | `srw r3, r4, r5` | 逻辑右移 |
| sraw | sraw rA, rS, rB | rA = rS >> rB | `sraw r3, r4, r5` | 算术右移 |
| srawi | srawi rA, rS, SH | rA = rS >> SH | `srawi r3, r4, 2` | 立即数算术右移 |
| rlwinm | rlwinm rA, rS, SH, MB, ME | 循环左移并掩码 | `rlwinm r3, r4, 2, 0, 29` | 复杂移位操作 |

#### 数据传输指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| lwz | lwz rD, d(rA) | rD = MEM[rA+d] | `lwz r3, 0(r1)` | 加载字并清零高位 |
| lbz | lbz rD, d(rA) | rD = MEM[rA+d] | `lbz r3, 0(r1)` | 加载字节并清零高位 |
| lhz | lhz rD, d(rA) | rD = MEM[rA+d] | `lhz r3, 0(r1)` | 加载半字并清零高位 |
| lha | lha rD, d(rA) | rD = MEM[rA+d] | `lha r3, 0(r1)` | 加载半字并符号扩展 |
| stw | stw rS, d(rA) | MEM[rA+d] = rS | `stw r3, 0(r1)` | 存储字 |
| stb | stb rS, d(rA) | MEM[rA+d] = rS | `stb r3, 0(r1)` | 存储字节 |
| sth | sth rS, d(rA) | MEM[rA+d] = rS | `sth r3, 0(r1)` | 存储半字 |
| lwzu | lwzu rD, d(rA) | rD = MEM[rA+d]; rA += d | `lwzu r3, 4(r1)` | 加载字并更新地址 |
| stwu | stwu rS, d(rA) | MEM[rA+d] = rS; rA += d | `stwu r3, -4(r1)` | 存储字并更新地址 |

#### 立即数加载指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| li | li rD, value | rD = value | `li r3, 100` | 加载立即数(伪指令) |
| lis | lis rD, value | rD = value << 16 | `lis r3, 0x1234` | 加载立即数到高位 |
| mr | mr rA, rB | rA = rB | `mr r3, r4` | 移动寄存器(伪指令) |

#### 比较指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| cmp | cmp crfD, rA, rB | 比较rA和rB | `cmp 0, r3, r4` | 有符号比较 |
| cmpi | cmpi crfD, rA, SIMM | 比较rA和立即数 | `cmpi 0, r3, 100` | 有符号立即数比较 |
| cmpl | cmpl crfD, rA, rB | 比较rA和rB | `cmpl 0, r3, r4` | 无符号比较 |
| cmpli | cmpli crfD, rA, UIMM | 比较rA和立即数 | `cmpli 0, r3, 100` | 无符号立即数比较 |

#### 分支跳转指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| b | b target | PC = target | `b main` | 无条件分支 |
| bl | bl target | LR = PC+4; PC = target | `bl function` | 分支并链接 |
| blr | blr | PC = LR | `blr` | 分支到链接寄存器 |
| bc | bc BO, BI, target | 条件分支 | `bc 12, 2, loop` | 条件分支 |
| beq | beq target | if CR[EQ] then PC = target | `beq loop` | 相等则分支 |
| bne | bne target | if !CR[EQ] then PC = target | `bne end` | 不等则分支 |
| blt | blt target | if CR[LT] then PC = target | `blt negative` | 小于则分支 |
| bgt | bgt target | if CR[GT] then PC = target | `bgt positive` | 大于则分支 |
| ble | ble target | if !CR[GT] then PC = target | `ble nonpos` | 小于等于则分支 |
| bge | bge target | if !CR[LT] then PC = target | `bge nonneg` | 大于等于则分支 |
| bctr | bctr | PC = CTR | `bctr` | 跳转到计数寄存器 (间接) |
| bctrl | bctrl | LR = PC+4; PC = CTR | `bctrl` | 跳转到 CTR 并保存返回地址 |
| blrl | blrl | (保存 LR)；PC = 旧LR | `blrl` | 罕用，等价于 `blr`+link，某些汇编器提供 |

### 间接 / 寄存器跳转详解

在 PowerPC 上不能像 x86 那样写 `jmp r9`；需要借助 CTR 或 LR：

1. 使用计数寄存器 CTR (推荐的通用间接跳转方式)

```asm
mtctr r9     ; 将 r9 中地址放入 CTR
bctr         ; 跳转到 r9 指向的地址 (不修改 LR)

mtctr r9
bctrl        ; 跳转到 r9，同时把返回地址保存到 LR
```

1. 使用链接寄存器 LR (更像“调用/返回”风格)

```asm
mtlr r9      ; 将 r9 中地址写入 LR
blr          ; 跳转到 r9 (因为 PC=LR)

mtlr r9
blrl         ; 同时把下一条指令地址写回 LR (形成链式调用)
```

1. 跳转到 r13 同理：

```asm
mtctr r13
bctr          ; 或 bctrl 保存调用点

mtlr r13
blr           ; 或 blrl 保存调用点
```

对比：

| 方式 | 指令序列 | 是否写 LR | 典型用途 | 利弊 |
|------|----------|-----------|----------|------|
| CTR 间接 (不留返回) | mtctr Rx; bctr  | 否 | 纯跳转 / pivot | 不污染 LR；像无返回跳转 |
| CTR 调用 | mtctr Rx; bctrl | 是 | 间接“调用” | 生成可控返回地址 (ROP/JOP 混合) |
| LR 间接 (返回语义) | mtlr Rx; blr    | 否 | 模拟 ret/gadget | 要先保存原 LR；不新建 link |
| LR 调用链 | mtlr Rx; blrl   | 是 | 少见；嵌套链式 | 依赖汇编器支持；可混淆控制流 |

注意事项：

* 指令宽度固定 4 字节，`b label` 的 label 需汇编期解析；`b 9` 这样的立即数字面量既非符号又非对齐编码 → 汇编报 “operand out of domain”。
* 不能直接写 `b r9`；必须 `mtctr r9; bctr` 或 `mtlr r9; blr`。
* `bctr` 与 `blr` 都是无条件分支，不会自动清理栈；调用者/被调用者栈维护要手动完成。
* Exploit 场景中寻找现成 gadget：常见片段如 `mtctr rX; bctr`, `mtlr rX; blr`, `lwz rX,disp(rY); mtctr rX; bctr`，可实现 JOP 链。
* 若需要保存原 LR 以免破坏返回序列，可在使用前 `mflr r0; stw r0,off(r1)`，结束后恢复。
* `bctrl` 会把下一条指令地址写入 LR，可以把它当作“call *reg” 的语义；后续可用 `blr` 返回。
* 某些安全特性 (e.g. ELFv2 ABI / 指针认证(在某些变体)/CFI) 可能关注间接调用点，手工合成序列时要与 ABI 预期一致（例如保持 r2/toc 不被破坏）。

最简“跳到 r9” 代码模板：

```asm
mtctr r9
bctr
```

最简“调用 r9 并可返回” 代码模板：

```asm
mtctr r9    ; 或 mtlr r9
bctrl       ; 若希望返回地址在 LR
; ......
blr         ; 返回到调用者
```

或使用 LR 路径：

```asm
mtlr r9
blr         ; 无新 link (相当于 tail jump)
```

调试建议：

* 用 `objdump -d` 确认 gadget 是否存在：`grep -i "mtctr"` / `grep -i "bctr"`。
* GDB 下可用 `si` 单步观察 CTR/LR 的变化：`info registers ctr lr`。
* 若跳转地址未对齐（非 4 字节边界）会触发对齐异常；确保寄存器内地址末两位为 0。

常见坑：

1. 忘记把控制转移目标写入 CTR/LR，就直接执行 bctr/blr → 跳到旧地址。
2. 使用 bctrl 时未保存/期望原 LR，导致后续返回链断裂。
3. 泄漏/构造地址时忽略字节序 (PowerPC big-endian)，利用时写入的字节序混乱。
4. Smash 栈覆盖 r1 回链结构时，未同时准备一个可执行/可读的受控栈区域，造成崩溃。

与 x86 对比速记：

| x86 指令 | 语义 | PowerPC 等价概念 |
|----------|------|------------------|
| jmp *reg | 无返回跳转 | mtctr rX; bctr |
| call *reg | 保存返回地址并跳转 | mtctr rX; bctrl |
| ret | 弹栈返回 | (lwz r0,off(r1); mtlr r0; addi r1,r1,frame; blr) 组合 |

这样即可在 README 中完整覆盖“如何跳到 r9 / r13” 及相关间接跳转实践。

#### 特殊指令

| 指令 | 格式 | 含义 | 示例 | 描述 |
|------|------|------|------|------|
| nop | nop | 空操作 | `nop` | 无操作(ori 0,0,0) |
| sc | sc | 系统调用 | `sc` | 触发系统调用 |
| mflr | mflr rD | rD = LR | `mflr r0` | 从链接寄存器移动 |
| mtlr | mtlr rS | LR = rS | `mtlr r0` | 移动到链接寄存器 |
| mfcr | mfcr rD | rD = CR | `mfcr r3` | 从条件寄存器移动 |
| mtcr | mtcr rS | CR = rS | `mtcr r3` | 移动到条件寄存器 |
| mfctr | mfctr rD | rD = CTR | `mfctr r3` | 从计数寄存器移动 |
| mtctr | mtctr rS | CTR = rS | `mtctr r3` | 移动到计数寄存器 |

### 寻址模式详解

#### 立即数寻址

```asm
li r3, 100          ; 将立即数100加载到r3
addi r4, r3, 5      ; r4 = r3 + 5
```

#### 寄存器寻址

```asm
mr r3, r4           ; 将r4的值复制到r3
add r3, r4, r5      ; r3 = r4 + r5
```

#### 基址加偏移寻址

```asm
lwz r3, 0(r1)       ; 从r1+0地址加载数据到r3
lwz r3, 4(r1)       ; 从r1+4地址加载数据到r3
stw r3, 8(r1)       ; 将r3的数据存储到r1+8地址
```

#### 索引寻址

```asm
lwzx r3, r4, r5     ; 从r4+r5地址加载数据到r3
stwx r3, r4, r5     ; 将r3的数据存储到r4+r5地址
```

#### 更新寻址

```asm
lwzu r3, 4(r4)      ; 从r4+4地址加载数据到r3，然后r4 += 4
stwu r3, -4(r1)     ; 将r3存储到r1-4地址，然后r1 -= 4
```

### 条件码操作

#### 条件寄存器字段

```text
CR0: 算术操作结果
CR1: 浮点操作结果
CR2-CR7: 逻辑操作和比较结果
```

#### 条件码设置

```asm
; 算术操作设置CR0
add. r3, r4, r5     ; 加法并设置CR0
sub. r3, r4, r5     ; 减法并设置CR0

; 比较操作设置指定CR字段
cmp 0, r3, r4       ; 比较r3和r4，结果放入CR0
cmpi 1, r3, 100     ; 比较r3和100，结果放入CR1
```

#### 条件分支

```asm
cmp 0, r3, r4       ; 比较r3和r4
beq equal           ; 如果相等则跳转
blt less_than       ; 如果r3 < r4则跳转
bgt greater_than    ; 如果r3 > r4则跳转
```

### 数据类型支持

PowerPC支持多种数据类型的操作：

#### 数据类型表

| 数据类型 | 大小 | 后缀 | 有符号后缀 | 描述 |
|----------|------|------|------------|------|
| 字节 (Byte) | 8位 | b | 无 | 8位数据 |
| 半字 (Halfword) | 16位 | h | ha | 16位数据 |
| 字 (Word) | 32位 | w | 无 | 32位数据 |
| 双字 (Doubleword) | 64位 | d | 无 | 64位数据(64位PowerPC) |

#### 加载指令示例

```asm
lbz r3, 0(r1)       ; 加载字节，高24位清零
lhz r3, 0(r1)       ; 加载半字，高16位清零
lha r3, 0(r1)       ; 加载半字，符号扩展到32位
lwz r3, 0(r1)       ; 加载32位字
```

#### 存储指令示例

```asm
stb r3, 0(r1)       ; 存储r3的低8位
sth r3, 0(r1)       ; 存储r3的低16位
stw r3, 0(r1)       ; 存储r3的32位
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

#### 循环结构

```asm
; for循环示例: for(int i=0; i<10; i++)
li r3, 0            ; i = 0
li r4, 10           ; 循环上限
loop:
    cmp 0, r3, r4   ; 比较 i 和 10
    bge loop_end    ; 如果 i >= 10 跳出循环
    ; 循环体代码
    addi r3, r3, 1  ; i++
    b loop          ; 跳回循环开始
loop_end:

; while循环示例: while(condition)
while_loop:
    ; 检查条件的代码
    cmpi 0, r3, 0   ; 检查条件
    beq while_end   ; 条件为假则退出
    ; 循环体代码
    b while_loop    ; 继续循环
while_end:
```

#### 条件判断

```asm
; if-else 结构
cmp 0, r3, r4       ; 比较 r3 和 r4
bne else_branch     ; 如果 r3 != r4 跳到 else
    ; if 分支代码
    li r5, 1
    b endif
else_branch:
    ; else 分支代码
    li r5, 0
endif:

; switch-case 结构
cmpi 0, r3, 1
beq case1
cmpi 0, r3, 2
beq case2
cmpi 0, r3, 3
beq case3
b default_case

case1:
    ; case 1 代码
    b switch_end
case2:
    ; case 2 代码
    b switch_end
case3:
    ; case 3 代码
    b switch_end
default_case:
    ; 默认情况代码
switch_end:
```

#### 函数调用模板

```asm
; 标准函数模板
function_name:
    mflr r0             ; 获取返回地址
    stwu r1, -32(r1)    ; 分配栈空间并写入回链
    stw r0, 8(r1)       ; 保存返回地址
    stw r31, 12(r1)     ; 保存需要的寄存器
    stw r30, 16(r1)

    ; 函数体
    ; 参数在 r3-r10 中
    ; 局部变量使用栈空间

    li r3, return_val   ; 设置返回值
    lwz r30, 16(r1)     ; 恢复寄存器
    lwz r31, 12(r1)
    lwz r0, 8(r1)       ; 恢复返回地址
    mtlr r0             ; 设置链接寄存器
    addi r1, r1, 32     ; 释放栈空间
    blr                 ; 返回

; 调用函数
    li r3, arg1         ; 第一个参数
    li r4, arg2         ; 第二个参数
    li r5, arg3         ; 第三个参数
    li r6, arg4         ; 第四个参数
    bl function_name    ; 调用函数
    ; 返回值在 r3 中
```

#### 数组操作

```asm
; 数组遍历示例
lis r3, array@h     ; 数组基地址高位
ori r3, r3, array@l ; 数组基地址低位
li r4, 0            ; 索引 i = 0
li r5, array_size   ; 数组大小

array_loop:
    cmp 0, r4, r5   ; 比较 i 和 size
    bge array_end   ; i >= size 则结束

    slwi r6, r4, 2  ; r6 = i * 4 (假设int数组)
    lwzx r7, r3, r6 ; 加载 array[i]
    ; 处理 r7 中的数据

    addi r4, r4, 1  ; i++
    b array_loop
array_end:

; 字符串长度计算
lis r3, string@h    ; 字符串指针高位
ori r3, r3, string@l ; 字符串指针低位
li r4, 0            ; 长度计数器

strlen_loop:
    lbzx r5, r3, r4 ; 加载当前字符
    cmpi 0, r5, 0   ; 检查是否为'\0'
    beq strlen_end  ; 是则结束
    addi r4, r4, 1  ; 长度++
    b strlen_loop
strlen_end:
    ; r4 包含字符串长度
```

#### 位操作技巧

```asm
; 检查第n位是否为1
li r4, 1
slw r4, r4, r3      ; r4 = 1 << n
and. r5, r6, r4     ; 测试 r6 的第n位
bne bit_is_set      ; 如果位为1则跳转

; 设置第n位为1
li r4, 1
slw r4, r4, r3      ; r4 = 1 << n
or r5, r5, r4       ; r5 |= (1 << n)

; 清除第n位
li r4, 1
slw r4, r4, r3      ; r4 = 1 << n
andc r5, r5, r4     ; r5 &= ~(1 << n)

; 切换第n位
li r4, 1
slw r4, r4, r3      ; r4 = 1 << n
xor r5, r5, r4      ; r5 ^= (1 << n)

; 计算2的幂次
li r4, 1
slw r4, r4, r3      ; r4 = 2^r3

; 除以2的幂次(无符号)
srw r4, r5, r3      ; r4 = r5 / (2^r3)

; 除以2的幂次(有符号)
sraw r4, r5, r3     ; r4 = r5 / (2^r3) (保持符号)
```

#### 内存对齐和优化

```asm
; 4字节对齐检查
andi. r4, r3, 3     ; 检查低2位
bne not_aligned     ; 如果不为0则未对齐

; 向上对齐到4字节边界
addi r3, r3, 3      ; r3 += 3
rlwinm r3, r3, 0, 0, 29  ; r3 &= ~3

; 向下对齐到4字节边界
rlwinm r3, r3, 0, 0, 29  ; r3 &= ~3

; 快速清零内存块
li r4, 0            ; 清零值
mr r5, r3           ; 保存起始地址
add r6, r3, r7      ; 计算结束地址
clear_loop:
    cmp 0, r5, r6   ; 比较当前地址和结束地址
    bge clear_end   ; 如果 >= 则结束
    stw r4, 0(r5)   ; 存储0
    addi r5, r5, 4  ; 递增地址
    b clear_loop
clear_end:
```

#### PowerPC特有操作

```asm
; 循环移位和掩码操作
rlwinm r3, r4, 8, 24, 31    ; 将r4循环左移8位，保留位24-31
rlwimi r3, r4, 16, 8, 15    ; 将r4循环左移16位，插入r3的位8-15

; 计数寄存器循环
li r3, 10           ; 循环次数
mtctr r3            ; 设置计数寄存器
count_loop:
    ; 循环体
    bdnz count_loop ; 递减CTR并跳转(如果CTR != 0)

; 条件寄存器操作
mfcr r3             ; 读取条件寄存器
rlwinm r4, r3, 4, 28, 31  ; 提取CR0字段
```

### PowerPC 特性

#### 固定点单元 vs 浮点单元

```asm
; 整数运算 (固定点单元)
add r3, r4, r5      ; 整数加法
mullw r3, r4, r5    ; 整数乘法

; 浮点运算 (浮点单元)
fadd f1, f2, f3     ; 浮点加法
fmul f1, f2, f3     ; 浮点乘法
```

#### 分支预测

```asm
; 分支很可能执行
bc 12, 2, likely_target     ; 使用BO=12表示很可能

; 分支不太可能执行
bc 4, 2, unlikely_target    ; 使用BO=4表示不太可能
```

#### 多种加载/存储变体

```asm
; 基本加载/存储
lwz r3, 0(r4)       ; 基本加载
stw r3, 0(r4)       ; 基本存储

; 索引加载/存储
lwzx r3, r4, r5     ; 索引加载 r3 = MEM[r4+r5]
stwx r3, r4, r5     ; 索引存储 MEM[r4+r5] = r3

; 更新加载/存储
lwzu r3, 4(r4)      ; 加载并更新 r3 = MEM[r4+4]; r4 += 4
stwu r3, 4(r4)      ; 存储并更新 MEM[r4+4] = r3; r4 += 4

; 索引更新加载/存储
lwzux r3, r4, r5    ; 索引加载并更新 r3 = MEM[r4+r5]; r4 += r5
stwux r3, r4, r5    ; 索引存储并更新 MEM[r4+r5] = r3; r4 += r5
```

这些编程模式涵盖了PowerPC汇编中最常用的结构和技巧，包括PowerPC架构特有的循环移位、条件寄存器操作和多样化的寻址模式，可以作为编写PowerPC汇编程序的参考模板。

### 伪指令与展开

| 伪指令 | 展开 | 说明 |
|--------|------|------|
| li rD,IMM | addi rD,r0,IMM | 16位有符号立即数装载；大常量需 lis/ori 组合 |
| lis rD,IMM | addis rD,r0,IMM | 载入高 16 位 (IMM<<16) |
| mr rD,rS | or rD,rS,rS | 自拷贝实现寄存器移动 |
| sub rD,rA,rB | subf rD,rB,rA | 语义 rD=rA-rB |
| subi rD,rA,IMM | addi rD,rA,-IMM | 立即数取负实现减法 |
| nop | ori 0,0,0 | 空操作 |

### 系统调用错误快速判断

执行 sc 后：

1. CR0.SO 未置位表示成功，`r3` 为返回值。
2. CR0.SO 置位表示失败，`r3` 通常是正 errno。
3. glibc/musl 封装会把它转换为通用的 `-1`/`errno` 语义；手写 shellcode 或裸 `sc` 后不要照搬“负返回值”判断。

### 常见调试寄存器检查片段

```asm
sc              ; 发起系统调用
bso  handle_err ; CR0.SO 置位则错误
; 成功路径...
handle_err:
mr   r4,r3      ; r4 = errno 值
```

### 参考资料

* Power Architecture 32-bit / 64-bit ELF ABI
* Linux kernel arch/powerpc/include/uapi/asm/unistd.h
* IBM Power ISA v3.x Reference
* GCC Inline Assembly for PowerPC 文档
* ELFv2 ABI Supplement
