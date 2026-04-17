# Pwn

Pwn 方向通常围绕二进制程序的分析、利用与防护展开，常见主题包括栈溢出、堆利用、程序装载与链接机制、保护机制绕过等。

## 目录

### 环境准备

- [如何优雅地配置 pwn 环境](environment/pwn_environment.md)

### 栈溢出

- [[Ret2csu]为什么是神？](Ret2csu/Ret2csu.md)
- [[Ret2dlresolve]迈出阅读 Glibc 源码的第一步](Ret2dlresolve/Ret2dlresolve.md)
- [[Ret2gets]不靠 `pop rdi; ret` 也能控制 `rdi`](Ret2gets/Ret2gets.md)

### 堆与 ptmalloc

- [ptmalloc 源码阅读笔记（目录）](ptmalloc_source_code_glibc-2.35/source-reading-index.md)
- [入门：先建立 ptmalloc 的整体模型](ptmalloc_source_code_glibc-2.35/source-reading-00-heap-model.md)
- [精读 1：`malloc` 入口、初始化与 tcache 建立](ptmalloc_source_code_glibc-2.35/source-reading-01-malloc-init.md)
- [精读 2：`_int_malloc` 主分配路径](ptmalloc_source_code_glibc-2.35/source-reading-02-int-malloc.md)
- [精读 3：`free`、合并与 trim 路径](ptmalloc_source_code_glibc-2.35/source-reading-03-free-trim.md)
