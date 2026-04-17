# ptmalloc 源码阅读笔记

## 页面入口

- [入门：先建立 ptmalloc 整体模型](source-reading-00-heap-model.md)
- [精读 1：`malloc` 入口、初始化与 tcache 建立](source-reading-01-malloc-init.md)
- [精读 2：`_int_malloc` 主分配路径](source-reading-02-int-malloc.md)
- [精读 3：`free`、合并与 trim 路径](source-reading-03-free-trim.md)

## 阅读顺序

1. 如果是第一次接触 ptmalloc，先看“入门：先建立 ptmalloc 整体模型”，先把 `chunk`、`bin`、`top chunk`、`mmap chunk` 和分配/释放主线串起来。
2. 再看“精读 1”，把 `malloc` 入口、初始化和 tcache 建立串起来。
3. 接着看“精读 2”，沿着 `_int_malloc` 的主流程理解各个 bin 与 top chunk 的分配顺序。
4. 最后看“精读 3”，把 `free`、合并、unsorted bin、trim 整体闭环起来。

## 阅读方式

统一采用同一种节奏：

- 先进入某条主线或分支。
- 再看“主体源码与执行流程”，顺着判断分支往下读。
- 如果碰到陌生结构或宏，再切到同一节里的“定义与宏”选项卡。

这样读的时候，主流程会一直连着，不会被前置的大段宏定义打断；需要补细节时，也不用滚很远去找定义。

## 版本说明

!!! note
    本文以 `glibc 2.35` 为主线，正文里的分析、注释和分支顺序都以这个版本为准。
