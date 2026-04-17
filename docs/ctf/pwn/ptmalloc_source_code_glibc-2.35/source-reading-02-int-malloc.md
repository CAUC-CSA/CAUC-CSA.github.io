# `_int_malloc` 主分配路径

这一页最长，也最容易在各种 bin 之间读乱。建议先看每个分支的“主体源码与执行流程”，确认这一轮到底从哪个 bin 取块；如果碰到不熟的宏或结构，再切到“定义与宏”选项卡补看。

!!! tip "这一页怎么读"
    不要试图第一次就把 `_int_malloc` 全背下来。更好的方式是抓“本轮请求最终从哪里拿到 chunk”，再回头看它为什么会跳过前面的 bin。

### 主线2-从非tcache分配内存(\_int_malloc)

=== "主体源码与执行流程"

    由于 `_int_malloc` 分支很多，这里直接按“最终从哪里取到 chunk”来拆开分析。

    建议先把路径顺序记成下面这条主线：

    1. 先把用户请求规范化成内部大小 `nb`。
    2. 如果大小落在 fastbin 范围，先检查 fastbin。
    3. 如果是 small request，优先检查 smallbin。
    4. 接着处理 unsorted bin，并在这里完成大量中转与重分类。
    5. 对 large request，再看 largebin 和从更大 chunk 切割的路径。
    6. 前面都拿不到时，再落到 top chunk 和向系统继续申请空间。

    其中 top chunk 分配这里不再单独展开，因为它和前面为 `tcache_perthread_struct` 分配空间时走到的那条 top chunk 切割逻辑本质一致。

=== "定义与宏"

    这一节只是路线总览，没有额外需要补看的独立定义。

### 主线2->分支1-从fastbin分配(\_int_malloc)

=== "主体源码与执行流程"

    这一段真正要看清的只有三件事：

    1. 先判断 `nb` 是否落在 fastbin 范围内。
    2. 如果命中，就把 fastbin 头部的 chunk 摘下来。
    3. 如果启用了 tcache，还会顺手把同大小的其他 fastbin chunk 继续预填进 tcache。

    ``` c
    if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
      {
        idx = fastbin_index (nb);
        mfastbinptr *fb = &fastbin (av, idx);
        mchunkptr pp;
        victim = *fb;

        if (victim != NULL)
          {
            if (__glibc_unlikely (misaligned_chunk (victim)))
              malloc_printerr ("malloc(): unaligned fastbin chunk detected 2");

            if (SINGLE_THREAD_P)
              *fb = REVEAL_PTR (victim->fd);
            else
              REMOVE_FB (fb, pp, victim);

            if (__glibc_likely (victim != NULL))
              {
                size_t victim_idx = fastbin_index (chunksize (victim));
                if (__builtin_expect (victim_idx != idx, 0))
                  malloc_printerr ("malloc(): memory corruption (fast)");
                check_remalloced_chunk (av, victim, nb);

    #if USE_TCACHE
                /* While we're here, if we see other chunks of the same size,
                   stash them in the tcache.  */
                size_t tc_idx = csize2tidx (nb);
                if (tcache && tc_idx < mp_.tcache_bins)
                  {
                    mchunkptr tc_victim;

                    while (tcache->counts[tc_idx] < mp_.tcache_count
                           && (tc_victim = *fb) != NULL)
                      {
                        if (__glibc_unlikely (misaligned_chunk (tc_victim)))
                          malloc_printerr ("malloc(): unaligned fastbin chunk detected 3");
                        if (SINGLE_THREAD_P)
                          *fb = REVEAL_PTR (tc_victim->fd);
                        else
                          {
                            REMOVE_FB (fb, pp, tc_victim);
                            if (__glibc_unlikely (tc_victim == NULL))
                              break;
                          }
                        tcache_put (tc_victim, tc_idx);
                      }
                  }
    #endif
                void *p = chunk2mem (victim);
                alloc_perturb (p, bytes);
                return p;
              }
          }
      }
    ```

    这里可以把 fastbin 命中理解成“先从非常便宜的缓存层里直接拿一个能用的 chunk”。如果开启了 tcache，这一段还会顺手把同大小的 fastbin chunk 再搬一批到 tcache，减少后续同尺寸请求再次碰 fastbin 的机会。

=== "定义与宏"

    ``` c
    #define fastbin_index(sz) \
      ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
    #define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])
    #define PROTECT_PTR(pos, ptr) \
      ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
    #define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)

    #define REMOVE_FB(fb, victim, pp)			\
      do							\
        {							\
          victim = pp;					\
          if (victim == NULL)				\
            break;						\
          pp = REVEAL_PTR (victim->fd);                             \
          if (__glibc_unlikely (pp != NULL && misaligned_chunk (pp)))       \
            malloc_printerr ("malloc(): unaligned fastbin chunk detected"); \
        }							\
      while ((pp = catomic_compare_and_exchange_val_acq (fb, pp, victim)) \
             != victim)

    // 这段宏可以先把它理解成“带 CAS 的 fastbin 出链”。
    // 单线程时直接改 fastbin 头指针即可；多线程时需要确认这段时间里头指针没被别的线程改掉，
    // 所以这里循环做 compare-and-exchange，直到真正把 victim 从 fastbin 头部摘下来。

    static __always_inline void
    tcache_put (mchunkptr chunk, size_t tc_idx)
    {
      tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
    
      /* Mark this chunk as "in the tcache" so the test in _int_free will
         detect a double free.  */
      e->key = tcache_key;// 全局key检查doublefree
    
      e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);// 将当前chunk指针位移和下一个异或，保存到next
      tcache->entries[tc_idx] = e;
      ++(tcache->counts[tc_idx]);// 上限为7
    }
    ```

### 主线2->分支2-从smallbin分配(\_int_malloc)
!!! note "读这一段时先抓住结论"
    smallbin 的优势不是“复杂搜索”，而是“同一 bin 内大小完全一致”，所以这里一旦命中，基本就是直接摘链返回。

=== "主体源码与执行流程"

    ``` c
    static void *
    _int_malloc (mstate av, size_t bytes)
    {
      INTERNAL_SIZE_T nb;               /* 规范化的请求大小 */
      unsigned int idx;                 /* 关联的 bin 索引 */
      mbinptr bin;                      /* 关联的 bin */
    
      mchunkptr victim;                 /* 检查/选定的内存块 */
      INTERNAL_SIZE_T size;             /* 其大小 */
      int victim_index;                 /* 其 bin 索引 */
    
      mchunkptr remainder;              /* 分割后的剩余部分 */
      unsigned long remainder_size;     /* 其大小 */
    
      unsigned int block;               /* 位图遍历器 */
      unsigned int bit;                 /* 位图遍历器 */
      unsigned int map;                 /* binmap 的当前字 */
    
      mchunkptr fwd;                    /* 用于链接的杂项临时变量 */
      mchunkptr bck;                    /* 用于链接的杂项临时变量 */
    
    #if USE_TCACHE
      size_t tcache_unsorted_count;	    /* 已处理的未分类内存块数量 */
    #endif
    
      /*
         通过添加 SIZE_SZ 字节开销，并可能增加更多以获得必要的对齐和/或
         至少达到 MINSIZE（最小可分配大小），将请求大小转换为内部形式。
         此外，checked_request2size 函数会针对填充和对齐后环绕为零的
         过大请求大小返回 false。
       */
    
      if (!checked_request2size (bytes, &nb))
      {
        __set_errno (ENOMEM);
        return NULL;
      }
    
      /* 没有可用的arena。退回到 sysmalloc 从 mmap 获取一个内存块。 */
      if (__glibc_unlikely (av == NULL))
      {
        void *p = sysmalloc (nb, av);
        if (p != NULL)
          alloc_perturb (p, bytes);
        return p;
      }
    	......
      if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
      {
        ......
      }
    
      /*
         如果是一个小请求，检查常规 bin。由于这些“smallbins”每个只容纳一种大小，
         因此无需在 bin 内部搜索。(对于大请求，我们需要等到未分类的内存块处理完毕
         才能找到最匹配的。但对于小请求，匹配总是精确的，所以现在就可以检查，这会更快。)
       */
    
      if (in_smallbin_range (nb))// 如果fastbin和tcache没有则smallbin，范围0x20~0x3f0
      {
        idx = smallbin_index (nb);
        bin = bin_at (av, idx);
    
        if ((victim = last (bin)) != bin)// 获取bk，不是指向本身则存在对应smallbin，获取bk即最后一个堆块地址放入victim
        {
          bck = victim->bk;
          if (__glibc_unlikely (bck->fd != victim))// 保证再向后一个chunk指向victim
            malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;// 从尾部取出chunk
    
          if (av != &main_arena)
            set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
    #if USE_TCACHE
          /* 趁此机会，如果看到相同大小的其他内存块，则将其暂存到 tcache 中。 */
          size_t tc_idx = csize2tidx (nb);
          if (tcache && tc_idx < mp_.tcache_bins)
          {
            mchunkptr tc_victim;
    
            /* 当 bin 不为空且 tcache 未满时，复制内存块。 */
            while (tcache->counts[tc_idx] < mp_.tcache_count
                   && (tc_victim = last (bin)) != bin)// 典中典Tcache Stashing Unlink Attack
            {
              if (tc_victim != 0)
              {
                bck = tc_victim->bk;
                set_inuse_bit_at_offset (tc_victim, nb);
                if (av != &main_arena)
                  set_non_main_arena (tc_victim);
                bin->bk = bck;
                bck->fd = bin;
    
                tcache_put (tc_victim, tc_idx);
              }
            }
          }
    #endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
      }
    ......
    ```

=== "定义与宏"

    ``` c
    #define NBINS             128
    #define NSMALLBINS         64
    #define SMALLBIN_WIDTH    MALLOC_ALIGNMENT=16
    #define CHUNK_HDR_SZ (2 * SIZE_SZ)=16
    #define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > CHUNK_HDR_SZ)=0
    #define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)=(64-0)*16=0x400
    #define in_smallbin_range(sz)  \
      ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
    #define smallbin_index(sz) \
      ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
       + SMALLBIN_CORRECTION)

    #define first(b)     ((b)->fd)
    #define last(b)      ((b)->bk)
    ```
### 主线2->分支3-从unsortedbin分配&从比本身大的切割(\_int_malloc)
!!! tip "为什么 unsorted bin 这一段最值得反复读"
    因为大量 chunk 都不会在 free 之后立刻进入最终 bin，而是先经过 unsorted bin。也就是说，这里既在“尝试直接复用”，也在“把 chunk 重新分流到 smallbin / largebin”。

=== "主体源码与执行流程"

    ``` c
    // 进入这一段之前，先记住一个阅读目标：
    // 看清“从 unsorted bin 直接返回”、“把 chunk 重新分类进 bin”、
    // 以及“对 large request 从更大 chunk 上切割”这三种结果分别是怎么发生的。
    static void malloc_consolidate(mstate av)
    {
      mfastbinptr*    fb;                 /* 当前正在合并的 fastbin */
      mfastbinptr*    maxfb;              /* 最后一个 fastbin (用于循环控制) */
      mchunkptr       p;                  /* 当前正在合并的 chunk */
      mchunkptr       nextp;              /* 下一个要合并的 chunk */
      mchunkptr       unsorted_bin;       /* bin 头 */
      mchunkptr       first_unsorted;     /* 要链接的 chunk */
    
      /* 这些变量的用途与 free() 中相同 */
      mchunkptr       nextchunk;
      INTERNAL_SIZE_T size;
      INTERNAL_SIZE_T nextsize;
      INTERNAL_SIZE_T prevsize;
      int             nextinuse;
    
      atomic_store_relaxed (&av->have_fastchunks, false);// 全部fastchunk都会被取出，清理碎片内存，因此直接将其设为false
    
      unsorted_bin = unsorted_chunks(av);// 取出unsorted bin指针
    
      /*
        从 fast bin 中取出每个 chunk 并进行合并，然后将其放入 unsorted bin。
        这样做的一个原因是，将其放入 unsorted bin 可以避免在 malloc 确定 chunk 
        不会立即被重用之前计算实际的 bin。
      */
    
      maxfb = &fastbin (av, NFASTBINS - 1);
      fb = &fastbin (av, 0);
      do {
        p = atomic_exchange_acq (fb, NULL);// 一个CAS操作，该函数取出fb指针
        if (p != 0) {
          do {
            { 
              if (__glibc_unlikely (misaligned_chunk (p)))
                malloc_printerr ("malloc_consolidate(): "
                                 "unaligned fastbin chunk detected");
    
              unsigned int idx = fastbin_index (chunksize (p));
              if ((&fastbin (av, idx)) != fb)// 检查对齐和大小
                malloc_printerr ("malloc_consolidate(): invalid chunk size");
            }
    
            check_inuse_chunk(av, p);// 检查前后堆块释放使用是否正常
            nextp = REVEAL_PTR (p->fd);
    
            /* free() 中合并代码的简化版本 */
            size = chunksize (p);
            nextchunk = chunk_at_offset(p, size);// 通过p的size计算下个chunk的位置
            nextsize = chunksize(nextchunk);
    
            if (!prev_inuse(p)) {// 判断前一个chunk是否在用
              prevsize = prev_size (p);
              size += prevsize;
              p = chunk_at_offset(p, -((long) prevsize));// 将p指向上一个chunk
              if (__glibc_unlikely (chunksize(p) != prevsize))// prevsize是否与上一个chunksize相同
                malloc_printerr ("corrupted size vs. prev_size in fastbins");
              unlink_chunk (av, p);// 从链表中取出p
            }
    
            if (nextchunk != av->top) {// 如果下一个不是top则尝试unlink，如果是则直接覆盖了
              nextinuse = inuse_bit_at_offset(nextchunk, nextsize);// 从下一个chunk获取inuse位
    
              if (!nextinuse) {
                size += nextsize;// 如果不在用直接合并
                unlink_chunk (av, nextchunk);
              } else {
                clear_inuse_bit_at_offset(nextchunk, 0);// 如其名
              }
    
              first_unsorted = unsorted_bin->fd;
              unsorted_bin->fd = p;
              first_unsorted->bk = p;
    
              if (!in_smallbin_range (size)) {
                p->fd_nextsize = NULL;
                p->bk_nextsize = NULL;
              }
    
              set_head(p, size | PREV_INUSE);
              p->bk = unsorted_bin;
              p->fd = first_unsorted;// 上面这一块简单理解就是将新生成的chunk放到unsorted开头了
              set_foot(p, size);// 设置下一个chunk的privsize
            }
            else { /* nextchunk == av->top 的情况 */
              size += nextsize;
              set_head(p, size | PREV_INUSE);
              av->top = p;
            }
    
          } while ( (p = nextp) != 0); /* 内部 do-while 循环结束 */
    
        }
      } while (fb++ != maxfb); /* 外部 do-while 循环结束 */
    }
    ```

=== "定义与宏"

    ``` c
    #define largebin_index_32(sz)                                                \
      (((((unsigned long) (sz)) >> 6) <= 38) ?  56 + (((unsigned long) (sz)) >> 6) :\
       ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
       ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
       ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
       ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
       126)
    
    #define largebin_index_32_big(sz)                                            \
      (((((unsigned long) (sz)) >> 6) <= 45) ?  49 + (((unsigned long) (sz)) >> 6) :\
       ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
       ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
       ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
       ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
       126)
    
    // XXX It remains to be seen whether it is good to keep the widths of
    // XXX the buckets the same or whether it should be scaled by a factor
    // XXX of two as well.
    #define largebin_index_64(sz)                                                \
      (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
       ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
       ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
       ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
       ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
       126)
    
    #define largebin_index(sz) \
      (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
       : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
       : largebin_index_32 (sz))
       // 这里先把它理解成“把 large chunk 按大小区间映射到不同 bin”即可，
       // 不需要第一次阅读就把每个阈值背下来。
    
    #define mark_bin(m, i)    ((m)->binmap[idx2block (i)] |= idx2bit (i))
    
    #define next_bin(b)  ((mbinptr) ((char *) (b) + (sizeof (mchunkptr) << 1)))
    ```
    
    | 层（仅供快速建立区间感） | 条件判断          | 大小范围（字节）         | 步长     | Bin范围   | Bin数量 |
    | --------------- | ------------- | ---------------- | ------ | ------- | ----- |
    | 1               | sz/64 ≤ 48    | [1024, 3136)     | 64 B   | 64-96   | 33个   |
    | 2               | sz/512 ≤ 20   | [3136, 10752)    | 512 B  | 97-111  | 15个   |
    | 3               | sz/4096 ≤ 10  | [10752, 45056)   | 4 KB   | 112-120 | 9个    |
    | 4               | sz/32768 ≤ 4  | [45056, 163840)  | 32 KB  | 120-123 | 4个*   |
    | 5               | sz/262144 ≤ 2 | [163840, 786432) | 256 KB | 124-126 | 3个    |
    | 6               | 其他            | [786432, ∞)      | /      | 126     | 1个    |
    !!! note "这一段真正要观察的不是公式，而是行为"
        unsorted bin 这一轮处理完后，chunk 只有几种去向：精确命中直接返回、重分流进 smallbin 或 largebin、被更大的 chunk 切一块出来返回、或者最后继续走 top chunk / sysmalloc。

    #### 主体源码与执行流程 
    ``` c
    static void *
    _int_malloc (mstate av, size_t bytes)
    {
      INTERNAL_SIZE_T nb;               /* 规范化的请求大小 */
      unsigned int idx;                 /* 关联的 bin 索引 */
      mbinptr bin;                      /* 关联的 bin */
    
      mchunkptr victim;                 /* 检查/选定的内存块 */
      INTERNAL_SIZE_T size;             /* 其大小 */
      int victim_index;                 /* 其 bin 索引 */
    
      mchunkptr remainder;              /* 分割后的剩余部分 */
      unsigned long remainder_size;     /* 其大小 */
    
      unsigned int block;               /* 位图遍历器 */
      unsigned int bit;                 /* 位图遍历器 */
      unsigned int map;                 /* binmap 的当前字 */
    
      mchunkptr fwd;                    /* 用于链接的杂项临时变量 */
      mchunkptr bck;                    /* 用于链接的杂项临时变量 */
    
    #if USE_TCACHE
      size_t tcache_unsorted_count;	    /* 已处理的未分类内存块数量 */
    #endif
    
      if (!checked_request2size (bytes, &nb))
      {
        __set_errno (ENOMEM);
        return NULL;
      }
    
      /* 没有可用的竞技场。退回到 sysmalloc 从 mmap 获取一个内存块。 */
      if (__glibc_unlikely (av == NULL))
      {
        void *p = sysmalloc (nb, av);
        if (p != NULL)
          alloc_perturb (p, bytes);
        return p;
      }
    
      if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
      {
       ......
      }
    
      if (in_smallbin_range (nb))// 这里需考虑两个分支，一个是smallbin大小，一个是largebin大小
      {
       ......// smallbin无对应空闲跳过
      else
      { // 该次请求超过smallbin_max则进入该条件
        idx = largebin_index (nb);// 获取nb对应的largebin-idx
        if (atomic_load_relaxed (&av->have_fastchunks))// 判断是否有fastbin，有则进入小分支1尝试将其合并
          malloc_consolidate (av);// 小分支1-将fastbin合并(malloc_consolidate)
      }
    
      /*
         处理最近释放或剩余的内存块，只有在精确匹配时才取走一个；
         或者，如果这是一个小请求，则该内存块是最近一次非精确匹配的剩余部分。
         将其他遍历到的内存块放入 bin 中。请注意，这里是 malloc 路径里非常关键的“重新分类”位置：
         许多 chunk 正是在这一段里从 unsorted bin 被重新挂回 smallbin 或 largebin。
    
         这里的外部循环是必要的，因为我们可能直到 malloc 接近结束时才意识到
         应该进行合并，因此必须合并并重试。这最多发生一次，并且只在我们否则
         需要扩展内存来服务“小”请求时发生。
       */
    
    #if USE_TCACHE
      INTERNAL_SIZE_T tcache_nb = 0;
      size_t tc_idx = csize2tidx (nb);
      if (tcache && tc_idx < mp_.tcache_bins)
        tcache_nb = nb;
      int return_cached = 0;
    
      tcache_unsorted_count = 0;
    #endif
    
      for (;; )
      {
        int iters = 0;
        while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {// 从 unsorted bin 尾部开始拿 chunk。这里的重点不是“为什么从尾部”，而是“每拿出一个都要先判断能否立刻复用，否则再决定它该被重新分到哪里”。
          bck = victim->bk;
          size = chunksize (victim);
          mchunkptr next = chunk_at_offset (victim, size);// 获取相邻的下一个chunk
    
          if (__glibc_unlikely (size <= CHUNK_HDR_SZ)
              || __glibc_unlikely (size > av->system_mem))
            malloc_printerr ("malloc(): invalid size (unsorted)");
          if (__glibc_unlikely (chunksize_nomask (next) < CHUNK_HDR_SZ)
              || __glibc_unlikely (chunksize_nomask (next) > av->system_mem))
            malloc_printerr ("malloc(): invalid next size (unsorted)");
          if (__glibc_unlikely ((prev_size (next) & ~(SIZE_BITS)) != size))
            malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
          if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
          if (__glibc_unlikely (prev_inuse (next)))
            malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
    
          /*
             如果是一个小请求，并且该内存块是unsorted bin 中唯一的内存块，
             则尝试使用上一个剩余内存块。这有助于促进连续小请求的局部性。
             这是最佳匹配的唯一例外，并且仅适用于当小内存块没有精确匹配时。
           */
    
          if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
          {// 只有 unsorted bin 里只剩这一块、它正好还是 last_remainder、并且当前请求是 small request 时，glibc 才会优先继续从这块 remainder 上切。
            /* 分割并重新连接剩余部分 */
            remainder_size = size - nb;
            remainder = chunk_at_offset (victim, nb);
            unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
            av->last_remainder = remainder;
            remainder->bk = remainder->fd = unsorted_chunks (av);
            if (!in_smallbin_range (remainder_size))
            {
              remainder->fd_nextsize = NULL;
              remainder->bk_nextsize = NULL;
            }
    
            set_head (victim, nb | PREV_INUSE |
                      (av != &main_arena ? NON_MAIN_ARENA : 0));
            set_head (remainder, remainder_size | PREV_INUSE);
            set_foot (remainder, remainder_size);
    
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
    
          /* 从 unsorted bin 中移除。走到这里说明它要么不是精确匹配，要么没触发上面的 last_remainder 特判。 */
          if (__glibc_unlikely (bck->fd != victim))
            malloc_printerr ("malloc(): corrupted unsorted chunks 3");
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
    
          /* 如果精确匹配，直接返回，而不是再把它分流进别的 bin。 */
          if (size == nb)
          {
            set_inuse_bit_at_offset (victim, size);
            if (av != &main_arena)
              set_non_main_arena (victim);
    #if USE_TCACHE
            /* 首先填充缓存，仅当缓存已满时才返回给用户。
               我们可能稍后返回其中一个内存块。 */
            if (tcache_nb
                && tcache->counts[tc_idx] < mp_.tcache_count)
            {
              tcache_put (victim, tc_idx);
              return_cached = 1;
              continue;
            }
            else
            {
    #endif
    	        check_malloced_chunk (av, victim, nb);
    	        void *p = chunk2mem (victim);
    	        alloc_perturb (p, bytes);
    	        return p;
    #if USE_TCACHE
            }
    #endif
          }
    
          /* 走到这里就不再是“立刻可用”的块了，而是要把它重新分类进 smallbin 或 largebin。 */
    
          if (in_smallbin_range (size))
          {
            victim_index = smallbin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;// 获取bin头部空闲chunk
          }
          else
          {
            victim_index = largebin_index (size);
            bck = bin_at (av, victim_index);
            fwd = bck->fd;
    
            /* largebin 不只是双链表，还要尽量维持按大小的有序关系。 */
            if (fwd != bck)// 判断该bin是否有chunk，有则进入下面，否则进入else
            {
              /* 或与 inuse 位进行按位或操作以加速比较 */
              size |= PREV_INUSE;
              /* 如果小于最小的，跳过下面的循环 */
              assert (chunk_main_arena (bck->bk));
              if ((unsigned long) (size)
                  < (unsigned long) chunksize_nomask (bck->bk))// 当前 chunk 比这个 largebin 里最小的还小，就直接插到“最小值那一侧”
              {
    	          // 这里之所以要绕过 arena 上那个伪造的 bin 头，是因为它本身并不是正常的 large chunk，也没有 nextsize 这套语义。
                fwd = bck;
                bck = bck->bk;
    
                victim->fd_nextsize = fwd->fd;
                victim->bk_nextsize = fwd->fd->bk_nextsize;
                fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                // 这也是 largebin attack 常被关注的代码位置之一：核心点不是死记利用细节，
                // 而是看懂“当前 chunk 被插入 largebin 时，会改写哪些 nextsize 指针”。
              }
              else
              {
                assert (chunk_main_arena (fwd));
                while ((unsigned long) size < chunksize_nomask (fwd))// 沿 nextsize 链继续找，直到找到不再比当前 chunk 大的位置
                {
                  fwd = fwd->fd_nextsize;
                  assert (chunk_main_arena (fwd));
                }
    
                if ((unsigned long) size
                    == (unsigned long) chunksize_nomask (fwd))
                  /* 始终插入到第二个位置。 */
                  fwd = fwd->fd;// 如果碰到同样大小，则尽量插到第二个位置，避免总是动到这一大小的第一个条目
                else
                {
                  victim->fd_nextsize = fwd;
                  victim->bk_nextsize = fwd->bk_nextsize;
                  if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                    malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                  fwd->bk_nextsize = victim;
                  victim->bk_nextsize->fd_nextsize = victim;
                }
                bck = fwd->bk;
                if (bck->fd != fwd)
                  malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
              }
            }
            else
              victim->fd_nextsize = victim->bk_nextsize = victim;// 仅有一个即将放入的则让fd_nextsize、bk_nextsize都指向自己
          }
    
          mark_bin (av, victim_index);// 重新分类完成后，别忘了同步更新 binmap
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;// 将unsorted 放入指定bin的头部
    
    #if USE_TCACHE
          /* 如果我们在填充缓存时已经处理了允许的最大数量的内存块，则返回其中一个缓存的内存块。 */
          ++tcache_unsorted_count;
          if (return_cached
              && mp_.tcache_unsorted_limit > 0
              && tcache_unsorted_count > mp_.tcache_unsorted_limit)// 正常情况下tcache_unsorted_limit = 0，即没有限制
          {
            return tcache_get (tc_idx);
          }
    #endif
    
    #define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)// 设置循环上限防止一次malloc时间太久
            break;
        }
    
    #if USE_TCACHE
        /* 如果我们找到的所有小内存块最终都被缓存了，现在就返回一个。 */
        if (return_cached)
        {
          return tcache_get (tc_idx);// 返回被放入tcache相同大小的chunk
        }
    #endif
    
        /*
           如果是一个大请求，按排序顺序扫描当前 bin 中的内存块，
           以找到最小的合适块。为此使用跳表。
         */
    
        if (!in_smallbin_range (nb))// 如果是largebin大小则先尝试从largebin中查找
        {
          bin = bin_at (av, idx);
    
          /* 如果对应idx的bins下为空或最大内存块太小，则跳过扫描 */
          if ((victim = first (bin)) != bin
              && (unsigned long) chunksize_nomask (victim)
                >= (unsigned long) (nb))
          {
            victim = victim->bk_nextsize;// 如果比最大内存块小，则从小到大查找合适的位置
            while (((unsigned long) (size = chunksize (victim)) <
                    (unsigned long) (nb)))
              victim = victim->bk_nextsize;
    
            /* 避免移除某个大小的第一个条目，这样跳表就不必重新路由。 */
            if (victim != last (bin)
                && chunksize_nomask (victim)
                  == chunksize_nomask (victim->fd))
              victim = victim->fd;// 尽可能取第二个条目
    
            remainder_size = size - nb;// 计算剩下的chunk大小
            unlink_chunk (av, victim);// 移除chunk
    
            /* 耗尽 */
            if (remainder_size < MINSIZE)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                set_non_main_arena (victim);
            }
            /* 分割 */
            else
            { // 没耗尽的情况下，放入unsortedbin
              remainder = chunk_at_offset (victim, nb);
              /* 我们不能假设未分类列表是空的，因此必须在这里执行完全插入操作。 */
              bck = unsorted_chunks (av);// 将剩下的chunk放入头部
              fwd = bck->fd;
              if (__glibc_unlikely (fwd->bk != bck))
                malloc_printerr ("malloc(): corrupted unsorted chunks");
              remainder->bk = bck;
              remainder->fd = fwd;
              bck->fd = remainder;
              fwd->bk = remainder;
              if (!in_smallbin_range (remainder_size))
              {
                remainder->fd_nextsize = NULL;
                remainder->bk_nextsize = NULL;
              }
              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);
            }
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
        }
    
        /*
           通过扫描 bin 来搜索内存块，从下一个最大的 bin 开始。
           此搜索严格遵循最佳匹配原则；即，选择最小的（如果有多个相同大小的，
           则选择大约最近最少使用的）合适内存块。
           位图避免了检查大多数块是否为空的需要。
           在没有内存块返回的预热阶段跳过所有 bin 的特定情况比看起来要快。
         */
    
        ++idx;
        bin = bin_at (av, idx);
        block = idx2block (idx);
        map = av->binmap[block];
        bit = idx2bit (idx);// 这一块在申请tcache结构体时提到过，map是uint类型则每个map代表32位，通过idx找到bit，对应的bit位置1
    
        for (;; )
        {
          /* 如果此块中没有更多设置位，则跳过块的其余部分。 */
          if (bit > map || bit == 0)
          {
            do
            {
              if (++block >= BINMAPSIZE) /* 超出 bin 范围 */
                goto use_top;
            }
            while ((map = av->binmap[block]) == 0);
    
            bin = bin_at (av, (block << BINMAPSHIFT));
            bit = 1;
          }
    
          /* 前进到带有设置位的 bin。必须有一个。 */
          while ((bit & map) == 0)
          {
            bin = next_bin (bin);// 获取下一个bin，本质就是64位下+0x10
            bit <<= 1;
            assert (bit != 0);
          }// 循环直到找到对应bit不为0的bin
    
          /* 检查 bin。它很可能不为空。 */
          victim = last (bin);
    
          /* 如果是误报（空 bin），清除该位。 */
          if (victim == bin)
          {
            av->binmap[block] = map &= ~bit; /* 直写 */
            bin = next_bin (bin);
            bit <<= 1;
          }
    
          else
          {
            size = chunksize (victim);
    
            /* 我们知道这个 bin 中的第一个内存块足够大，可以使用。 */
            assert ((unsigned long) (size) >= (unsigned long) (nb));
    
            remainder_size = size - nb;
    
            /* 解除链接 */
            unlink_chunk (av, victim);
    
            /* 耗尽 */
            if (remainder_size < MINSIZE)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                set_non_main_arena (victim);
            }
    
            /* 分割 */
            else
            {
              remainder = chunk_at_offset (victim, nb);
    
              /* 我们不能假设未分类列表是空的，因此必须在这里执行完全插入操作。 */
              bck = unsorted_chunks (av);
              fwd = bck->fd;
              if (__glibc_unlikely (fwd->bk != bck))
                malloc_printerr ("malloc(): corrupted unsorted chunks 2");
              remainder->bk = bck;
              remainder->fd = fwd;
              bck->fd = remainder;
              fwd->bk = remainder;
    
              /* 声明为最后一个剩余块 */
              if (in_smallbin_range (nb))
                av->last_remainder = remainder;
              if (!in_smallbin_range (remainder_size))
              {
                remainder->fd_nextsize = NULL;
                remainder->bk_nextsize = NULL;
              }
              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);
            }
            check_malloced_chunk (av, victim, nb);
            void *p = chunk2mem (victim);
            alloc_perturb (p, bytes);
            return p;
          }
        }
    
        ......
      }
    }
    ```
    ### 分支3->小分支1-将fastbin合并(malloc_consolidate)
    #### 相关定义与宏
    ``` c
    /* Take a chunk off a bin list.  */ /* 从 bin 列表中取出一个 chunk。*/
    static void
    unlink_chunk (mstate av, mchunkptr p)
    {
      if (chunksize (p) != prev_size (next_chunk (p)))
        malloc_printerr ("corrupted size vs. prev_size"); /* 损坏的 size 与 prev_size 不匹配 */
    
      mchunkptr fd = p->fd;
      mchunkptr bk = p->bk;
    
      if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
        malloc_printerr ("corrupted double-linked list"); /* 损坏的双向链表 */
    
      fd->bk = bk;
      bk->fd = fd;
      if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
        {
          if (p->fd_nextsize->bk_nextsize != p
    	  || p->bk_nextsize->fd_nextsize != p)
    	malloc_printerr ("corrupted double-linked list (not small)"); /* 损坏的双向链表（非 small bin） */
    
          if (fd->fd_nextsize == NULL) /* 如果 fd 没有 nextsize 链表 */
    	{
    	  if (p->fd_nextsize == p) /* 如果 p 是其 nextsize 链表中的唯一元素 */
    	    fd->fd_nextsize = fd->bk_nextsize = fd;
    	  else /* 将 p 的 nextsize 链表转移到 fd */
    	    {
    	      fd->fd_nextsize = p->fd_nextsize;
    	      fd->bk_nextsize = p->bk_nextsize;
    	      p->fd_nextsize->bk_nextsize = fd;
    	      p->bk_nextsize->fd_nextsize = fd;
    	    }
    	}
          else /* 如果 fd 已经有 nextsize 链表，则从 p 的 nextsize 链表中移除 p */
    	{
    	  p->fd_nextsize->bk_nextsize = p->bk_nextsize;
    	  p->bk_nextsize->fd_nextsize = p->fd_nextsize;
    	}
        }
    }
    
    #define inuse_bit_at_offset(p, s)					      \
      (((mchunkptr) (((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)
    #define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->mchunk_prev_size = (s))
    ```
### 主线2->分支4-从mmap分配(\_int_malloc)
=== "主体源码与执行流程"

    ``` c
    static void *
    _int_malloc (mstate av, size_t bytes)
    {
    	...... // mmap申请阈值是0x20000大于该值则直接跳转use_top
        use_top:
    	   ......
          if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
          {
    	      ......
          }
          else if (atomic_load_relaxed (&av->have_fastchunks))
          {
    	      ......// 即便进入该条件，也会因大小不够，在下一次循环进入else
          }
          else
          {
            void *p = sysmalloc (nb, av);// 如果内存不够，即top_chunk不够，尝试系统调用
            if (p != NULL)
            {
              alloc_perturb (p, bytes);
            }
            return p;
          }
    }
    }
    ```

    上面这段只是把控制流引到 `sysmalloc(nb, av)`；真正决定走 `mmap`、`grow_heap`、`new_heap` 还是 `MORECORE(sbrk)` 的主逻辑在下面这段。

    ``` c
    static void *
    sysmalloc (INTERNAL_SIZE_T nb, mstate av)
    {
      mchunkptr old_top;              /* av->top 的传入值 */
      INTERNAL_SIZE_T old_size;       /* 其大小 */
      char *old_end;                  /* 其结束地址 */

      long size;                      /* 第一次 MORECORE 或 mmap 调用的参数 */
      char *brk;                      /* MORECORE 的返回值 */

      long correction;                /* 第二次 MORECORE 调用的参数 */
      char *snd_brk;                  /* 第二个返回值 */

      INTERNAL_SIZE_T front_misalign; /* 新空间前端不可用的字节 */
      INTERNAL_SIZE_T end_misalign;   /* 新空间末尾剩余的部分页面 */
      char *aligned_brk;              /* 对齐到 brk 的偏移量 */

      mchunkptr p;                    /* 已分配/返回的内存块 (chunk) */
      mchunkptr remainder;            /* 分配后的剩余部分 */
      unsigned long remainder_size;   /* 其大小 */


      size_t pagesize = GLRO (dl_pagesize);
      bool tried_mmap = false;


      /*
         如果支持 mmap，且请求大小达到 mmap 阈值，
         且系统支持 mmap，且当前分配的 mmapped 区域足够少，
         则尝试直接映射此请求，而不是扩展 top。
       */

      if (av == NULL
          || ((unsigned long) (nb) >= (unsigned long) (mp_.mmap_threshold)
              && (mp_.n_mmaps < mp_.n_mmaps_max))) // 使用mmap的阈值mmap_threshold默认为(128*1024)=0x20000，使用mmap的次数n_mmaps_max默认为65536
                                                    // 申请大于0x20000，进入该分支
        {
          char *mm;
    #if HAVE_TUNABLES
          if (mp_.hp_pagesize > 0 && nb >= mp_.hp_pagesize)
            {
              // huge page正常情况下为0关闭，可以通过内核设置开启

              /* 如果直接使用大页 (Huge Pages)，则无需发出 THP madvise 调用。 */
              mm = sysmalloc_mmap (nb, mp_.hp_pagesize, mp_.hp_flags, av);
              if (mm != MAP_FAILED)
                return mm;
            }
    #endif
          mm = sysmalloc_mmap (nb, pagesize, 0, av); // 跳转 分支4->小分支1
          if (mm != MAP_FAILED)
            return mm;
          tried_mmap = true;
        }

      /* 没有可用的 arena 且 mmap 也失败了。 */
      if (av == NULL)
        return 0;

      /* 记录 top 的传入配置 */
      // 进入另一种情况，申请大小没超过从mmap申请的阈值，而是top_chunk不够用了
      old_top = av->top;
      old_size = chunksize (old_top);
      old_end = (char *) (chunk_at_offset (old_top, old_size));

      brk = snd_brk = (char *) (MORECORE_FAILURE); // MORECORE_FAILURE为-1

      /*
         如果不是第一次执行，我们要求 old_size 至少为 MINSIZE，
         并且设置 prev_inuse 标志。
       */

      assert ((old_top == initial_top (av) && old_size == 0)
              || ((unsigned long) (old_size) >= MINSIZE
                  && prev_inuse (old_top)
                  && ((unsigned long) old_end & (pagesize - 1)) == 0));

      /* 前提条件：当前空间不足以满足 nb 请求 */
      assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));


      if (av != &main_arena) // 多线程情况下，当前arena不是main_arena情况下
        {
          heap_info *old_heap, *heap;
          size_t old_heap_size;

          /* 首先尝试扩展当前堆。*/
          old_heap = heap_for_ptr (old_top); // 获取起始地址，这里直接指向了heap_info，之前没分析过线程的arena相关分配，这里可以猜测是通过mmap分配一个大块的内存，同时将heap_info结构体放在大块的头部，具体可以进一步细看_int_new_arena 函数，同时线程arena也是紧跟在heap_info之后的
          old_heap_size = old_heap->size;
          if ((long) (MINSIZE + nb - old_size) > 0 // 如果所求信息比剩下的大，尝试增长内存
              && grow_heap (old_heap, MINSIZE + nb - old_size) == 0)
            {
              av->system_mem += old_heap->size - old_heap_size;
              set_head (old_top,
                        (((char *) old_heap + old_heap->size) - (char *) old_top)
                        | PREV_INUSE);
            } // 如果没法进一步增长则分配新的64mb大块
          else if ((heap = new_heap (nb + (MINSIZE + sizeof (*heap)), mp_.top_pad))) // 分支4->小分支2-新建线程大块heap(new_heap)
            {
              /* 使用新分配的堆。*/
              heap->ar_ptr = av;
              heap->prev = old_heap;
              av->system_mem += heap->size;

              /* 设置新的 top。*/
              top (av) = chunk_at_offset (heap, sizeof (*heap));
              set_head (top (av),
                        (heap->size - sizeof (*heap)) | PREV_INUSE);

              /* 设置 fencepost (边界标识) 并释放旧的 top 内存块 (chunk)，其大小为 MALLOC_ALIGNMENT 的倍数。*/
              /* fencepost 至少占用 MINSIZE 字节，因为它稍后可能会再次成为 top 内存块。
                 请注意，即使内存块被标记为已使用，也会设置一个 footer (尾部信息)。*/
              // fencepost的功能可以理解为当两个大块的heap在地址空间连续时，防止跨堆合并导致内存错乱
              old_size = (old_size - MINSIZE) & ~MALLOC_ALIGN_MASK;
              set_head (chunk_at_offset (old_top, old_size + CHUNK_HDR_SZ),
                        0 | PREV_INUSE); // 这里得多预留一个fencepost的空间
              if (old_size >= MINSIZE) // 减去fencepost的空间判断是否有MINSIZE大小
                {
                  // 大于MINSIZE则设置fencepost，以及将剩余的堆块释放
                  set_head (chunk_at_offset (old_top, old_size),
                            CHUNK_HDR_SZ | PREV_INUSE);
                  set_foot (chunk_at_offset (old_top, old_size), CHUNK_HDR_SZ);
                  set_head (old_top,
                            old_size | PREV_INUSE | NON_MAIN_ARENA);
                  _int_free (av, old_top, 1); // 后续分析free相关再说
                }
              else
                {
                  // 小于则将整个都设置为fencepost
                  set_head (old_top,
                            (old_size + CHUNK_HDR_SZ) | PREV_INUSE);
                  set_foot (old_top, (old_size + CHUNK_HDR_SZ));
                }
            }
          else if (!tried_mmap)
            {
              /* 我们至少可以尝试使用 mmap 内存。如果 new_heap 失败，
                 那么尝试分配大页 (huge pages) 也不太可能成功。*/
              char *mm = sysmalloc_mmap (nb, pagesize, 0, av);
              if (mm != MAP_FAILED)
                return mm;
            }
        }
      else                       /* av 等于 main_arena */
        {
          /* 请求足够大的空间，包括 nb + 填充 + 开销 */
          size = nb + mp_.top_pad + MINSIZE;

          /*
             如果是连续的，我们可以减去希望与新空间合并的现有空间。
             只有当我们实际上没有获得连续空间时，稍后才会将其加回来。
           */

          if (contiguous (av)) // 当前arena是否是连续内存，正常情况下为真（sbrk管理的传统堆）
            size -= old_size; // 空间连续则topchunk和后续新申请的空间将会连续

          /*
             向上取整到页大小或大页 (huge page) 大小的倍数。
             如果 MORECORE 不是连续的，这确保我们只用整页参数调用它。
             如果 MORECORE 是连续的且这不是第一次执行，这会保留之前调用的页对齐。
             否则，我们将在下面校正为页对齐。
           */

    #if HAVE_TUNABLES && defined (MADV_HUGEPAGE)
          /* 在 brk.c 中定义。*/
          extern void *__curbrk;
          if (__glibc_unlikely (mp_.thp_pagesize != 0)) // 默认为0，跳过
            {
              uintptr_t top = ALIGN_UP ((uintptr_t) __curbrk + size,
                                        mp_.thp_pagesize);
              size = top - (uintptr_t) __curbrk;
            }
          else
    #endif
            size = ALIGN_UP (size, GLRO (dl_pagesize)); // 向上对齐0x1000

          /*
             如果参数过大以致看起来为负，不要尝试调用 MORECORE。
             请注意，由于 mmap 接受 size_t 参数，即使我们无法调用 MORECORE，
             它也可能在下面成功。
           */

          if (size > 0)
            {
              brk = (char *) (MORECORE (size)); // MORECORE指向sbrk函数，即通过sbrk申请内容
              // 具体sbrk内容不进一步深入简而言之内核为每个进程维护一个program break（brk），指向数据段的结束地址，也就是堆的当前顶部。sbrk的作用就是将这个边界向后移动一定字节，从而扩大或缩小堆的虚拟地址空间。
              if (brk != (char *) (MORECORE_FAILURE)) // brk成功
                madvise_thp (brk, size); // 对扩展的内存区域建议内核使用透明大页（如果支持）

              LIBC_PROBE (memory_sbrk_more, 2, brk, size);
            }

          if (brk == (char *) (MORECORE_FAILURE)) // brk失败
            {
              /*
                 如果支持 mmap，当 MORECORE 失败或无法使用时，尝试将其作为备用。
                 这对于在地址空间中存在“洞”的系统来说是值得的，因为 sbrk 无法扩展以提供连续空间，
                 但空间在其他地方可用。请注意，我们忽略 mmap 的最大数量和阈值限制，
                 因为该空间不会用作独立的 mmap 区域。
               */

              char *mbrk = MAP_FAILED;
    #if HAVE_TUNABLES
              if (mp_.hp_pagesize > 0)
                mbrk = sysmalloc_mmap_fallback (&size, nb, old_size,
                                                mp_.hp_pagesize,
                                                mp_.hp_pagesize,
                                                mp_.hp_flags, av);
    #endif
              if (mbrk == MAP_FAILED)
                mbrk = sysmalloc_mmap_fallback (&size, nb, old_size,
                                                pagesize,
                                                MMAP_AS_MORECORE_SIZE,
                                                0, av);
              if (mbrk != MAP_FAILED)
                {
                  /* 我们不需要也无法使用另一个 sbrk 调用来查找结束地址 */
                  brk = mbrk;
                  snd_brk = brk + size;
                }
            }

          if (brk != (char *) (MORECORE_FAILURE))
            {
              if (mp_.sbrk_base == 0) // 这里应该是涉及到第一次执行brk相关
                mp_.sbrk_base = brk;
              av->system_mem += size;

              /*
                 如果 MORECORE 扩展了之前的空间，我们同样可以扩展 top 的大小。
               */

              if (brk == old_end && snd_brk == (char *) (MORECORE_FAILURE)) // 这里可以发现snd_brk可以认为是种标志，成功通过sbrk扩展则其还是MORECORE_FAILURE正常进入该条件，如果是通过mmap扩展其会被赋值
                set_head (old_top, (size + old_size) | PREV_INUSE);

              else if (contiguous (av) && old_size && brk < old_end)
                /* 糟糕！有人破坏了我们的空间……不能再动它了。*/
                malloc_printerr ("break adjusted to free malloc space");

              /*
                 否则，进行调整：

               * 如果是第一次执行或非连续情况，我们需要调用 sbrk 只是为了找出内存的结束位置。

               * 我们需要确保从 malloc 返回的所有内存块 (chunk) 都满足 MALLOC_ALIGNMENT。

               * 如果存在一个外部的 sbrk 调用，我们需要调整 sbrk 请求的大小，
                  以考虑我们无法将新空间与 old_top 中的现有空间合并的事实。

               * 几乎所有系统都一次性内部分配整个页面，在这种情况下，我们不妨使用请求的整个最后一页。
                  因此，我们现在分配足够的额外内存以达到页面边界，
                  这反过来会导致未来的连续调用也进行页面对齐。
               */

              else
                {
                ...... // 由于使用mmap分配概率极小，这一块基本不可能进，直接跳过（我是懒狗
            }
        } /* if (av != &main_arena) */

      if ((unsigned long) av->system_mem > (unsigned long) (av->max_system_mem))
        av->max_system_mem = av->system_mem;
      check_malloc_state (av);

      /* 最后，执行分配 */
      p = av->top;
      size = chunksize (p);

      /* 检查上述分配路径之一是否成功 */
      if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
        {
          remainder_size = size - nb;
          remainder = chunk_at_offset (p, nb);
          av->top = remainder;
          set_head (p,
                    nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
          set_head (remainder, remainder_size | PREV_INUSE);
          check_malloced_chunk (av, p, nb);
          return chunk2mem (p);
        }

      /* 捕获所有失败路径 */
      __set_errno (ENOMEM);
      return 0;
    }
    ```

=== "定义与宏"

    ``` c
    typedef struct _heap_info
    {
      mstate ar_ptr; /* 此堆所属的内存区域（arena）。 */
      struct _heap_info *prev; /* 前一个堆。 */
      size_t size;   /* 当前大小（字节）。 */
      size_t mprotect_size; /* 已经通过 mprotect 设置为 PROT_READ|PROT_WRITE 的大小（字节）。 */
      size_t pagesize; /* 分配内存区域时使用的页大小。 */
      /* 确保以下数据正确对齐，特别是 sizeof (heap_info) + 2 * SIZE_SZ 是 MALLOC_ALIGNMENT 的倍数。 */
      char pad[-3 * SIZE_SZ & MALLOC_ALIGN_MASK];
    } heap_info;
    
    # if __WORDSIZE == 32
    #  define DEFAULT_MMAP_THRESHOLD_MAX (512 * 1024)
    # else
    #  define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
    # endif
    #endif
    
    #define HEAP_MIN_SIZE (32 * 1024)
    #ifndef HEAP_MAX_SIZE
    # ifdef DEFAULT_MMAP_THRESHOLD_MAX
    #  define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)
    # else
    #  define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
    # endif
    #endif
    
    static inline size_t
    heap_max_size (void)
    {
    #if HAVE_TUNABLES
      return mp_.hp_pagesize == 0 ? HEAP_MAX_SIZE : mp_.hp_pagesize * 4;
    #else
      return HEAP_MAX_SIZE;
    #endif
    }
    #define PTR_ALIGN_DOWN(base, size) \
      ((__typeof__ (base)) ALIGN_DOWN ((uintptr_t) (base), (size)))
    static inline heap_info *
    heap_for_ptr (void *ptr)
    {
      size_t max_size = heap_max_size ();// 根据所给的函数以及宏定义可计算出max_size=4*1024*1024*8*2=0x4000000bytes=64mb，这个点之前也提到过，线程的arena对于的内存空间最大是64mb
      return PTR_ALIGN_DOWN (ptr, max_size);// 和ALIGN_DOWN同理以max_size向下取整，本质就是获取这个大块的起始地址
    }
    
    /* 扩展堆。大小会自动向上舍入到页面大小的倍数。 */
    
    static int
    grow_heap (heap_info *h, long diff)
    {
      size_t pagesize = h->pagesize;
      size_t max_size = heap_max_size ();
      long new_size;
    
      diff = ALIGN_UP (diff, pagesize);
      new_size = (long) h->size + diff;
      if ((unsigned long) new_size > (unsigned long) max_size)
        return -1;
    
      if ((unsigned long) new_size > h->mprotect_size)
        { // 这一块可以理解是在创建arena后，先用mmap创建了64mb的大块，但是不可用，后续想要使用就得通过下面的mprotect进行扩充，依稀记得以前有人利用下面的mprotect实现修改libc库出了一题
          if (__mprotect ((char *) h + h->mprotect_size,
                          (unsigned long) new_size - h->mprotect_size,
                          mtag_mmap_flags | PROT_READ | PROT_WRITE) != 0)
            return -2;
    
          h->mprotect_size = new_size;
        }
    
      h->size = new_size;
      LIBC_PROBE (memory_heap_more, 2, h, h->size);// 方便外部程序监控使用
      return 0;
    }
    
    /*
      MORECORE 相关的声明。默认情况下，使用 sbrk
    */
    
    
    /*
      MORECORE 是用于从系统获取更多内存的例程名称。
      有关编写替代 MORECORE 函数的常规指导，请参见下文，
      以及 WIN32 版本和 pre-OSX macos 的示例版本。
    */
    
    #ifndef MORECORE
    #define MORECORE sbrk
    #endif
    
    /*
      MORECORE_FAILURE 是 MORECORE 失败时返回的值，
      同时也适用于 mmap。由于它不能是其他有效的内存地址，
      且必须反映标准系统调用的值，你可能不应该尝试重新定义它。
    */
    
    #ifndef MORECORE_FAILURE
    #define MORECORE_FAILURE (-1)
    #endif
    
    /*
      如果 MORECORE_CONTIGUOUS 为真，则利用以下事实：
      连续调用 MORECORE 并传入正参数时，总是返回连续递增的地址。
      这在 unix sbrk 中是成立的。即使未定义，当区域恰好连续时，
      malloc 也会允许跨区域分配，这些区域来自不同的调用。
      但在适用时定义此宏可以启用一些更强的一致性检查和空间效率。
    */
    
    #ifndef MORECORE_CONTIGUOUS
    #define MORECORE_CONTIGUOUS 1
    #endif
    
    /*
      如果你的 MORECORE 版本在收到负参数时无法将空间释放回系统，
      则定义 MORECORE_CANNOT_TRIM。这通常只在你使用自定义的
      MORECORE 函数且该函数无法处理负参数时才需要。
    */
    
    /* #define MORECORE_CANNOT_TRIM */
    
    /*  MORECORE_CLEARS           (默认 1)
         映射到 MORECORE 的例程将内存清零的程度：
         从不 (0)、仅对新分配的空间 (1) 或始终 (2)。
         (1) 和 (2) 之间的区别是必要的，因为在某些系统上，
         如果应用程序先减少然后增加断点值，
         重新分配空间的内容是未指定的。
     */
    
    #ifndef MORECORE_CLEARS
    # define MORECORE_CLEARS 1
    #endif
    
    
    /*
       MMAP_AS_MORECORE_SIZE 是当 sbrk 失败时，
       使用 mmap 作为备份所要使用的最小 mmap 大小参数。
       该值必须是页面大小的倍数。这种备份策略通常仅适用于
       地址空间中存在"空洞"的系统，因此 sbrk 无法执行连续扩展，
       但系统中仍有可用空间。在已知此策略有用的系统上（即大多数 Linux 内核），
       这仅在程序分配大量内存时才会发生。鉴于这一点，
       以及 mmap 区域往往有限的事实，该值应该足够大，
       以避免过多的 mmap 调用，从而避免耗尽内核资源。
     */
    
    #ifndef MMAP_AS_MORECORE_SIZE
    #define MMAP_AS_MORECORE_SIZE (1024 * 1024)
    #endif
    
    static inline void
    madvise_thp (void *p, INTERNAL_SIZE_T size)
    {
    #if HAVE_TUNABLES && defined (MADV_HUGEPAGE)
      /* 不考虑小于大页的区域，或者如果可调参数未激活。  */
      if (mp_.thp_pagesize == 0 || size < mp_.thp_pagesize)
        return;
    
      /* Linux 要求输入地址按页对齐，且未对齐的输入仅发生在初始数据段。 */
      if (__glibc_unlikely (!PTR_IS_ALIGNED (p, GLRO (dl_pagesize))))
        {
          void *q = PTR_ALIGN_DOWN (p, GLRO (dl_pagesize));
          size += PTR_DIFF (p, q);
          p = q;
        }
    
      __madvise (p, size, MADV_HUGEPAGE);
    #endif
    }
    
    static void *
    sysmalloc_mmap_fallback (long int *s, INTERNAL_SIZE_T nb,
    			 INTERNAL_SIZE_T old_size, size_t minsize,
    			 size_t pagesize, int extra_flags, mstate av)
    {
      long int size = *s;
    
      /* 无法与旧顶部合并，因此将其大小加回 */
      if (contiguous (av))
        size = ALIGN_UP (size + old_size, pagesize);
    
      /* 如果我们依赖 mmap 作为备份，则使用更大的单位 */
      if ((unsigned long) (size) < minsize)
        size = minsize;
    
      /* 如果大小回绕到 0，则不要尝试 */
      if ((unsigned long) (size) <= (unsigned long) (nb))
        return MORECORE_FAILURE;
    
      char *mbrk = (char *) (MMAP (0, size,
    			       mtag_mmap_flags | PROT_READ | PROT_WRITE,
    			       extra_flags));
      if (mbrk == MAP_FAILED)
        return MAP_FAILED;
    
    #ifdef MAP_HUGETLB
      if (!(extra_flags & MAP_HUGETLB))
        madvise_thp (mbrk, size);
    #endif
    
      /* 记录我们不再拥有连续的 sbrk 区域。在第一次使用 mmap 作为备份之后，
         我们永远不依赖连续空间，因为这可能错误地桥接区域。 */
      set_noncontiguous (av);
    
      *s = size;
      return mbrk;
    }
    
    ```

### 分支4->小分支1-从mmap获取内存(sysmalloc_mmap)
=== "主体源码与执行流程"

    ``` c
    static void *
    sysmalloc_mmap (INTERNAL_SIZE_T nb, size_t pagesize, int extra_flags, mstate av)
    {
      long int size;
    
      /*
        将大小向上取整到最近的页大小倍数。对于mmap分配的块，其开销比普通块大一个SIZE_SZ单位，
        因为没有后续块可以使用其prev_size字段。
    
        参见下面的front_misalign处理，对于glibc，除非有高对齐要求，否则不需要进一步对齐。
       */
      if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)
        size = ALIGN_UP (nb + SIZE_SZ, pagesize);// 以pagesize(0x1000)为基础向上取整
      else
        size = ALIGN_UP (nb + SIZE_SZ + MALLOC_ALIGN_MASK, pagesize);
    
      /* 如果大小溢出到0，则不尝试。 */
      if ((unsigned long) (size) <= (unsigned long) (nb))
        return MAP_FAILED;
    
      char *mm = (char *) MMAP (0, size,
    			    mtag_mmap_flags | PROT_READ | PROT_WRITE,
    			    extra_flags);
      if (mm == MAP_FAILED)
        return mm;
    
    #ifdef MAP_HUGETLB
      if (!(extra_flags & MAP_HUGETLB))
        madvise_thp (mm, size);
    #endif
    
      /*
        mmap区域起始的偏移量存储在块的prev_size字段中。
        这允许我们在此处和memalign()中调整返回的起始地址以满足对齐要求，
        并且仍然能够在free()和realloc()中计算出用于后续munmap的正确地址参数。
       */
    
      INTERNAL_SIZE_T front_misalign; /* 新空间前端不可用的字节数 */
    
      if (MALLOC_ALIGNMENT == CHUNK_HDR_SZ)
        {
          /* 对于glibc，chunk2mem将地址增加CHUNK_HDR_SZ，并且MALLOC_ALIGN_MASK是CHUNK_HDR_SZ-1。
    	 每个mmap分配的区域都是页对齐的，因此肯定也是MALLOC_ALIGN_MASK对齐的。 */
          assert (((INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK) == 0);
          front_misalign = 0;
        }
      else
        front_misalign = (INTERNAL_SIZE_T) chunk2mem (mm) & MALLOC_ALIGN_MASK;
    
      mchunkptr p;                    /* 分配/返回的块 */
    
      if (front_misalign > 0)// 64位正常情况下`MALLOC_ALIGNMENT == CHUNK_HDR_SZ`为正因此frint_misalign也为0
        {
          ptrdiff_t correction = MALLOC_ALIGNMENT - front_misalign;
          p = (mchunkptr) (mm + correction);
          set_prev_size (p, correction);
          set_head (p, (size - correction) | IS_MMAPPED);
        }
      else
        {
          p = (mchunkptr) mm;
          set_prev_size (p, 0);
          set_head (p, size | IS_MMAPPED);
        }
    
      /* 更新统计数据 */
      int new = atomic_exchange_and_add (&mp_.n_mmaps, 1) + 1;
      atomic_max (&mp_.max_n_mmaps, new);
    
      unsigned long sum;
      sum = atomic_exchange_and_add (&mp_.mmapped_mem, size) + size;
      atomic_max (&mp_.max_mmapped_mem, sum);
    
      check_chunk (av, p);
    
      return chunk2mem (p);
    }
    ```

=== "定义与宏"

    ``` c
    /* 将一个值向下舍入到最近的对齐大小。
       例如，使用大小 4096，我们得到以下行为：
    	{4095, 4096, 4097} = {0, 4096, 4096}。 */
    #define ALIGN_DOWN(base, size)	((base) & -((__typeof__ (base)) (size)))
    
    /* 将一个值向上舍入到最近的对齐大小。
       例如，使用大小 4096，我们得到以下行为：
    	{4095, 4096, 4097} = {4096, 4096, 8192}。
    
      注意：`size` 参数有副作用（会被多次展开）。 */
    #define ALIGN_UP(base, size)	ALIGN_DOWN ((base) + (size) - 1, (size))
    ```
### 分支4->小分支2-新建线程大块heap(new_heap)
=== "主体源码与执行流程"

    ``` c
    static heap_info *
    new_heap (size_t size, size_t top_pad)
    {
    #if HAVE_TUNABLES
      if (__glibc_unlikely (mp_.hp_pagesize != 0))
        {
          /* MAP_NORESERVE 不用于大页（huge pages），因为某些内核可能不会保留 mmap 区域，
             如果池中没有可用页面，后续访问可能会触发 SIGBUS。*/
          heap_info *h = alloc_new_heap (size, top_pad, mp_.hp_pagesize,
    				     mp_.hp_flags);
          if (h != NULL)
    	return h;
        }
    #endif
      return alloc_new_heap (size, top_pad, GLRO (dl_pagesize), MAP_NORESERVE);
             // size=(nb+MINSIZE+siezof(*heap))，top_pad=mp_.top_pad=0x20000
    }  
    /* 如果连续调用 mmap(0, HEAP_MAX_SIZE << 1, ...) 返回递减的地址而非递增的地址，
       new_heap 会严重碎片化地址空间。在这种情况下，记住上一次 mmap (0, HEAP_MAX_SIZE << 1, ...)
       调用的第二个 HEAP_MAX_SIZE 部分（如果已对齐），并尝试在下一次重用它。
       我们不需要为其加锁，因为内核会为我们保证原子性——最坏的情况是多个线程
       会对某个 addr 值调用 mmap(addr, HEAP_MAX_SIZE, ...)，但只有一个会成功。 */
    static char *aligned_heap_area;
    ```

    `new_heap(...)` 自己只负责挑选页大小与 mmap 标志；真正完成地址对齐、保留 `aligned_heap_area`、建立新线程 heap 的主体逻辑在 `alloc_new_heap(...)`。

    ``` c
    static heap_info *
    alloc_new_heap  (size_t size, size_t top_pad, size_t pagesize,
    		 int mmap_flags)
    {
      char *p1, *p2;
      unsigned long ul;
      heap_info *h;
      size_t min_size = heap_min_size ();// 0x8000
      size_t max_size = heap_max_size ();// 0x4000000

      if (size + top_pad < min_size)
        size = min_size;
      else if (size + top_pad <= max_size)
        size += top_pad;
      else if (size > max_size)
        return 0;
      else
        size = max_size;
      size = ALIGN_UP (size, pagesize);

      /* 需要一个与 max_size 的倍数对齐的内存区域。
         以下大映射不需要保留交换空间（在 Linux 上，所有不可写映射都是如此）。*/
      p2 = MAP_FAILED;
      if (aligned_heap_area)// 全局静态变量
        {
    	  // 这个静态变量通过下一条来赋值得到的，简单理解改值是64mb对其的，可以直接用于mmap
          p2 = (char *) MMAP (aligned_heap_area, max_size, PROT_NONE, mmap_flags);
          aligned_heap_area = NULL;
          if (p2 != MAP_FAILED && ((unsigned long) p2 & (max_size - 1)))// 检测是否对其，没对齐直接释放
            {
              __munmap (p2, max_size);
              p2 = MAP_FAILED;
            }
        }
      if (p2 == MAP_FAILED)
        {
          p1 = (char *) MMAP (0, max_size << 1, PROT_NONE, mmap_flags);// 参数1为0则随机申请地址，但是申请大小是max_size两倍，说明其中肯定有符合对其的位置
          if (p1 != MAP_FAILED)
            {
              p2 = (char *) (((unsigned long) p1 + (max_size - 1))
                             & ~(max_size - 1));// 计算符合对其的地址
              ul = p2 - p1;
              if (ul)// 如果为0，说明其实地址符合对其则将后半地址放入aligned_heap_area并释放、否则将前后都释放
                __munmap (p1, ul);
              else
                aligned_heap_area = p2 + max_size;
              __munmap (p2 + max_size, max_size - ul);
            }
          else
            {
              /* 尝试利用只分配 max_size 的内存可能已经对齐的机会。*/
              // 可能空间不够什么的，两倍内存申请失败，进入该条件
              p2 = (char *) MMAP (0, max_size, PROT_NONE, mmap_flags);
              if (p2 == MAP_FAILED)
                return 0;

              if ((unsigned long) p2 & (max_size - 1))
                {
                  __munmap (p2, max_size);
                  return 0;
                }
            }
        }
      if (__mprotect (p2, size, mtag_mmap_flags | PROT_READ | PROT_WRITE) != 0)
        {
          __munmap (p2, max_size);
          return 0;
        }

      madvise_thp (p2, size);// AI：通过调用 madvise_thp，它告诉内核：“对于这块刚分配的、即将被频繁使用的内存，请尝试使用大页（Huge Pages，通常是 2MB）来映射”。

      h = (heap_info *) p2;
      h->size = size;
      h->mprotect_size = size;
      h->pagesize = pagesize;
      LIBC_PROBE (memory_heap_new, 2, h, h->size);
      return h;
    }
    ```

=== "定义与宏"

    ``` c
    #define HEAP_MIN_SIZE (32 * 1024)
    static inline size_t
    heap_min_size (void)
    {
    #if HAVE_TUNABLES
      return mp_.hp_pagesize == 0 ? HEAP_MIN_SIZE : mp_.hp_pagesize;
    #else
      return HEAP_MIN_SIZE;
    #endif
    }
    
    /* 如果连续调用 mmap(0, HEAP_MAX_SIZE << 1, ...) 返回递减的地址而非递增的地址，
       new_heap 会严重碎片化地址空间。在这种情况下，记住上一次 mmap (0, HEAP_MAX_SIZE << 1, ...)
       调用的第二个 HEAP_MAX_SIZE 部分（如果已对齐），并尝试在下一次重用它。
       我们不需要为其加锁，因为内核会为我们保证原子性——最坏的情况是多个线程
       会对某个 addr 值调用 mmap(addr, HEAP_MAX_SIZE, ...)，但只有一个会成功。 */
    static char *aligned_heap_area;
    ```
