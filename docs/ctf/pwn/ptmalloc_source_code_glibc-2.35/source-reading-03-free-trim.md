# `free`、合并与 trim 路径

这一页最好和 `_int_malloc` 一起看，因为这里的很多操作都不是简单“释放结束”，而是把 chunk 送回之后还会再次参与分配的状态里。
### 主线3-尝试释放内存(\_\_libc_free)
=== "主体源码与执行流程"

    ``` c
    void
    __libc_free (void *mem)
    {
      mstate ar_ptr;
      mchunkptr p;                          /* 对应于 mem 的内存块 (chunk) */
    
      if (mem == 0)                              /* free(0) 不产生任何效果 */
        return;
    
      /* 快速检查被释放的指针是否与内存标签匹配。
         这提供了一个有用的双重释放检测。 */
      if (__glibc_unlikely (mtag_enabled))// 默认情况下不开启
        *(volatile char *)mem;
    
      int err = errno;
    
      p = mem2chunk (mem);// 从指向内存改为指向chunk头
    
      if (chunk_is_mmapped (p))                       /* 释放 mmapped 内存。*/
        {
          /* 检查是否需要调整动态的 brk/mmap 阈值。
    	 被倾倒 (dumped) 的伪 mmapped 内存块不影响阈值。 */
          if (!mp_.no_dyn_threshold// 判断是否开启了动态阈值
              && chunksize_nomask (p) > mp_.mmap_threshold
              && chunksize_nomask (p) <= DEFAULT_MMAP_THRESHOLD_MAX)
              // 判断是否大于阈值小于最大默认值
            {
              mp_.mmap_threshold = chunksize (p);
              mp_.trim_threshold = 2 * mp_.mmap_threshold;
              // mp_.trim_threshold在malloc_trim()（brk收缩）时被使用；当堆的空闲空间超过该阈值时，glibc 会尝试把多余的内存归还给操作系统
              LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                          mp_.mmap_threshold, mp_.trim_threshold);
            // 动态阈值：如果最近一次性释放了一块尺寸为S的大块，malloc 认为以后可能还会有类似大小的请求。把这块的大小设为新的 mmap 阈值，以后同样大小或更大的分配就会走mmap（更安全、不会产生碎片），而不是继续在堆里sbrk。
            }
          munmap_chunk (p);// 跳转主线3->分支1-释放mmap内存
        }
      else
        {
          MAYBE_INIT_TCACHE ();// 判断TCACHE是否初始化，malloc开始之前也有同样调用
    
          /* 再次将内存块标记为属于库。 */
          (void)tag_region (chunk2mem (p), memsize (p));// 涉及内存标签防护机制跳过
    
          ar_ptr = arena_for_chunk (p);// 本质通过标志位是来自哪个arena
          _int_free (ar_ptr, p, 0);// 跳转主线4
        }
    
      __set_errno (err);
    }
    ```

=== "定义与宏"

    ``` c
    #define mem2chunk(mem) ((mchunkptr)tag_at (((char*)(mem) - CHUNK_HDR_SZ)))
    ```
### 主线3->分支1-释放mmap内存(munmap_chunk)
=== "主体源码与执行流程"

    ``` c
    static void munmap_chunk (mchunkptr p) {
       size_t pagesize = GLRO (dl_pagesize);
       assert (chunk_is_mmapped (p));
       uintptr_t mem = (uintptr_t) chunk2mem (p);// 执行内存区域
       uintptr_t block = mmap_base (p);// 获取mmap申请区域的基地址
       size_t total_size = mmap_size (p);// 获取完整的mmap大小
       /* 可惜我们必须在这里手动完成编译器的工作。通常，我们会分别测试 BLOCK 和 TOTAL-SIZE 是否符合页面大小。但 gcc 目前还不能识别这种优化可能性（至少目前是这样），所以我们在位测试之前将两个值合并为一个。 */
       if (__glibc_unlikely ((block | total_size) & (pagesize - 1)) != 0
           || __glibc_unlikely (!powerof2 (mem & (pagesize - 1))))
           // 条件一满足是0x1000对齐，条件二确保页内偏移是0或二次幂
         malloc_printerr ("munmap_chunk(): 无效指针");
    
       atomic_fetch_add_relaxed (&mp_.n_mmaps, -1);// 原子操作，总mmap数减1
       atomic_fetch_add_relaxed (&mp_.mmapped_mem, -total_size);// 总申请内存减去
    
       /* 如果 munmap 失败，进程的虚拟内存地址空间将处于不良状态。就让这个块悬着吧，反正进程很快就会终止，因为此时也做不了什么了。 */
       __munmap ((char *) block, total_size);
    }
    ```

=== "定义与宏"

    ``` c
    /* 用于 mmap 块的大页面。  */
    #define MMAP_HP 0x1
    
    /* 返回 mmap 块相对于 mmap 基址的偏移量。  */
    static __always_inline size_t
    mmap_base_offset (mchunkptr p)
    {
      return prev_size (p) & ~MMAP_HP;
    }
    
    /* 返回设置了 IS_MMAPPED 标志的块对应的 mmap 基址指针。  */
    static __always_inline uintptr_t
    mmap_base (mchunkptr p)
    {
      return (uintptr_t) p - mmap_base_offset (p);
    }
    
    /* 返回设置了 IS_MMAPPED 标志的块的总 mmap 大小。  */
    static __always_inline size_t
    mmap_size (mchunkptr p)
    {
      return mmap_base_offset (p) + chunksize (p) + CHUNK_HDR_SZ;
    }
    
    
    ```

### 主线4-尝试进一步释放内存(\_int\_free)
=== "主体源码与执行流程"

    ``` c
    static void
    _int_free (mstate av, mchunkptr p, int have_lock)
    {
      INTERNAL_SIZE_T size;        /* 块的大小 */
      mfastbinptr *fb;             /* 关联的 fastbin（快速块链表） */
      mchunkptr nextchunk;         /* 下一个连续块 */
      INTERNAL_SIZE_T nextsize;    /* 下一个块的大小 */
      int nextinuse;               /* 标记下一个块是否正在使用 */
      INTERNAL_SIZE_T prevsize;    /* 前一个连续块的大小 */
      mchunkptr bck;               /* 链接用的临时变量（后向指针） */
      mchunkptr fwd;               /* 链接用的临时变量（前向指针） */
    
      size = chunksize (p);
    
      /* 对性能无影响的小型安全检查：
         分配器永远不会在地址空间末尾环绕。
         因此我们可以排除一些可能因意外或某些入侵者"设计"而出现的值。  */
      if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
          || __builtin_expect (misaligned_chunk (p), 0))
        malloc_printerr ("free(): invalid pointer");
      /* 我们知道每个块至少为 MINSIZE 字节大小或是 MALLOC_ALIGNMENT 的倍数。  */
      if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
        malloc_printerr ("free(): invalid size");
    
      check_inuse_chunk(av, p);// 检测前后堆块是否释放正常
    
    #if USE_TCACHE
      {
        size_t tc_idx = csize2tidx (size);
        if (tcache != NULL && tc_idx < mp_.tcache_bins)
          {
            /* 检查它是否已经在 tcache 中。  */
            tcache_entry *e = (tcache_entry *) chunk2mem (p);
    
            /* 双重释放时此测试会成功。然而，我们不能100%信任它
               （它也会以 2^<size_t> 分之一的几率匹配随机负载数据），
               因此在中止之前先验证这不是不太可能的巧合。  */
            if (__glibc_unlikely (e->key == tcache_key))// 防doublefree，绕过也很简单破坏即可，第二次free前理论上修改其大小也能绕过，不过你都能修改大小了
              {
                tcache_entry *tmp;
                size_t cnt = 0;
                LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
                for (tmp = tcache->entries[tc_idx];
                     tmp;
                     tmp = REVEAL_PTR (tmp->next), ++cnt)
                  { // 循环遍历对应大小的tcache列表是否有其，防止出现那极小的概率事件
                    if (cnt >= mp_.tcache_count)
                      malloc_printerr ("free(): too many chunks detected in tcache");
                    if (__glibc_unlikely (!aligned_OK (tmp)))
                      malloc_printerr ("free(): unaligned chunk detected in tcache 2");
                    if (tmp == e)
                      malloc_printerr ("free(): double free detected in tcache 2");
                    /* 如果我们到达这里，那只是个巧合。我们浪费了几个周期，
                       但不会中止。  */
                  }
              }
    
            if (tcache->counts[tc_idx] < mp_.tcache_count)
              {
                tcache_put (p, tc_idx);// 放入
                return;
              }
          }
      }
    #endif
    
      /*
        如果符合条件，将块放入快速bin以便在malloc中快速找到并使用。
      */
    
      if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
    
    #if TRIM_FASTBINS
          /*
            如果设置了TRIM_FASTBINS，不要将边界顶部的块放入快速bin
          */
          && (chunk_at_offset(p, size) != av->top)
    #endif
          ) {
        if (__builtin_expect (chunksize_nomask (chunk_at_offset (p, size))
                              <= CHUNK_HDR_SZ, 0)
            || __builtin_expect (chunksize (chunk_at_offset (p, size))
                                 >= av->system_mem, 0))// 判断堆块大小是否正常
          {
            bool fail = true;
            /* 此时我们可能没有锁，并且system_mem的并发修改可能导致误报。
               获取锁后重做测试。  */
            if (!have_lock)
              {
                __libc_lock_lock (av->mutex);
                fail = (chunksize_nomask (chunk_at_offset (p, size)) <= CHUNK_HDR_SZ
                        || chunksize (chunk_at_offset (p, size)) >= av->system_mem);
                        //再次判断堆块大小是否正常
                __libc_lock_unlock (av->mutex);
              }
    
            if (fail)
              malloc_printerr ("free(): invalid next size (fast)");
          }
    
        free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ); // 尝试堆释放的内存进行perturb值填充，正常情况下为0，不会尝试填充
    
        atomic_store_relaxed (&av->have_fastchunks, true);// 原操设置为1
        unsigned int idx = fastbin_index(size);
        fb = &fastbin (av, idx);
    
        /* 原子地将P链接到它的快速bin：P->FD = *FB; *FB = P;  */
        mchunkptr old = *fb, old2;
    
        if (SINGLE_THREAD_P)// 是否多线程
          {
            /* 检查bin顶部不是我们正要添加的记录（即双重释放）。  */
            if (__builtin_expect (old == p, 0))
              malloc_printerr ("double free or corruption (fasttop)");
            p->fd = PROTECT_PTR (&p->fd, old);// 获取真实地址，并将其储存到p的fd里
            *fb = p;
          }
        else
          do
            {
              /* 检查bin顶部不是我们正要添加的记录（即双重释放）。  */
              if (__builtin_expect (old == p, 0))// 经典手法有A，B两个同样大的要free，释放顺序A->B->A即可绕过
                malloc_printerr ("double free or corruption (fasttop)");
              old2 = old;
              p->fd = PROTECT_PTR (&p->fd, old);// 获取真实地址，并将其储存到p的fd里
            }
          while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
                 != old2);// 这里是将fb中储存的原先的chunk值替换为新的，替换成功则两者不相等退出循环，不成功则存在线程冲突，再次尝试
    
        /* 检查快速bin顶部块的大小是否与我们正在添加的块的大小相同。
           只有持有锁时我们才能解引用OLD，否则它可能已被重新分配。  */
        if (have_lock && old != NULL
            && __builtin_expect (fastbin_index (chunksize (old)) != idx, 0))
          malloc_printerr ("invalid fastbin entry (free)");
      }
    
      /*
        当它们到达时，合并其他非mmap的块。
      */
    
      else if (!chunk_is_mmapped(p)) {// 考虑非tcache和fastbin情况
        /* 如果是单线程，不要锁住arena。  */
        if (SINGLE_THREAD_P)
          have_lock = true;
    
        if (!have_lock)
          __libc_lock_lock (av->mutex);
    
        nextchunk = chunk_at_offset(p, size);
    
        /* 轻量级测试：检查块是否已经是顶部块。  */
        if (__glibc_unlikely (p == av->top))
          malloc_printerr ("double free or corruption (top)");
        /* 或者下一个块是否超出arena的边界。  */
        if (__builtin_expect (contiguous (av)
                              && (char *) nextchunk
                              >= ((char *) av->top + chunksize(av->top)), 0))
          malloc_printerr ("double free or corruption (out)");
        /* 或者块实际上是否未标记为使用。  */
        if (__glibc_unlikely (!prev_inuse(nextchunk)))
          malloc_printerr ("double free or corruption (!prev)");
    
        nextsize = chunksize(nextchunk);
        if (__builtin_expect (chunksize_nomask (nextchunk) <= CHUNK_HDR_SZ, 0)
            || __builtin_expect (nextsize >= av->system_mem, 0))
          malloc_printerr ("free(): invalid next size (normal)");
    
        free_perturb (chunk2mem(p), size - CHUNK_HDR_SZ);
    
        /* 向后合并 */ // 向后指低地址
        if (!prev_inuse(p)) {
          prevsize = prev_size (p);
          size += prevsize;
          p = chunk_at_offset(p, -((long) prevsize));
          if (__glibc_unlikely (chunksize(p) != prevsize))
            malloc_printerr ("corrupted size vs. prev_size while consolidating");
          unlink_chunk (av, p);
        }
    
        if (nextchunk != av->top) {
          /* 获取并清除inuse位 */
          nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
    
          /* 向前合并 */
          if (!nextinuse) {
            unlink_chunk (av, nextchunk);
            size += nextsize;
          } else
            clear_inuse_bit_at_offset(nextchunk, 0);
    
          /*
            将块放入unsorted bin。块在有机会在malloc中被使用一次之前，
            不会放入常规bin中。
          */
    
          bck = unsorted_chunks(av);
          fwd = bck->fd;
          if (__glibc_unlikely (fwd->bk != bck))
            malloc_printerr ("free(): corrupted unsorted chunks");
          p->fd = fwd;
          p->bk = bck;
          if (!in_smallbin_range(size))
            {
              p->fd_nextsize = NULL;
              p->bk_nextsize = NULL;
            }
          bck->fd = p;
          fwd->bk = p;
    
          set_head(p, size | PREV_INUSE);
          set_foot(p, size);
    
          check_free_chunk(av, p);// 等同do_check_free_chunk检测是否正常释放，从块头 → 块大小对齐 → 前后块使用位 → footer 字段 → 空闲链表指针 → 哨兵块这几个维度，完整地验证一个已被释放的内存块在元数据层面是否保持内部一致性。
        }
    
        /*
          如果块与当前内存高端相邻，则合并到顶部
        */
    
        else { // 直接合top合并
          size += nextsize;
          set_head(p, size | PREV_INUSE);
          av->top = p;
          check_chunk(av, p);
        }
    
        /*
          如果释放一个大空间，合并可能相邻的块。然后，如果未使用的顶端内存总量
          超过trim阈值，要求malloc_trim减少顶部。
    
          除非max_fast为0，否则我们不知道快速bin是否与顶部相邻，
          因此除非快速bin被合并，否则无法确定是否达到阈值。
          但我们不想在每次释放时都合并。作为折衷，
          仅在达到FASTBIN_CONSOLIDATION_THRESHOLD时执行合并。
        */
    
        if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
          if (atomic_load_relaxed (&av->have_fastchunks))
          // FASTBIN_CONSOLIDATION_THRESHOLD为65536，可以认为通过上面处理size大于65536且存在fastbin会触发一次malloc_consolidate
            malloc_consolidate(av);
    
          if (av == &main_arena) {
    #ifndef MORECORE_CANNOT_TRIM
            if ((unsigned long)(chunksize(av->top)) >=
                (unsigned long)(mp_.trim_threshold))
              systrim(mp_.top_pad, av);// 通过top_chunk大小大于trim_threshold(0x20000)则会将部分内存归还给系统
              // 跳转主线4->分支1-收缩top_chunk
    #endif
          } else {
            /* 即使顶部块不大，也始终尝试heap_trim()，
               因为相应的堆可能会消失。  */
            heap_info *heap = heap_for_ptr(top(av));
    
            assert(heap->ar_ptr == av);
            heap_trim (heap, mp_.top_pad);// 跳转主线4->分支2-线程heap收缩
          }
        }
    
        if (!have_lock)
          __libc_lock_unlock (av->mutex);
      }
    
      /*
        如果块是通过mmap分配的，通过munmap()释放。
      */
    
      else {
        munmap_chunk (p);
      }
    }
    ```

=== "定义与宏"

    ``` c
    static void
    free_perturb (char *p, size_t n)
    {
      if (__glibc_unlikely (perturb_byte))
        memset (p, perturb_byte, n);
    }
    
    #define FASTBIN_CONSOLIDATION_THRESHOLD  (65536UL)
    ```
### 主线4->分支1-收缩top_chunk(systrim)
=== "主体源码与执行流程"

    ``` c
    static int
    systrim (size_t pad, mstate av)
    {
      long top_size;         /* 顶部内存的大小 */
      long extra;            /* 要释放的数量 */
      long released;         /* 实际释放的数量 */
      char *current_brk;     /* pre-check sbrk 调用返回的地址 */
      char *new_brk;         /* post-check sbrk 调用返回的地址 */
      long top_area;

      top_size = chunksize (av->top);

      top_area = top_size - MINSIZE - 1;
      if (top_area <= pad)// 默认情况下全局pad为0
        return 0;

      /* 按 pagesize 单位释放，并向下取整到最近的页边界。  */
    #if HAVE_TUNABLES && defined (MADV_HUGEPAGE)
      if (__glibc_unlikely (mp_.thp_pagesize != 0))
        extra = ALIGN_DOWN (top_area - pad, mp_.thp_pagesize);
      else
    #endif
        extra = ALIGN_DOWN (top_area - pad, GLRO(dl_pagesize));

      if (extra == 0)
        return 0;

      /*
         仅当内存末尾在我们上次设置的位置时继续执行。
         这样可以避免 foreign sbrk 调用带来的问题。
       */
      current_brk = (char *) (MORECORE (0));
      if (current_brk == (char *) (av->top) + top_size)
        {
          /*
             尝试释放内存。我们忽略 MORECORE 的返回值，
             而是再次调用来查找内存的新末尾位置。
             这样可以避免首次调用释放的内存少于我们请求的数量，
             或者失败时以某种方式改变了 brk 值。（如果它以某种非常糟糕的方式
             改变了 brk，我们仍然可能遇到问题，但我们可以做的唯一事情
             就是无论如何都进行调整，这会导致一些下游失败。）
           */

          MORECORE (-extra);
          new_brk = (char *) (MORECORE (0));

          LIBC_PROBE (memory_sbrk_less, 2, new_brk, extra);

          if (new_brk != (char *) MORECORE_FAILURE)
            {
              released = (long) (current_brk - new_brk);

              if (released != 0)
                {
                  /* 成功。调整顶部块。 */
                  av->system_mem -= released;
                  set_head (av->top, (top_size - released) | PREV_INUSE);
                  check_malloc_state (av);
                  return 1;
                }
            }
        }
      return 0;
    }
    ```

=== "定义与宏"

    ``` c
    #define top(ar_ptr) ((ar_ptr)->top)

    #define PREV_INUSE 0x1
    #define IS_MMAPPED 0x2
    #define NON_MAIN_ARENA 0x4
    #define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

    #define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))
    #define chunksize_nomask(p) ((p)->mchunk_size)

    #define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
                              ? __alignof__ (long double) : 2 * SIZE_SZ)
    #define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
    #define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))
    #define MINSIZE  \
      (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

    #define ALIGN_DOWN(base, size) ((base) & -((__typeof__ (base)) (size)))

    #ifndef MORECORE
    #define MORECORE sbrk
    #endif

    #ifndef MORECORE_FAILURE
    #define MORECORE_FAILURE (-1)
    #endif

    #define set_head(p, s) ((p)->mchunk_size = (s))
    ```

### 主线4->分支2-线程heap收缩(heap_trim)
=== "主体源码与执行流程"

    ``` c
    static int
    heap_trim (heap_info *heap, size_t pad)
    {
      mstate ar_ptr = heap->ar_ptr;
      mchunkptr top_chunk = top (ar_ptr), p;
      heap_info *prev_heap;
      long new_size, top_size, top_area, extra, prev_size, misalign;
      size_t max_size = heap_max_size ();

      /* 能否完全丢弃该堆？ */
      while (top_chunk == chunk_at_offset (heap, sizeof (*heap)))
        {
          prev_heap = heap->prev;
          prev_size = prev_heap->size - (MINSIZE - 2 * SIZE_SZ);
          p = chunk_at_offset (prev_heap, prev_size);
          /* 边界标记必须正确对齐。 */
          misalign = ((long) p) & MALLOC_ALIGN_MASK;
          p = chunk_at_offset (prev_heap, prev_size - misalign);
          assert (chunksize_nomask (p) == (0 | PREV_INUSE)); /* 必须是边界标记 */
          p = prev_chunk (p);
          new_size = chunksize (p) + (MINSIZE - 2 * SIZE_SZ) + misalign;
          assert (new_size > 0 && new_size < (long) (2 * MINSIZE));
          if (!prev_inuse (p))
            new_size += prev_size (p);
          assert (new_size > 0 && new_size < max_size);
          if (new_size + (max_size - prev_heap->size) < pad + MINSIZE
                                                + heap->pagesize)
            break;
          ar_ptr->system_mem -= heap->size;
          LIBC_PROBE (memory_heap_free, 2, heap, heap->size);
          if ((char *) heap + max_size == aligned_heap_area)
            aligned_heap_area = NULL;
          __munmap (heap, max_size);
          heap = prev_heap;
          if (!prev_inuse (p)) /* 向后合并 */
            {
              p = prev_chunk (p);
              unlink_chunk (ar_ptr, p);
            }
          assert (((unsigned long) ((char *) p + new_size) & (heap->pagesize - 1))
                  == 0);
          assert (((char *) p + new_size) == ((char *) heap + heap->size));
          top (ar_ptr) = top_chunk = p;
          set_head (top_chunk, new_size | PREV_INUSE);
          /*check_chunk(ar_ptr, top_chunk);*/
        }

      /* 与主 arena 的 systrim 和 _int_free 使用相似的逻辑，
         通过保留顶部填充并向下取整到最近的页面来管理每个线程的 arena。 */
      top_size = chunksize (top_chunk);
      if ((unsigned long)(top_size) <
          (unsigned long)(mp_.trim_threshold))
        return 0;

      top_area = top_size - MINSIZE - 1;
      if (top_area < 0 || (size_t) top_area <= pad)
        return 0;

      /* 按页大小释放并向下取整到最近的页面。 */
      extra = ALIGN_DOWN(top_area - pad, heap->pagesize);
      if (extra == 0)
        return 0;

      /* 尝试缩小堆。 */
      if (shrink_heap (heap, extra) != 0)
        return 0;

      ar_ptr->system_mem -= extra;

      /* 成功。相应地调整顶部块。 */
      set_head (top_chunk, (top_size - extra) | PREV_INUSE);
      /*check_chunk(ar_ptr, top_chunk);*/
      return 1;
    }
    ```

=== "定义与宏"

    ``` c
    #define top(ar_ptr) ((ar_ptr)->top)

    typedef struct _heap_info
    {
      mstate ar_ptr;
      struct _heap_info *prev;
      size_t size;
      size_t mprotect_size;
      size_t pagesize;
      char pad[-3 * SIZE_SZ & MALLOC_ALIGN_MASK];
    } heap_info;

    static inline size_t
    heap_max_size (void)
    {
    #if HAVE_TUNABLES
      return mp_.hp_pagesize == 0 ? HEAP_MAX_SIZE : mp_.hp_pagesize * 4;
    #else
      return HEAP_MAX_SIZE;
    #endif
    }

    static int
    shrink_heap (heap_info *h, long diff)
    {
      long new_size;

      new_size = (long) h->size - diff;
      if (new_size < (long) sizeof (*h))
        return -1;

      if (__glibc_unlikely (check_may_shrink_heap ()))
        {
          if ((char *) MMAP ((char *) h + new_size, diff, PROT_NONE,
                             MAP_FIXED) == (char *) MAP_FAILED)
            return -2;

          h->mprotect_size = new_size;
        }
      else
        __madvise ((char *) h + new_size, diff, MADV_DONTNEED);

      h->size = new_size;
      LIBC_PROBE (memory_heap_less, 2, h, h->size);
      return 0;
    }

    #define PREV_INUSE 0x1
    #define IS_MMAPPED 0x2
    #define NON_MAIN_ARENA 0x4
    #define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

    #define prev_inuse(p) ((p)->mchunk_size & PREV_INUSE)
    #define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))
    #define chunksize_nomask(p) ((p)->mchunk_size)
    #define prev_size(p) ((p)->mchunk_prev_size)
    #define prev_chunk(p) ((mchunkptr) (((char *) (p)) - prev_size (p)))
    #define chunk_at_offset(p, s) ((mchunkptr) (((char *) (p)) + (s)))
    #define set_head(p, s) ((p)->mchunk_size = (s))

    #define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
                              ? __alignof__ (long double) : 2 * SIZE_SZ)
    #define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)
    #define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))
    #define MINSIZE  \
      (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))

    # if __WORDSIZE == 32
    #  define DEFAULT_MMAP_THRESHOLD_MAX (512 * 1024)
    # else
    #  define DEFAULT_MMAP_THRESHOLD_MAX (4 * 1024 * 1024 * sizeof(long))
    # endif
    #define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)
    ```
