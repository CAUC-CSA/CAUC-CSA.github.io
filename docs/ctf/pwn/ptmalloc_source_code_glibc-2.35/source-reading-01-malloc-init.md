# `malloc` 入口、初始化与 tcache 建立

这一页先顺着 `malloc` 入口一路往下读，碰到不熟的结构、宏或者辅助函数时，再切到同一节里的“定义与宏”选项卡补看。

## Glibc 2.35
### 主线1-尝试申请内存(\_\_libc_malloc)
=== "主体源码与执行流程"

    ``` c
    #if IS_IN (libc)
    void *
    __libc_malloc (size_t bytes)
    {
      mstate ar_ptr;
      void *victim;
    
      _Static_assert (PTRDIFF_MAX <= SIZE_MAX / 2,
                      "PTRDIFF_MAX is not more than half of SIZE_MAX");// 编译阶段的断言，一个简单检测无需理会
    
      if (!__malloc_initialized)// 静态全局变量在默认情况下为0，则堆空间未初始化
        ptmalloc_init ();// 分支1-开始堆空间初始化
    #if USE_TCACHE
      /* int_free also calls request2size, be careful to not pad twice.  */
      size_t tbytes;
      if (!checked_request2size (bytes, &tbytes))// 检查大小，并转成对其大小储存在tbytes
        {
          __set_errno (ENOMEM);
          return NULL;
        }
      size_t tc_idx = csize2tidx (tbytes);// 计算tcache下标，64位下通常是 0x20->0、0x30->1 ... 0x410->63
    
      MAYBE_INIT_TCACHE ();// 分支2-Tcache初始化
    
      DIAG_PUSH_NEEDS_COMMENT;// 编译器诊断相关宏，对主流程理解影响不大
      if (tc_idx < mp_.tcache_bins
          && tcache
          && tcache->counts[tc_idx] > 0)// 这里判断计算出来的tc_idx是否在范围内，且tcache结构体是否不为空，且tc_idx对应的bin是否有可用的
        {
          victim = tcache_get (tc_idx);// 获取对应的空闲tcache
          return tag_new_usable (victim);// 涉及mtag默认不触发，正常返回victim
        }
      DIAG_POP_NEEDS_COMMENT;
    #endif
    
      if (SINGLE_THREAD_P)// 这里就是判断是否是单线程，是的话进入该条件，使用main_arena
        {
          victim = tag_new_usable (_int_malloc (&main_arena, bytes));// 主线2-从非tcache分配内存(_int_malloc)
          assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
    	      &main_arena == arena_for_chunk (mem2chunk (victim)));// 分配解释后要么地址位0，要么从mmap分配，要么分配是从main_arena来的（本质检标志位NON_MAIN_ARENA）
          return victim;
        }
      // 多线程走下面，会尝试使用其他arena
      arena_get (ar_ptr, bytes);
    
      victim = _int_malloc (ar_ptr, bytes);
      /* Retry with another arena only if we were able to find a usable arena
         before.  */
      if (!victim && ar_ptr != NULL)
        {
          LIBC_PROBE (memory_malloc_retry, 1, bytes);
          ar_ptr = arena_get_retry (ar_ptr, bytes);
          victim = _int_malloc (ar_ptr, bytes);
        }
    
      if (ar_ptr != NULL)
        __libc_lock_unlock (ar_ptr->mutex);
    
      victim = tag_new_usable (victim);
    
      assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
              ar_ptr == arena_for_chunk (mem2chunk (victim)));
      return victim;
    }
    ```

=== "定义与宏"

    ``` c
    #ifndef INTERNAL_SIZE_T
    # define INTERNAL_SIZE_T size_t   /* 64 位下通常是 8 字节，32 位下通常是 4 字节 */
    #endif
    struct malloc_chunk {
    
      /* 前一个内存块的大小（如果前一个块是空闲的）。 */
      INTERNAL_SIZE_T      mchunk_prev_size;
      /* 当前内存块的总大小（字节），包括元数据开销。 */
      INTERNAL_SIZE_T      mchunk_size;
    
      /* 双向链表指针——仅当内存块空闲时使用。 */
      struct malloc_chunk* fd;
      struct malloc_chunk* bk;
    
      /* 仅用于大型内存块：指向下一个更大尺寸的内存块的指针。 */
      struct malloc_chunk* fd_nextsize;
      struct malloc_chunk* bk_nextsize;
    };
    typedef struct malloc_chunk *mfastbinptr;
    typedef struct malloc_chunk* mchunkptr;
    /* offset 2 to use otherwise unindexable first 2 bins */
    #define fastbin_index(sz) \
      ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
    
    #define request2size(req)                                         \
      (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
       MINSIZE :                                                      \
       ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
    // req 是用户申请的大小，request2size 返回的是分配器内部真正使用的 chunk 大小。
    // 在 64 位下可以先粗略理解成：req + 8{SIZE_SZ} + 15{MALLOC_ALIGN_MASK = 16 - 1}，
    // 然后和 MINSIZE 比较，再按 0x10 对齐。于是 req 为 0x0~0x18 时通常都会落到 0x20，
    // req 为 0x19~0x28 时通常会落到 0x30，后面以 0x10 为粒度继续增长。
    // 一个容易困惑的问题是：chunk 头看起来像有 0x10，但为什么申请 0x18 时 chunk 仍可能只有 0x20。
    // 关键点在于 mchunk_prev_size 并不是每次都作为“当前 chunk 自己的固定头部”来理解；
    // 当前一个 chunk 正在使用时，这一字段不会被当前 chunk 当成可解释的 prev_size 使用，
    // 所以这部分空间会和前一个 chunk 的用户区发生复用。
    
    /* The maximum fastbin request size we support */
    #define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)=0xa0
    #define fastbin_index(sz) \
      ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
    	#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)=fastbin_index (0xb0)+1=10
    // 需要注意的是这边所计算的fastbin最大大小是0xa0，不过会被默认通过global_max_fast全局变量将最大chunk值限制到128字节，就是0~128，对应chunk大小就是0x20~0x80
    struct malloc_state
    {
      __libc_lock_define (, mutex);
      int flags;
      int have_fastchunks;
      mfastbinptr fastbinsY[NFASTBINS];// nfastbins=10 存放fastbin
      mchunkptr top;
      mchunkptr last_remainder;
      mchunkptr bins[NBINS * 2 - 2];// bins=128 存放unsorted bin、small bin、large bin
      unsigned int binmap[BINMAPSIZE];
      struct malloc_state *next;
      struct malloc_state *next_free;
      INTERNAL_SIZE_T attached_threads;
      INTERNAL_SIZE_T system_mem;
      INTERNAL_SIZE_T max_system_mem;
    };
    struct malloc_state;
    typedef struct malloc_state *mstate;
    
    static bool __malloc_initialized = false;
    
    static inline bool
    checked_request2size (size_t req, size_t *sz) __nonnull (1)
    {
      if (__glibc_unlikely (req > PTRDIFF_MAX))
        return false;
      *sz = request2size (req);
      return true;
    }
    
    # define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
    # define usize2tidx(x) csize2tidx (request2size (x))
    
    #define PROTECT_PTR(pos, ptr) \
      ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
    #define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
    
    static __always_inline void *
    tcache_get (size_t tc_idx)
    {
      tcache_entry *e = tcache->entries[tc_idx];
      if (__glibc_unlikely (!aligned_OK (e)))
        malloc_printerr ("malloc(): unaligned tcache chunk detected");
      tcache->entries[tc_idx] = REVEAL_PTR (e->next);// 这里取出来的是下一个 tcache_entry，也就是 chunk2mem 之后的用户区地址
      --(tcache->counts[tc_idx]);
      e->key = 0;
      return (void *) e;
    }
    
    #define mem2chunk(mem) ((mchunkptr)tag_at (((char*)(mem) - CHUNK_HDR_SZ)))
    ```

### 主线1->分支1-初始化堆空间(ptmalloc_init)
=== "主体源码与执行流程"

    ``` c
    static void
    ptmalloc_init (void)
    {
      if (__malloc_initialized)
        return;
    
      __malloc_initialized = true;
    
    #if USE_TCACHE
      tcache_key_initialize ();
    #endif
    
    #if defined SHARED && IS_IN (libc)
      if (!__libc_initial)// 正常调用下 __libc_initial 为真
        __always_fail_morecore = true;
    #endif
    
      thread_arena = &main_arena;
      malloc_init_state (&main_arena);
    
    #if HAVE_TUNABLES
      TUNABLE_GET (top_pad, size_t, TUNABLE_CALLBACK (set_top_pad));
      TUNABLE_GET (perturb, int32_t, TUNABLE_CALLBACK (set_perturb_byte));
      TUNABLE_GET (mmap_threshold, size_t, TUNABLE_CALLBACK (set_mmap_threshold));
      TUNABLE_GET (trim_threshold, size_t, TUNABLE_CALLBACK (set_trim_threshold));
      TUNABLE_GET (mmap_max, int32_t, TUNABLE_CALLBACK (set_mmaps_max));
      TUNABLE_GET (arena_max, size_t, TUNABLE_CALLBACK (set_arena_max));
      TUNABLE_GET (arena_test, size_t, TUNABLE_CALLBACK (set_arena_test));
    # if USE_TCACHE
      TUNABLE_GET (tcache_max, size_t, TUNABLE_CALLBACK (set_tcache_max));
      TUNABLE_GET (tcache_count, size_t, TUNABLE_CALLBACK (set_tcache_count));
      TUNABLE_GET (tcache_unsorted_limit, size_t,
    	       TUNABLE_CALLBACK (set_tcache_unsorted_limit));
    # endif
      TUNABLE_GET (mxfast, size_t, TUNABLE_CALLBACK (set_mxfast));
      TUNABLE_GET (hugetlb, size_t, TUNABLE_CALLBACK (set_hugetlb));
      if (mp_.hp_pagesize > 0)
        __always_fail_morecore = true;
    #endif
    }
    ```

=== "定义与宏"

    ``` c
    static uintptr_t tcache_key;
    static void
    tcache_key_initialize (void)
    {
      if (__getrandom (&tcache_key, sizeof(tcache_key), GRND_NONBLOCK)
          != sizeof (tcache_key))
        {
          tcache_key = random_bits ();
    #if __WORDSIZE == 64
          tcache_key = (tcache_key << 32) | random_bits ();
    #endif
        }
    }
    
    static struct malloc_state main_arena =
    {
      .mutex = _LIBC_LOCK_INITIALIZER,
      .next = &main_arena,
      .attached_threads = 1
    };
    
    typedef struct malloc_chunk *mbinptr;
    #define NBINS             128
    #define bin_at(m, i) \
      (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2]))			      \
                 - offsetof (struct malloc_chunk, fd))
    #define NONCONTIGUOUS_BIT     (2U)
    
    #define contiguous(M)          (((M)->flags & NONCONTIGUOUS_BIT) == 0)
    #define noncontiguous(M)       (((M)->flags & NONCONTIGUOUS_BIT) != 0)
    #define set_noncontiguous(M)   ((M)->flags |= NONCONTIGUOUS_BIT)
    #define set_contiguous(M)      ((M)->flags &= ~NONCONTIGUOUS_BIT)
    
    #define initial_top(M)              (unsorted_chunks (M))
    #define unsorted_chunks(M)          (bin_at (M, 1))
    static void
    malloc_init_state (mstate av)
    {
      int i;
      mbinptr bin;
    
      for (i = 1; i < NBINS; ++i)
        {
          bin = bin_at (av, i);
          bin->fd = bin->bk = bin;
        }
    
      set_noncontiguous (av);
      if (av == &main_arena)
        set_max_fast (DEFAULT_MXFAST);
      atomic_store_relaxed (&av->have_fastchunks, false);
      av->top = initial_top (av);
    }
    
    struct malloc_par
    {
      unsigned long trim_threshold;
      INTERNAL_SIZE_T top_pad;
      INTERNAL_SIZE_T mmap_threshold;
      INTERNAL_SIZE_T arena_test;
      INTERNAL_SIZE_T arena_max;
      int n_mmaps;
      int n_mmaps_max;
      int max_n_mmaps;
      int no_dyn_threshold;
      INTERNAL_SIZE_T mmapped_mem;
      INTERNAL_SIZE_T max_mmapped_mem;
      char *sbrk_base;
    #if USE_TCACHE
      size_t tcache_bins;
      size_t tcache_max_bytes;
      size_t tcache_count;
      size_t tcache_unsorted_limit;
    #endif
    };
    
    # define tidx2usize(idx)	(((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)
    static struct malloc_par mp_ =
    {
      .top_pad = DEFAULT_TOP_PAD,
      .n_mmaps_max = DEFAULT_MMAP_MAX,
      .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
      .trim_threshold = DEFAULT_TRIM_THRESHOLD,
    #define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
      .arena_test = NARENAS_FROM_NCORES (1)
    #if USE_TCACHE
      ,
      .tcache_count = TCACHE_FILL_COUNT,
      .tcache_bins = TCACHE_MAX_BINS,
      .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
      .tcache_unsorted_limit = 0
    #endif
    };
    ```

### 主线1->分支2-初始化Tcache空间(MAYBE_INIT_TCACHE)
=== "主体源码与执行流程"

    ``` c
    # define MAYBE_INIT_TCACHE() \
      if (__glibc_unlikely (tcache == NULL)) \
        tcache_init();
    static void
    tcache_init(void)
    {
      mstate ar_ptr;
      void *victim = 0;
      const size_t bytes = sizeof (tcache_perthread_struct);// 64 位下通常对应一个 0x290 的 chunk
    
      if (tcache_shutting_down)
        return;
    
      arena_get (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);// 跳小分支1后返回成功分配的地址
      if (!victim && ar_ptr != NULL)
        {
          ar_ptr = arena_get_retry (ar_ptr, bytes);
          victim = _int_malloc (ar_ptr, bytes);
        }
    
      if (ar_ptr != NULL)
        __libc_lock_unlock (ar_ptr->mutex);
    
      if (victim)
        {
          tcache = (tcache_perthread_struct *) victim;
          memset (tcache, 0, sizeof (tcache_perthread_struct));
        }
    }
    ```

=== "定义与宏"

    ``` c
    typedef struct tcache_entry
    {
      struct tcache_entry *next;
      uintptr_t key;
    } tcache_entry;
    typedef struct tcache_perthread_struct
    {
      uint16_t counts[TCACHE_MAX_BINS];// TCACHE_MAX_BINS=64
      tcache_entry *entries[TCACHE_MAX_BINS];
    } tcache_perthread_struct;
    ```

### 分支2->小分支1-为tcache_perthread_struct()分配空间(\_int_malloc)

=== "主体源码与执行流程"

    ``` c
    static void *
    _int_malloc (mstate av, size_t bytes)
    {
      INTERNAL_SIZE_T nb;               /* 规范化请求大小 */
      unsigned int idx;                 /* 关联的 bin 索引 */
      mbinptr bin;                      /* 关联的 bin */
    
      mchunkptr victim;                 /* 检查/选定的 chunk */
      INTERNAL_SIZE_T size;             /* 其大小 */
      int victim_index;                 /* 其 bin 索引 */
    
      mchunkptr remainder;              /* 分割后剩余的 chunk */
      unsigned long remainder_size;     /* 其大小 */
    
      unsigned int block;               /* 位图遍历器 */
      unsigned int bit;                 /* 位图遍历器 */
      unsigned int map;                 /* binmap 的当前字 */
    
      mchunkptr fwd;                    /* 用于链接的杂项临时指针 */
      mchunkptr bck;                    /* 用于链接的杂项临时指针 */
    
    #if USE_TCACHE
      size_t tcache_unsorted_count;	    /* 处理过的 unsorted chunks 计数 */
    #endif
    
      /*
         将请求大小转换为内部形式，方法是增加 SIZE_SZ 字节的开销，
         并且可能再增加一些以获得必要的对齐和/或达到至少 MINSIZE
         （最小可分配大小）。此外，checked_request2size 对于
         过大以至于在填充和对齐后会溢出到零的请求大小返回 false。
       */
    
      if (!checked_request2size (bytes, &nb))// 标准化请求大小，并储存到nb中
        {
          __set_errno (ENOMEM);
          return NULL;
        }
    
      /* 没有可用的 arena。回退到 sysmalloc 以从 mmap 获取一个 chunk。*/
      if (__glibc_unlikely (av == NULL))
        {
          void *p = sysmalloc (nb, av);
          if (p != NULL)
    	alloc_perturb (p, bytes);
          return p;
        }					
      .......
      if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))// 目前仅看其为tcache结构体分配空间，则nb=0x290那么不会进入该条件
        {
          ......
        }
    
      /*
         如果是一个小型请求，检查常规 bin。由于这些“smallbins”
         每个只持有一种大小的 chunk，因此无需在 bin 内部进行搜索。
         （对于大型请求，我们需要等到 unsorted chunks 处理完毕才能找到最合适的。
         但对于小型请求，无论如何都是精确匹配，所以我们现在就可以检查，这更快。）
       */
    
      if (in_smallbin_range (nb))// 小于0x400为smallbin
      {
        idx = smallbin_index (nb);// 获取大小对应的在bins中的idx
        bin = bin_at (av, idx);
    
        if ((victim = last (bin)) != bin)// 由于处于初始化，bin里的bk依旧指向自己，不会进入该条件
        {
    	    ......
        }
      }
    
      /*
         如果这是一个大型请求，在继续之前先整合 fastbins。
         虽然在查看是否有可用空间之前就清除所有 fastbins 可能看起来有些过度，
         但这避免了通常与 fastbins 相关的碎片问题。
         此外，在实践中，程序倾向于运行小型或大型请求，但很少混合，
         因此在大多数程序中，整合并不会经常被调用。
         而在其他情况下频繁调用它的程序往往会产生碎片。
       */
    
      else
      {
        idx = largebin_index (nb);// 大于等于0x400会被划入largebin，不过其每个bins位置不像smallbin以0x10大小分割，而是有一定规划，后面再说
        if (atomic_load_relaxed (&av->have_fastchunks))// 判断fastbin是否为空，不为空则尝试将fastbin碎片和其他普通bins合成，不过现在不考虑，跳过
        {
          malloc_consolidate (av);
        }
      }
    
      /*
         处理最近释放或剩余的 chunk，仅在精确匹配时才取用一个；
         或者，如果这是一个小型请求，则取用最近非精确匹配的剩余 chunk。
         将其他遍历过的 chunk 放入 bin 中。
         请注意，此步骤是任何例程中唯一将 chunk 放入 bin 的地方。
    
         这里需要外部循环是因为我们可能直到 malloc 快结束时才意识到
         我们应该进行整合，因此必须这样做并重试。
         这最多发生一次，并且仅当我们本来需要扩展内存来服务“小型”请求时。
       */
    
    #if USE_TCACHE
      INTERNAL_SIZE_T tcache_nb = 0;
      size_t tc_idx = csize2tidx (nb);
      if (tcache && tc_idx < mp_.tcache_bins)// tcache是静态全局变量，保存指向tcache_perthread_struct结构体的指针，此时为null
      {
        tcache_nb = nb;
      }
      int return_cached = 0;
    
      tcache_unsorted_count = 0;
    #endif
    
      for (;; )
      {
        int iters = 0;
        while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        // 这一块应该在循环遍历unsortedbin是否有可用的，从bk即尾巴开始空，此时为空跳过
        {
    	    ......
        }
    
    #if USE_TCACHE
        /* 如果我们找到的所有小型 chunk 最终都被缓存了，现在返回一个。*/
        if (return_cached)// 为0跳过
        {
          return tcache_get (tc_idx);
        }
    #endif
    
        /*
           如果是一个大型请求，按排序顺序扫描当前 bin 中的 chunk，
           以找到最合适的最小 chunk。为此使用跳表（skip list）。
         */
    
        if (!in_smallbin_range (nb))// 非smallbin大小，跳过
        {
          ......
        }
    
        /*
           通过扫描 bins 查找 chunk，从下一个最大的 bin 开始。
           此搜索严格遵循最佳适配原则；即，选择最合适的最小 chunk
           （在大小相同的情况下，选择大约最不常使用的）。
    
           位图避免了检查大多数块是否非空的需求。
           在没有 chunk 返回的预热阶段跳过所有 bin 的特定情况，
           其速度可能比看起来的要快。
         */
    
        ++idx;
        bin = bin_at (av, idx);
        block = idx2block (idx);
        map = av->binmap[block];
        bit = idx2bit (idx);// idx2bit将idx对应的bit位设置位1
    	// 前头smallbin和largebin都没找到空闲可用的
    	// 这里获取下一个相邻 bin 的空闲 chunk 链表，并获取该 bin 对于 binmap 中的 bit 位的值。 Binmap 中的标识了相应的 bin 中是否有空闲 chunk 存在。 Binmap 按 block 管理，每个 block 为一个 int ，共 32 个 bit ，可以表示 32 个 bin 中是否有空闲 chunk 存在。使用 binmap 可以加快查找 bin 是否包含空闲 chunk 。这里只查询比所需 chunk 大的 bin 中是否有空闲 chunk 可用。
        for (;; )
        {
          /* 如果此块中没有更多置位，则跳过块的其余部分。*/
          if (bit > map || bit == 0)// 这里bit大于map，则map为0或者bit自己为0则跳过该block
          {
            do
            {
              if (++block >= BINMAPSIZE) /* out of bins */
              {
                goto use_top;
              }
            }
            while ((map = av->binmap[block]) == 0);// 一直循环遍历直到map不为0或者超出binmap范围，接下来就跳转到use_top
    
            bin = bin_at (av, (block << BINMAPSHIFT));
            bit = 1;
          }
          ......
        }
    
        use_top:
          /*
             如果足够大，则从内存末端（存储在 av->top 中）的 chunk 进行分割。
             请注意，这符合最佳适配搜索规则。
             实际上，av->top 被视为比任何其他可用 chunk 更大
             （因此适配度较差），因为它可以扩展到所需的大小
             （受系统限制）。
    
             我们要求 av->top 在初始化后始终存在（即，大小 >= MINSIZE），
             因此如果它会被当前请求耗尽，它将被补充。
             （确保它存在的主要原因是我们可能需要在 sysmalloc 中留出
             MINSIZE 空间来放置围栏（fenceposts）。）
           */
    
          victim = av->top;// 获取top_chunk的指针
          size = chunksize (victim);// 获取top_chunk大小
    
          if (__glibc_unlikely (size > av->system_mem))// 保证top_chunk大小小于之前申请的，防止top_chunk的size被修改，导致任意地址写（house of force 小于等于2.29版本可用）
          {
            malloc_printerr ("malloc(): corrupted top size");
          }
    
          if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
          //加上MINSIZE的原因是必须保证top_chunk最小是MINSIZE大小
          {
            remainder_size = size - nb;// 计算top_chunk剩下大小
            remainder = chunk_at_offset (victim, nb);// 计算top_chunk新地址
            av->top = remainder;
            set_head (victim, nb | PREV_INUSE |
                      (av != &main_arena ? NON_MAIN_ARENA : 0));// 为新鲜出炉的chunk设置低字节flag位，可以知道32位8字节对其，64位16字节对其，那么在储存size是最低3位是空闲出来的，那么最低三位恰好能用于表达一些特殊信息，从第1位开始，分别对应PREV_INUSE、IS_MMAPPED、NON_MAIN_ARENA，同时分别代表的是前一个chunk在使用，该chunk是mmap分配的，该chunk不是从main_arena分配的
            set_head (remainder, remainder_size | PREV_INUSE);
    
            check_malloced_chunk (av, victim, nb);// 深度检测不仅检测自己，还对其前一个后一个进行检测
            void *p = chunk2mem (victim);// 将指针指向该chunk可用地址，也就是去除chunk头的地址方便返回给用户
            alloc_perturb (p, bytes);// 这玩意应该特殊情况下才用，全局静态变量perturb_byte不为0的情况下申请出来的内存会被perturb_byte^0xff填充
            return p;// 返回地址
          }
    
          /* 当我们使用原子操作来释放 fast chunks 时，所有块大小都可能到达此处。*/
          else if (atomic_load_relaxed (&av->have_fastchunks))
          {
            malloc_consolidate (av);
            // 再次将fastbin等相关bin进行整合，重新获取申请chunk的大小对应的idx，再次回到上面的循环
            /* restore original bin index */
            if (in_smallbin_range (nb))
            {
              idx = smallbin_index (nb);
            }
            else
            {
              idx = largebin_index (nb);
            }
          }
    
          /*
             否则，转发以处理系统相关的情况
           */
          else
          {
            void *p = sysmalloc (nb, av);// 如果内存不够，即top_chunk不够，尝试系统调用，对于该函数内top_chunk不够，旧的topchunk如何处理(放转转上())，详细直接跳转主线2->分支3-从mmap分配
            if (p != NULL)
            {
              alloc_perturb (p, bytes);
            }
            return p;
          }
      }
    }
    ```

=== "定义与宏"

    ``` c
    static inline INTERNAL_SIZE_T
    get_max_fast (void)
    {
    	// 存在边缘大小检测，正常是128字节，不能大于160字节
      if (global_max_fast > MAX_FAST_SIZE)
        __builtin_unreachable ();
      return global_max_fast;
    }
    
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
    
    #define BINMAPSHIFT      5
    #define BITSPERMAP       (1U << BINMAPSHIFT)=32
    #define BINMAPSIZE       (NBINS / BITSPERMAP)=4
    
    #define idx2block(i)     ((i) >> BINMAPSHIFT)=i>>5
    #define idx2bit(i)       ((1U << ((i) & ((1U << BINMAPSHIFT) - 1))))
    
    #define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    
    /* 去除低字节标志位，获取原始大小 */
    #define chunksize(p) (chunksize_nomask (p) & ~(SIZE_BITS))
    
    /* 获取chunksize，没除去低字节标志位 */
    #define chunksize_nomask(p)         ((p)->mchunk_size)
    
    #define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))
    
    # define check_malloced_chunk(A, P, N)   do_check_malloced_chunk (A, P, N)
    static void
    do_check_malloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
    {
      /* 与回收情况相同... */
      do_check_remalloced_chunk (av, p, s);
    
      /*
         ... 另外，必须遵守实现的不变式：任何已分配块的 prev_inuse (前一个块在使用中) 字段始终为真；
         也就是说，每个已分配块要么与一个之前已分配且仍在使用的块相邻，要么与其内存竞技场 (arena) 的基地址相邻。
         这是通过从任何找到的块的“最低”部分进行所有分配来确保的。
         然而，通过 fastbins 回收的块不一定满足此条件。
       */
    
      assert (prev_inuse (p));
    }
    static inline struct malloc_state *
    arena_for_chunk (mchunkptr ptr)
    {
      return chunk_main_arena (ptr) ? &main_arena : heap_for_ptr (ptr)->ar_ptr;
    }
    #define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)
    
    static void
    do_check_remalloced_chunk (mstate av, mchunkptr p, INTERNAL_SIZE_T s)
    {
      INTERNAL_SIZE_T sz = chunksize_nomask (p) & ~(PREV_INUSE | NON_MAIN_ARENA);
    
      if (!chunk_is_mmapped (p))// 获取IS_MMAPPED值，判断是从arena分配还是mmap
        {
          assert (av == arena_for_chunk (p));// 确保分配出的地址和在当前av下，本质就是通过NON_MAIN_ARENA标志位判断
          if (chunk_main_arena (p))
            assert (av == &main_arena);
          else
            assert (av != &main_arena);
        }
    
      do_check_inuse_chunk (av, p);
    
      /* 合法大小 ... */
      assert ((sz & MALLOC_ALIGN_MASK) == 0);
      assert ((unsigned long) (sz) >= MINSIZE);
      /* ... 合法对其 */
      assert (aligned_OK (chunk2mem (p)));
      /* chunk is less than MINSIZE more than request */
      assert ((long) (sz) - (long) (s) >= 0);// 保证申请的比实际申请的大
      assert ((long) (sz) - (long) (s + MINSIZE) < 0);// 保证申请的比实际申请的大，不超过0x20
    }
    
    static void
    do_check_inuse_chunk (mstate av, mchunkptr p)
    {
      mchunkptr next;
    
      do_check_chunk (av, p);// 检查是否是正常chunk，所在地址是否正常
    
      if (chunk_is_mmapped (p))
        return; /* 内存映射块没有 next/prev */
    
      /* 检查它是否声明为已使用... */
    
      next = next_chunk (p);
    
      /* ... 并被正常的块包围。
         因为对空闲块的检查比对已使用块的检查更多，
         如果一个已使用块与它们相邻且调试模式开启，那么检查它们是值得的。
       */
      if (!prev_inuse (p))// 判断前一个是否正在使用
        {
          /* 请注意，我们只有在前一个块未被使用时才能查看它 */
          mchunkptr prv = prev_chunk (p);
          assert (next_chunk (prv) == p);
          do_check_free_chunk (av, prv);// 这一块检查比较复杂，简单来说是不是正常的freechunk
        }
    
      if (next == av->top)// 如果下一个是top_chunk则检测申请的chunk是否在使用中以及top_chunk是不是大于最小大小
        {
          assert (prev_inuse (next));
          assert (chunksize (next) >= MINSIZE);
        }
      else if (!inuse (next))// 判断后一个是不是正在使用，并判断是否是正常的chunk
        do_check_free_chunk (av, next);
    }
    static void
    do_check_chunk (mstate av, mchunkptr p)
    {
      unsigned long sz = chunksize (p);
      /* 假设是连续分配，最小和最大可能的地址 */
      char *max_address = (char *) (av->top) + chunksize (av->top);
      char *min_address = max_address - av->system_mem;
    
      if (!chunk_is_mmapped (p))
        {
          /* 具有合法地址 ... */
          if (p != av->top)
            {
              if (contiguous (av))
                {
                  assert (((char *) p) >= min_address);
                  assert (((char *) p + sz) <= ((char *) (av->top)));
                }
            }
          else
            {
              /* top chunk 的大小总是至少为 MINSIZE */
              assert ((unsigned long) (sz) >= MINSIZE);
              /* top chunk 的前一个块总是标记为已使用 */
              assert (prev_inuse (p));
            }
        }
      else if (!DUMPED_MAIN_ARENA_CHUNK (p))
        {
          /* 地址在主堆之外 */
          if (contiguous (av) && av->top != initial_top (av))
            {
              assert (((char *) p) < min_address || ((char *) p) >= max_address);
            }
          /* 块是页对齐的 */
          assert (((prev_size (p) + sz) & (GLRO (dl_pagesize) - 1)) == 0);
          /* 内存是对齐的 */
          assert (aligned_OK (chunk2mem (p)));
        }
    }
    
    #define chunk2mem(p) ((void*)((char*)(p) + CHUNK_HDR_SZ))
    ```
