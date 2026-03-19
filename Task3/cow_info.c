// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/pagewalk.h>
#include <linux/atomic.h>
#include <linux/highmem.h>
#include <linux/rmap.h>

/*
 * Task 3 requires this structure to be defined in the implementation
 * and in user-space test programs.
 */
struct cow_info {
	unsigned long total_cow;        /* total COW pages */
	unsigned long anon_cow;         /* COW pages in anonymous VMAs */
	unsigned long file_cow;         /* COW pages in file-backed VMAs */
	unsigned long total_writable;   /* total present pages in writable VMAs */
	unsigned long num_cow_vmas;     /* writable VMAs containing >= 1 COW page */
	unsigned long cow_fault_count;  /* COW faults resolved since process creation */
};

struct cow_walk_ctx {
	struct vm_area_struct *vma;
	unsigned long total_cow;
	unsigned long anon_cow;
	unsigned long file_cow;
	unsigned long total_writable;
	bool vma_has_cow;
};

static bool cow_vma_is_interesting(struct vm_area_struct *vma)
{
	/*
	 * Task only requires standard 4KB pages.
	 * Skip hugetlb mappings and special PFNMAP mappings.
	 */
	if (!(vma->vm_flags & VM_WRITE))
		return false;

	if (vma->vm_flags & VM_HUGETLB)
		return false;

	if (vma->vm_flags & VM_PFNMAP)
		return false;

	return true;
}

static bool pte_is_cow_candidate(struct vm_area_struct *vma, pte_t pte)
{
	unsigned long pfn;
	struct page *page;

	if (!(vma->vm_flags & VM_WRITE))
		return false;

	if (!pte_present(pte))
		return false;

	/*
	 * COW page should currently be write-protected.
	 */
	if (pte_write(pte))
		return false;

	pfn = pte_pfn(pte);

	/*
	 * Zero page must not be counted as COW.
	 */
	if (is_zero_pfn(pfn))
		return false;

	if (!pfn_valid(pfn))
		return false;

	page = pfn_to_page(pfn);

	/*
	 * Assignment wording says the physical page must be mapped by
	 * more than one process. page_mapcount() matches that intent
	 * better than page_count().
	 */
	if (folio_mapcount(page_folio(page)) <= 1)
		return false;

	return true;
}

static int cow_pte_entry(pte_t *ptep, unsigned long addr,
			 unsigned long next, struct mm_walk *walk)
{
	struct cow_walk_ctx *ctx = walk->private;
	pte_t pte = ptep_get(ptep);

	/*
	 * total_writable counts present pages in writable VMAs,
	 * regardless of whether they are COW or not.
	 */
	if (pte_present(pte))
		ctx->total_writable++;

	if (!pte_is_cow_candidate(ctx->vma, pte))
		return 0;

	ctx->total_cow++;
	ctx->vma_has_cow = true;

	if (ctx->vma->vm_file)
		ctx->file_cow++;
	else
		ctx->anon_cow++;

	return 0;
}

static int cow_pmd_entry(pmd_t *pmd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk)
{
	pmd_t pmdval = pmdp_get(pmd);

	/*
	 * Do not split huge PMDs during a read-only query syscall.
	 * Task says we only need to consider standard 4KB pages.
	 */
	if (pmd_trans_huge(pmdval) || pmd_leaf(pmdval))
		walk->action = ACTION_CONTINUE;

	return 0;
}

static int cow_pud_entry(pud_t *pud, unsigned long addr,
			 unsigned long next, struct mm_walk *walk)
{
	pud_t pudval = pudp_get(pud);

	/*
	 * Same idea for huge PUD mappings.
	 */
	if (pud_trans_huge(pudval) || pud_leaf(pudval))
		walk->action = ACTION_CONTINUE;

	return 0;
}

static const struct mm_walk_ops cow_walk_ops = {
	.pud_entry  = cow_pud_entry,
	.pmd_entry  = cow_pmd_entry,
	.pte_entry  = cow_pte_entry,
	.walk_lock  = PGWALK_RDLOCK,
};

static struct task_struct *cow_info_get_task(pid_t pid)
{
	struct task_struct *task = NULL;

	if (pid == 0) {
		get_task_struct(current);
		return current;
	}

	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	return task;
}

SYSCALL_DEFINE2(cow_info, pid_t, pid, struct cow_info __user *, info)
{
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct cow_info kinfo = {0};
	struct cow_walk_ctx ctx;
	int ret = 0;

	if (pid < 0)
		return -EINVAL;

	if (!info)
		return -EFAULT;

	task = cow_info_get_task(pid);
	if (!task)
		return -ESRCH;

	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -EINVAL;
	}

	kinfo.cow_fault_count = atomic_long_read(&task->cow_fault_count);

	mmap_read_lock(mm);
	VMA_ITERATOR(vmi, mm, 0);
	for_each_vma(vmi, vma) {
		if (!cow_vma_is_interesting(vma))
			continue;

		ctx.vma = vma;
		ctx.total_cow = 0;
		ctx.anon_cow = 0;
		ctx.file_cow = 0;
		ctx.total_writable = 0;
		ctx.vma_has_cow = false;

		ret = walk_page_vma(vma, &cow_walk_ops, &ctx);
		if (ret)
			break;

		kinfo.total_cow      += ctx.total_cow;
		kinfo.anon_cow       += ctx.anon_cow;
		kinfo.file_cow       += ctx.file_cow;
		kinfo.total_writable += ctx.total_writable;

		if (ctx.vma_has_cow)
			kinfo.num_cow_vmas++;
	}

	mmap_read_unlock(mm);
	mmput(mm);
	put_task_struct(task);

	if (ret)
		return ret;

	if (copy_to_user(info, &kinfo, sizeof(kinfo)))
		return -EFAULT;

	return 0;
}
