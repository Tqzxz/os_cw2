#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/uaccess.h>
#include <linux/pgtable.h>
#include <linux/rcupdate.h>
#include <linux/errno.h>

struct addr_space_info{
    unsigned long num_vmas;
    unsigned long num_anon;
    unsigned long num_file;
    unsigned long num_w_and_x;
    unsigned long total_mapped;
    unsigned long total_resident;
    unsigned long largest_gap;
    unsigned long stack_size;
    unsigned long heap_size;
};


static unsigned long count_present_pages_in_vma(
    struct mm_struct *mm,
    struct vm_area_struct *vma)
{
    unsigned long addr;
    unsigned long count = 0;

    for ( addr = vma->vm_start;addr < vma->vm_end; addr += PAGE_SIZE)
    {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        spinlock_t *ptl;
        
        pgd = pgd_offset(mm,addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd))
            continue;

        p4d = p4d_offset(pgd,addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d))
            continue;

        pud = pud_offset(p4d,addr);
        if (pud_none(*pud) || pud_bad(*pud))
            continue;

#ifdef pud_leaf
        if (pud_leaf(*pud))
            continue; 
#endif

        pmd = pmd_offset(pud,addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd))
            continue;

#ifdef pmd_leaf
        if (pmd_leaf(*pmd))
        continue;

#endif

        if(pmd_trans_huge(*pmd) || pmd_devmap(*pmd))
            continue; 

        pte = pte_offset_map_lock(mm,pmd,addr,&ptl);
        if(!pte)
            continue;

        if(pte_present(*pte))
            count++;

        pte_unmap_unlock(pte,ptl);
    }

    return count;

}

SYSCALL_DEFINE2(va_space_stat,pid_t,pid,struct addr_space_info __user *, info)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma; 
    struct addr_space_info kinfo = {0};
    unsigned long prev_end = 0;
    bool first_vma = true;


    if(pid < 0)
        return -EINVAL;

    if(!info)
        return -EINVAL;

    if( pid == 0){
        task = current;
        mm   = get_task_mm(task);
        if (!mm)
            return -EINVAL;
    } else {
        rcu_read_lock();
        task = find_task_by_vpid(pid);
        if(task)
            get_task_struct(task);
        rcu_read_unlock();

        if(!task)
            return -EINVAL;

        mm = get_task_mm(task);
        put_task_struct(task);

        if(!mm)
            return -EINVAL;
    }
    mmap_read_lock(mm);

    VMA_ITERATOR(vmi,mm,0);
    for_each_vma(vmi,vma){
        unsigned long vma_size = vma->vm_end - vma->vm_start;

        kinfo.num_vmas++;
        kinfo.total_mapped += vma_size;

        if(vma->vm_file)
            kinfo.num_file++;
        else 
            kinfo.num_anon++;

        if((vma->vm_flags & VM_WRITE) && (vma->vm_flags & VM_EXEC))
            kinfo.num_w_and_x++;

        if(!first_vma){
            unsigned long gap = vma->vm_start - prev_end;
            if( gap > kinfo.largest_gap)
                kinfo.largest_gap = gap;
        }else{
            first_vma = false;
        }

        prev_end = vma->vm_end;

        if( (mm->start_stack >= vma->vm_start) && (mm->start_stack < vma->vm_end)){
            kinfo.stack_size = vma_size;
        }

        kinfo.total_resident += count_present_pages_in_vma(mm,vma);
    }

    kinfo.heap_size = mm->brk - mm->start_brk;

    mmap_read_unlock(mm);

    mmput(mm);

    if( copy_to_user(info, &kinfo, sizeof(kinfo)))
        return -EINVAL;

    return 0;
}