#include "sgx_pmd.h"
#include "sgx.h"
#include <asm-generic/tlb.h>
#include <linux/rmap.h>

// This is required for asm-generic/tlb.h
#define tlb_flush(tlb)							\
{									\
	if (!tlb->fullmm && !tlb->need_flush_all) 			\
		flush_tlb_mm_range(tlb->mm, tlb->start, tlb->end, 0UL);	\
	else								\
		flush_tlb_mm_range(tlb->mm, 0UL, TLB_FLUSH_ALL, 0UL);	\
}

/*
 * YSSU: Function pointers required for unexported kernel symbols.
*/
pmd_t* (*mm_alloc_pmd_p)(struct mm_struct *mm, unsigned long address);

unsigned long (*zap_pte_range_p)(struct mmu_gather *tlb,
							struct vm_area_struct *vma, pmd_t *pmd,
							unsigned long addr, unsigned long end,
							struct zap_details *details);

void (*tlb_gather_mmu_p)(struct mmu_gather *tlb, struct mm_struct *mm,
										unsigned long start, unsigned long end);

void (*tlb_finish_mmu_p)(struct mmu_gather *tlb,
		unsigned long start, unsigned long end);

void (*flush_tlb_func_local_p)(void *info, enum tlb_flush_reason reason);

/*
 * YSSU: Functions to insert PMD entry for large page in EPC memory
 */
int vm_insert_pmd(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn)
{
	return vm_insert_pmd_prot(vma, addr, pfn, vma->vm_page_prot);
}

int vm_insert_pmd_prot(struct vm_area_struct *vma, unsigned long addr,
			unsigned long pfn, pgprot_t pgprot)
{
	int ret;

	if (addr < vma->vm_start || addr >= vma->vm_end)
		return -EFAULT;

	ret = insert_pmd(vma, addr, __pfn_to_pfn_t(pfn, PFN_DEV), pgprot,
			false);

	return ret;
}

int insert_pmd(struct vm_area_struct *vma, unsigned long addr,
                        pfn_t pfn, pgprot_t prot, bool mkwrite)
{
        struct mm_struct *mm = vma->vm_mm;
        int retval;
        pmd_t *pmd, entry;
        spinlock_t *ptl;

        retval = -ENOMEM;

       	mm_alloc_pmd_p = (void *)kallsyms_lookup_name("mm_alloc_pmd");
       	if(mm_alloc_pmd_p == NULL)
       		goto out;
        pmd = mm_alloc_pmd_p(mm, addr);
        if (!pmd)
                goto out;

        ptl = pmd_lock(mm, pmd);
        retval = -EBUSY;
        if (!pmd_none(*pmd)) {
                if (mkwrite) {
                        if (WARN_ON_ONCE(pmd_pfn(*pmd) != pfn_t_to_pfn(pfn)))
                                goto out_unlock;
                        entry = *pmd;
                        goto out_mkwrite;
                } else
                        goto out_unlock;
        }
        if (pfn_t_devmap(pfn))
        {
                entry = pmd_mkdevmap((pfn_t_pmd(pfn, prot)));
                entry = pmd_set_flags(entry, _PAGE_SPECIAL);
        }
        else
        	entry = pmd_set_flags((pfn_t_pmd(pfn, prot)), _PAGE_SPECIAL);
        entry = pmd_mkhuge(entry); //Setting the PAGE_PSE bit

out_mkwrite:
        if (mkwrite) {
                entry = pmd_mkyoung(entry);
								entry = pmd_mkdirty(entry);
								if(vma->vm_flags & VM_WRITE)
									entry = pmd_mkwrite(entry);
        }

        set_pmd_at(mm, addr, pmd, entry);
        update_mmu_cache_pmd(vma, addr, pmd);
				pr_info("PMD entry contents: 0x%lx\n", entry.pmd);
        retval = 0;
out_unlock:
        spin_unlock(ptl);
out:
        return retval;
}

/*
 * YSSU: Functions to remove page table entries for the enclave process.
 */

int sgx_zap_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
		 pmd_t *pmd, unsigned long addr)
{
	pmd_t orig_pmd;
	spinlock_t *ptl;
	struct page *page = NULL;

	ptl = pmd_lock(vma->vm_mm, pmd);
	if (!ptl)
		return 0;

	orig_pmd = pmdp_huge_get_and_clear_full(tlb->mm, addr, pmd,	tlb->fullmm);
	tlb_remove_pmd_tlb_entry(tlb, pmd, addr);

	if (pmd_present(orig_pmd)) {
			page = pmd_page(orig_pmd);
		}

	spin_unlock(ptl);

	return 1;
}

unsigned long sgx_zap_pmd_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pud_t *pud,
				unsigned long addr, unsigned long end)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (is_swap_pmd(*pmd) || pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
 				if(sgx_zap_huge_pmd(tlb, vma, pmd, addr))
					goto next;
		}

		if (pmd_none(*pmd))
			goto next;
		if(zap_pte_range_p == NULL)
			zap_pte_range_p = (void *)kallsyms_lookup_name("zap_pte_range");
		if(zap_pte_range_p == NULL)
		{
			//pr_err("intel_sgx: %s zap_pte_range symbol not found\n", __func__);
			return addr;
		}
		next = zap_pte_range_p(tlb, vma, pmd, addr, next, NULL);
next:
		cond_resched();
	} while (pmd++, addr = next, addr != end);

	return addr;
}

unsigned long sgx_zap_pud_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, p4d_t *p4d,
				unsigned long addr, unsigned long end)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none(*pud))
			continue;
		next = sgx_zap_pmd_range(tlb, vma, pud, addr, next);
	} while (pud++, addr = next, addr != end);

	return addr;
}

unsigned long sgx_zap_p4d_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pgd_t *pgd,
				unsigned long addr, unsigned long end)
{
	p4d_t *p4d;
	unsigned long next;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none(*p4d))
			continue;
		next = sgx_zap_pud_range(tlb, vma, p4d, addr, next);
	} while (p4d++, addr = next, addr != end);

	return addr;
}

void sgx_unmap_page_range(struct mmu_gather *tlb,
			     struct vm_area_struct *vma,
			     unsigned long addr, unsigned long end)
{
	pgd_t *pgd;
	unsigned long next;

	BUG_ON(addr >= end);
	tlb_start_vma(tlb, vma);
	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
			next = sgx_zap_p4d_range(tlb, vma, pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
	tlb_end_vma(tlb, vma);
}

void sgx_unmap_single_vma(struct mmu_gather *tlb,
		struct vm_area_struct *vma, unsigned long start_addr,
		unsigned long end_addr)
{
	unsigned long start = max(vma->vm_start, start_addr);
	unsigned long end;

	if (start >= vma->vm_end)
		return;

	end = min(vma->vm_end, end_addr);
	if (end <= vma->vm_start)
		return;

	sgx_unmap_page_range(tlb, vma, start, end);
}

void sgx_zap_page_range_single(struct vm_area_struct *vma, unsigned long address,
		unsigned long size)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mmu_gather tlb;
	unsigned long end = address + size;

	tlb_gather_mmu_p = (void *)kallsyms_lookup_name("tlb_gather_mmu");
	tlb_finish_mmu_p = (void *)kallsyms_lookup_name("tlb_finish_mmu");
	if(tlb_gather_mmu_p==NULL || tlb_finish_mmu_p==NULL)
	{
		pr_err("intel_sgx: %s symbols not found", __func__);
		return;
	}

	tlb_gather_mmu_p(&tlb, mm, address, end);
	sgx_unmap_single_vma(&tlb, vma, address, end);
	tlb_finish_mmu_p(&tlb, address, end);
}

int sgx_zap_vma_ptes(struct vm_area_struct *vma, unsigned long address,
		unsigned long size)
{
	if (address < vma->vm_start || address + size > vma->vm_end ||
			!(vma->vm_flags & VM_PFNMAP))
				return -1;
	sgx_zap_page_range_single(vma, address, size);
	return 0;
}

void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag)
{
	int cpu;

	struct flush_tlb_info info = {
		.mm = mm,
	};

	cpu = get_cpu();

	/* This is also a barrier that synchronizes with switch_mm(). */
	info.new_tlb_gen = inc_mm_tlb_gen(mm);

	/* Should we flush just the requested range? */
	if ((end != TLB_FLUSH_ALL) &&
	    !(vmflag & VM_HUGETLB) &&
	    ((end - start) >> PAGE_SHIFT) <= 33) {
		info.start = start;
		info.end = end;
	} else {
		info.start = 0UL;
		info.end = TLB_FLUSH_ALL;
	}

	if (mm == this_cpu_read(cpu_tlbstate.loaded_mm)) {
		VM_WARN_ON(irqs_disabled());
		local_irq_disable();

		flush_tlb_func_local_p = (void *)kallsyms_lookup_name("flush_tlb_func_local");
		if(flush_tlb_func_local_p == NULL)
		{
			pr_err("intel_sgx: %s symbol not found\n",__func__);
			return;
		}
		flush_tlb_func_local_p(&info, TLB_LOCAL_MM_SHOOTDOWN);
		local_irq_enable();
	}

	if (cpumask_any_but(mm_cpumask(mm), cpu) < nr_cpu_ids)
		flush_tlb_others(mm_cpumask(mm), &info);

	put_cpu();
}
