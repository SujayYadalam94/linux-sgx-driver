#include "sgx.h"
#include <linux/mm.h>
#include <linux/pfn_t.h>
#include <linux/hugetlb.h>
#include <linux/kallsyms.h>

int vm_insert_pmd(struct vm_area_struct *vma, unsigned long addr,
                        unsigned long pfn);
int vm_insert_pmd_prot(struct vm_area_struct *vma, unsigned long addr,
                        unsigned long pfn, pgprot_t pgprot);
int insert_pmd(struct vm_area_struct *vma, unsigned long addr,
                        pfn_t pfn, pgprot_t prot, bool mkwrite);
int sgx_zap_vma_ptes(struct vm_area_struct *vma, unsigned long address,
                                unsigned long size);
void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
                                            unsigned long end, unsigned long vmflag);
