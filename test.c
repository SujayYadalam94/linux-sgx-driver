#include "sgx.h"

void test_page(struct vm_area_struct *vma, pmd_t *pmd)
{
  struct page *page = NULL;

  page = pmd_page(orig_pmd);

}
