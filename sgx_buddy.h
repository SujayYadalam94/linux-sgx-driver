#include "sgx.h"

/*YSSU: For buddy */
#define LIST_COUNT (LARGE_PAGE_SHIFT - PAGE_SHIFT +1)

void sgx_init_free_lists(void);
unsigned long ptr_for_index(int8_t order, uint16_t index,
  uint16_t tree_index);
void index_for_ptr(unsigned long ptr, int8_t order,
    uint16_t *index, uint16_t *tree_index);
int parent_is_split(uint16_t index, uint16_t tree_index);
void flip_parent_is_split(uint16_t index, uint16_t tree_index);
struct sgx_epc_page *sgx_alloc_page_buddy(unsigned int page_size);
void sgx_free_page_buddy(struct sgx_epc_page *entry);
struct sgx_epc_page *find_page_with_pa(unsigned long addr, int8_t order);
void print_free_list_count(void);
