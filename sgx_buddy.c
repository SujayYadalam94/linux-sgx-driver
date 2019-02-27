#include "sgx.h"
#include "sgx_buddy.h"

// Structure to hold state of the nodes in the tree
uint8_t page_is_split[47][(1 << (LIST_COUNT-1))-1];
extern unsigned long epc_start_addr;
struct list_head sgx_free_lists[LIST_COUNT];

/* YSSU: Initialize all the free lists required for buddy */
void sgx_init_free_lists(void)
{
	int8_t order;
	for(order = 0; order < LIST_COUNT; order++)
	 	INIT_LIST_HEAD(&sgx_free_lists[order]);
}

/*
 * Given the index, the below function returns the address corresponding to
 * that index.
 */
unsigned long ptr_for_index(int8_t order, uint16_t index,
  uint16_t tree_index)
{
  return  epc_start_addr + (tree_index * LARGE_PAGE_SIZE) +
    ((index - (1 << order) + 1) << (LARGE_PAGE_LOG2 - order));
}

/*
 * Returns the Tree index and the index in the tree for the given
 * address and order.
 */
void index_for_ptr(unsigned long ptr, int8_t order,
  uint16_t *index, uint16_t *tree_index)
{
  unsigned long tree_base_ptr;

  *tree_index = (ptr - epc_start_addr) / LARGE_PAGE_SIZE;
  tree_base_ptr = epc_start_addr + (*tree_index * LARGE_PAGE_SIZE);
  *index = ((ptr - tree_base_ptr) >> (LARGE_PAGE_LOG2 - order)) +
    (1 << order) - 1;
}

int parent_is_split(uint16_t index, uint16_t tree_index)
{
  index = (index - 1) / 2;
  return (page_is_split[tree_index][index]) & 1;
}

void flip_parent_is_split(uint16_t index, uint16_t tree_index)
{
  index = (index - 1) / 2;
  page_is_split[tree_index][index] ^= 1 << (index);
}

struct sgx_epc_page *sgx_alloc_page_buddy(unsigned int page_size)
{
	struct sgx_epc_page *entry = NULL;
	int8_t required_order, order;
  uint16_t index, tree_index;

  //If page_size is set to 1, then 2M bucket.
	required_order = page_size ? 0 : (LIST_COUNT-1);
	order = required_order;

	pr_info("%s: required_order=%d\n", __func__, required_order);

	while(order+1 != 0)
	{
		/*
     * If the list is not empty, then pop off the first entry
     * from the desired order list
     */
		if(!list_empty(&sgx_free_lists[order]))
		{
			pr_info("%s: order=%d\n", __func__, order);
			entry = list_first_entry(&sgx_free_lists[order],struct sgx_epc_page,list);
			if(!entry)
				pr_info("Unable to get the entry from the list\n");
			else if(entry->list.next == NULL || entry->list.prev == NULL)
				pr_info("Only the the list pointer is NULL\n");
			list_del(&entry->list);
		}
		else
    {
			/* Move up the bucket ladder. */
			order--;
			continue;
		}

    /*
     * Obtain the index and tree_index of the page entry obtained from the
     * free list above.
     */
		index_for_ptr(entry->pa, order, &index, &tree_index);
		if(index!=0)
			flip_parent_is_split(index, tree_index);
    /*
     * If a larger page was split to get the desired page, then need to add
     * the other half to the free list.
     */
		while (order<required_order)
		{
      struct sgx_epc_page *new_epc_page;

			index = index*2 + 1;
			order++;
			flip_parent_is_split(index, tree_index);

			new_epc_page = kzalloc(sizeof(struct sgx_epc_page), GFP_KERNEL);
			if(!new_epc_page)
			{
				pr_info("kzalloc couldnt not allocate memory\n");
				return NULL;
			}
      new_epc_page->pa = ptr_for_index(order, index+1, tree_index);
      new_epc_page->page_size = (1 << (LARGE_PAGE_LOG2 - order));

			list_add_tail(&new_epc_page->list, &sgx_free_lists[order]);
		}

		/*
		 * Workaround for when I break a 2MB page to get a 4KB page. We have to set
		 * the override the size to 4KB because we are not creating a new struct.
		 */
		entry->page_size = 1 << (LARGE_PAGE_LOG2 - required_order);
		return entry;
	}

	pr_info("intel sgx: Buddy cannot allocate a page\n");
	return NULL;
}


void sgx_free_page_buddy(struct sgx_epc_page *entry) {
  int8_t order;
  uint16_t index, tree_index;
	struct sgx_epc_page *epc_page;

  if (!entry) {
    return;
  }

  /*
   * Look up the index of the node corresponding to this address.
   */
  order = (entry->page_size == LARGE_PAGE_SIZE) ? 0 : (LIST_COUNT-1);
  index_for_ptr(entry->pa, order, &index, &tree_index);

  /*
   * Traverse up to the root node, flipping USED blocks to UNUSED and merging
   * UNUSED buddies together into a single UNUSED parent.
   */
  while (index != 0) {
    flip_parent_is_split(index, tree_index);

    /*
     * If the parent is now SPLIT, that means our buddy is USED, so don't merge
     * with it. Instead, stop the iteration here and add ourselves to the free
     * list for our bucket.
     */
    if (parent_is_split(index, tree_index))
        break;

    /*
     * If we get here, we know our buddy is UNUSED. In this case we should
     * merge with that buddy and continue traversing up to the root node. We
     * need to remove the buddy from its free list here but we don't need to
     * add the merged parent to its free list yet. That will be done once after
     * this loop is finished.
     */

    epc_page = find_page_with_pa(ptr_for_index(order,
      ((index-1) ^ 1) + 1, tree_index), order);
    if(epc_page == NULL)
      break;


    list_del(&epc_page->list);
		kfree(epc_page);

    index = (index - 1) / 2;
    order--;
  }

	entry->pa = ptr_for_index(order, index, tree_index);
	entry->page_size = 1 << (LARGE_PAGE_LOG2 - order);

  list_add_tail(&entry->list, &sgx_free_lists[order]);
}

struct sgx_epc_page *find_page_with_pa(unsigned long addr, int8_t order)
{
  struct sgx_epc_page *find_epc_page;
  list_for_each_entry(find_epc_page, &sgx_free_lists[order], list)
  {
      if(find_epc_page->pa == addr)
        return find_epc_page;
  }
  return NULL;
}
