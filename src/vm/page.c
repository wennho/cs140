#include "page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"


#define PAGE_MAGIC 0xacedba5e

/* Sets the "is_mapped" of the page at vaddr to is_mapped. */
void page_set_is_mapped (void* vaddr, bool is_mapped)
{
	page_get_data (vaddr)->is_mapped = is_mapped;
}

/* Checks if the page at vaddr is mapped. */
bool page_is_mapped (void* vaddr)
{
	struct page_data * data = page_get_data(vaddr);
	if(data != NULL)
	{
		return page_get_data (vaddr)->is_mapped;
	}
	return false;
}

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page_data *p = hash_entry(p_, struct page_data, hash_elem);
  return hash_bytes (&p->vaddr, sizeof p->vaddr);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct page_data *a = hash_entry(a_, struct page_data, hash_elem);
  const struct page_data *b = hash_entry(b_, struct page_data, hash_elem);
  return (uint32_t) a->vaddr < (uint32_t) b->vaddr;
}

bool
is_page_data (const struct page_data *data)
{
  return data != NULL && data->magic == PAGE_MAGIC;
}

/* Destructor function for supplemental page hash. */
void page_hash_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct page_data *data = hash_entry(e, struct page_data, hash_elem);
  ASSERT(is_page_data (data));
  free(data);
}

/* Returns NULL if addr is not found in the hash table */
struct page_data*
page_get_data(void* vaddr)
{
  struct page_data p;
  p.vaddr = vaddr;
  struct hash_elem *e = hash_find(&thread_current ()->supplemental_page_table, &p.hash_elem);
  struct page_data *data = hash_entry(e, struct page_data, hash_elem);
  if(data != NULL)
  {
	  ASSERT(is_page_data (data));
	  return data;
  }
  return NULL;
}

struct page_data*
page_create_data (void* upage)
{
  struct page_data* data = malloc (sizeof(struct page_data));
  data->vaddr = upage;
  data->is_in_filesys = false;
  data->is_in_swap = false;
  data->magic = PAGE_MAGIC;
  ASSERT(hash_insert (&thread_current ()->supplemental_page_table, &data->hash_elem) == NULL);
  return data;
}
