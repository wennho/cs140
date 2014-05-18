#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"


#define PAGE_MAGIC 0xacedba5e

/* Indicates that a page corresponds to a mapped file and sets the file. */
void page_set_mmaped_file (void* vaddr, struct mmap_file * mmap_file, int offset)
{
	struct page_data * data = page_get_data(vaddr);
	ASSERT(is_page_data(data));
	data->is_being_mapped = true;
	data->is_mapped = true;
	data->mmap_file = mmap_file;
	data->mmap_offset = offset;
}

/* Checks if the page at vaddr is mapped. */
bool page_is_mapped (const void* vaddr)
{
	struct page_data * data = page_get_data(vaddr);
	if(data != NULL)
    {
      ASSERT(is_page_data (data));
      return page_get_data (vaddr)->is_mapped;
    }
	return false;
}

/* Checks if the page as vaddr was unmapped. */
bool page_is_unmapped (const void* vaddr)
{
  struct page_data * data = page_get_data(vaddr);
  if(data != NULL)
    {
      ASSERT(is_page_data (data));
      return page_get_data (vaddr)->is_unmapped;
    }
  return false;
}

/* Checks if the page at vaddr is read_only. */
bool page_is_read_only (const void* vaddr)
{
	struct page_data * data = page_get_data(vaddr);
	if(data != NULL)
	{
		return page_get_data (vaddr)->is_read_only;
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

void page_destroy(struct page_data *data)
{
  hash_delete(&thread_current ()->supplemental_page_table, &data->hash_elem);
  free(data);
}

/* Destructor function for supplemental page hash. */
void page_hash_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct page_data *data = hash_entry(e, struct page_data, hash_elem);
  ASSERT(is_page_data (data));
  free(data);
}

/* Takes a virtual address, returns the page_data if
 * Returns NULL if vaddr is not found in the hash table */
struct page_data*
page_get_data(const void* vaddr)
{
  struct page_data p;
  p.vaddr = (void*)vaddr;
  struct hash_elem *e = hash_find(&thread_current ()->supplemental_page_table, &p.hash_elem);
  if (e == NULL)
	  return NULL;
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
  data->is_read_only = false;
  data->is_in_swap = false;
  data->is_mapped = false;
  data->is_unmapped = false;
  data->needs_recreate = false;
  data->magic = PAGE_MAGIC;
  data->sector = 0;
  data->mmap_file = NULL;
  data->mmap_offset = 0;
  data->is_being_mapped = false;
  ASSERT(hash_insert (&thread_current ()->supplemental_page_table, &data->hash_elem) == NULL);
  return data;
}
