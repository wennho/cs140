#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "page.h"

#define PAGE_MAGIC 0xacedba5e

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page_data *p = hash_entry(p_, struct page_data, hash_elem);
  return hash_bytes (&p->addr, sizeof p->addr);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct page_data *a = hash_entry(a_, struct page_data, hash_elem);
  const struct page_data *b = hash_entry(b_, struct page_data, hash_elem);

  return (uint32_t) a->addr < (uint32_t) b->addr;
}

void
free_page_data (struct hash_elem *e, void *aux UNUSED)
{
  struct page_data *data = hash_entry(e, struct page_data, hash_elem);
  ASSERT(is_page_data (data));
  free (data);
}

bool
is_page_data (const struct page_data *data)
{
  return data != NULL && data->magic == PAGE_MAGIC;
}

struct page_data*
create_page_data (void* upage)
{
  struct page_data* data = malloc (sizeof(struct page_data));
  data->addr = upage;
  data->is_in_filesys = false;
  data->is_in_swap = false;
  data->magic = PAGE_MAGIC;
  return data;
}
