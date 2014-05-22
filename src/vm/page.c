#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"


#define PAGE_MAGIC 0xacedba5e

static void page_multi_set_pin(const void* vaddr, int num_bytes, bool pin_value);

/* Indicates that a page corresponds to a mapped file and sets the file. */
void page_set_mmaped_file (struct page_data *data, struct mmap_file *mmap_file, int offset, int readable_bytes)
{
	data->is_mapped = true;
	data->backing_file = mmap_file;
	data->file_offset = offset;
	data->readable_bytes = readable_bytes;
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
  frame_deallocate(data->vaddr, data->is_in_swap, data->sector);
  free(data);
}

/* Takes a virtual address, returns the page_data if existent.
 Returns NULL if vaddr is not found in the hash table */
struct page_data*
page_get_data(const void* vaddr)
{
  struct page_data p;
  p.vaddr = (void*)pg_round_down(vaddr);
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

static
void page_multi_set_pin(const void* vaddr, int num_bytes, bool pin_value)
{
  char* current_pos;
  void* highest_pin_vaddr = pg_round_down((char*)vaddr + num_bytes);
  void* lowest_pin_vaddr = pg_round_down(vaddr);
  thread_current()->lowest_pin_vaddr = lowest_pin_vaddr;
  thread_current()->highest_pin_vaddr = highest_pin_vaddr;
  for(current_pos = (char*)lowest_pin_vaddr; current_pos <= (char*)highest_pin_vaddr;
      current_pos += PGSIZE)
    {
      struct page_data* data = page_get_data(current_pos);
      if(data)
        {
          data->is_pinned = pin_value;
        }
    }
}

void page_multi_pin(const void* vaddr, int num_bytes)
{
  /* Only pin in the context of IO. */
  lock_acquire(&filesys_lock);
  page_multi_set_pin(vaddr, num_bytes, true);
}

void page_multi_unpin(const void* vaddr, int num_bytes)
{
  /* IO is done, release lock. */
  page_multi_set_pin(vaddr, num_bytes, false);
  thread_current()->highest_pin_vaddr = (void*)NO_PINNED_VADDR;
  thread_current()->lowest_pin_vaddr = (void*)NO_PINNED_VADDR;
  lock_release(&filesys_lock);
}

bool
page_is_dirty(struct page_data *data)
{
  return pagedir_is_dirty(thread_current ()->pagedir, data->vaddr);
}

struct page_data*
page_create_data (void* upage)
{
  struct page_data* data = malloc (sizeof(struct page_data));
  data->vaddr = upage;
  data->is_in_swap = false;
  data->is_mapped = false;
  data->magic = PAGE_MAGIC;
  data->sector = 0;
  data->backing_file = NULL;
  data->file_offset = 0;
  data->is_writable = true;
  data->is_dirty = false;
  data->readable_bytes = 0;
  data->is_pinned = false;
  lock_init(&data->lock);
  ASSERT(hash_insert (&thread_current ()->supplemental_page_table, &data->hash_elem) == NULL);
  return data;
}
