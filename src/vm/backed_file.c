#include "vm/backed_file.h"
#include <stddef.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"

struct backed_file * get_backed_file_by_vaddr(void * vaddr){
	return page_get_data(vaddr)->backing_file;
}

/* Returns a hash value for mmap_file f. */
unsigned
backed_file_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct backed_file *f = hash_entry(e, struct backed_file, elem);
  return hash_int (f->mapping);
}

/* Returns true if file a precedes file b. */
bool
backed_file_hash_less (const struct hash_elem *a, const struct hash_elem *b,
                     void *aux UNUSED)
{
  struct backed_file *fa = hash_entry(a, struct backed_file, elem);
  struct backed_file *fb = hash_entry(b, struct backed_file, elem);
  return fa->mapping < fb->mapping;
}

/* Destructor function for mmap_file hash. */
void
backed_file_hash_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct backed_file *f = hash_entry(e, struct backed_file, elem);
  if(!f->is_segment)
    {
      backed_file_write_back (f);
    }
  lock_acquire (&filesys_lock);
  file_close (f->file);
  lock_release (&filesys_lock);
  free (f);
}

/* Write back an mmap file. */
void
backed_file_write_back(struct backed_file * mmap_file)
{
  int offset = 0;
  while (mmap_file->num_bytes > offset)
    {
      struct page_data* data = page_get_data((char*)mmap_file->vaddr + offset);
      ASSERT(is_page_data(data));
      if(page_is_dirty(data))
        {
          backed_file_write_back_page(mmap_file, offset, data->readable_bytes);
        }
      frame_deallocate(data->vaddr, false, 0);
      hash_delete (&thread_current()->supplemental_page_table, &data->hash_elem);
      pagedir_clear_page(thread_current()->pagedir,data->vaddr);
      free(data);
      offset += PGSIZE;
    }
}

/* Write back a single mmaped_page. */
void backed_file_write_back_page(struct backed_file * mmap_file, int offset, int readable_bytes)
{
  page_multi_pin((char*)mmap_file->vaddr + offset, readable_bytes);
  file_write_at (mmap_file->file, (char*)mmap_file->vaddr + offset, readable_bytes, offset);
  page_multi_unpin ((char*)mmap_file->vaddr + offset, readable_bytes);
}
