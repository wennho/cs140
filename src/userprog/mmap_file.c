#ifdef VM
#include "userprog/mmap_file.h"
#include <stddef.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"

struct mmap_file * get_mmap_file_by_vaddr(void * vaddr){
	return page_get_data(vaddr)->backing_file;
}

/* Returns a hash value for mmap_file f. */
unsigned
mmap_file_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct mmap_file *f = hash_entry(e, struct mmap_file, elem);
  return hash_int (f->mapping);
}

/* Returns true if file a precedes file b. */
bool
mmap_file_hash_less (const struct hash_elem *a, const struct hash_elem *b,
                     void *aux UNUSED)
{
  struct mmap_file *fa = hash_entry(a, struct mmap_file, elem);
  struct mmap_file *fb = hash_entry(b, struct mmap_file, elem);
  return fa->mapping < fb->mapping;
}

/* Destructor function for mmap_file hash. */
void
mmap_file_hash_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct mmap_file *f = hash_entry(e, struct mmap_file, elem);
  write_back_mmap_file (f);
  free (f);
}

/* Write back an mmap file. */
void
write_back_mmap_file(struct mmap_file * mmap_file)
{
  int offset = 0;
  while (mmap_file->num_bytes > offset)
    {
      struct page_data* data = page_get_data((char*)mmap_file->vaddr + offset);
      data->is_unmapped = true;
      if(page_is_dirty(data))
        {
          write_back_mapped_page(mmap_file, offset, data->readable_bytes);
        }
      offset += PGSIZE;
    }
  lock_acquire (&dir_lock);
  file_close (mmap_file->file);
  lock_release (&dir_lock);
}

/* Write back a single mmaped_page. */
void write_back_mapped_page(struct mmap_file * mmap_file, int offset, int readable_bytes)
{
  lock_acquire (&dir_lock);
  file_write_at (mmap_file->file, mmap_file->vaddr, readable_bytes, offset);
  lock_release (&dir_lock);
  pagedir_set_dirty(thread_current()->pagedir, (char*)mmap_file->vaddr + offset, false);
  pagedir_set_accessed(thread_current()->pagedir, (char*)mmap_file->vaddr + offset, false);
}
#endif
