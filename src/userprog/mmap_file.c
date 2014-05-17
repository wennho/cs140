#ifdef VM
#include "userprog/mmap_file.h"
#include <stddef.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

struct mmap_file * get_mmap_file_by_vaddr(void * vaddr UNUSED){
	return page_get_data(vaddr)->mmap_struct;
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
  return fa->mapping+fa->byte_offset < fb->mapping+fb->byte_offset;
}

/* Destructor function for mmap_file hash. */
void
mmap_file_hash_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct mmap_file *f = hash_entry(e, struct mmap_file, elem);
  write_back_mmap_file (f);
  free (f);
}

/* for each piece of the mmap file, write it back.
 * Only done if the particular vaddr is dirty.
 * called by munmap and by eviction program
 */
void
write_back_mmap_file(struct mmap_file * mmap_file)
{
	void *vaddr = mmap_file->vaddr;

    struct file * file = mmap_file->file;
    /* moves us to the right position in file */
    lock_acquire (&dir_lock);
    file_write_at (mmap_file->file, vaddr, PGSIZE,
                   mmap_file->byte_offset);
    lock_release (&dir_lock);
    frame_unallocate (vaddr);
/*  void *vaddr = mmap_file->vaddr;
  int num_bytes_left = mmap_file->num_bytes;
  while (num_bytes_left > 0)
    {
      int bytes_to_write = PGSIZE;
      if (num_bytes_left <= PGSIZE)
        {
          bytes_to_write = num_bytes_left;
        }
      lock_acquire (&dir_lock);
      file_write (mmap_file->file, vaddr, bytes_to_write);
      lock_release (&dir_lock);
      frame_unallocate (vaddr);
      num_bytes_left -= bytes_to_write;
    }
  lock_acquire (&dir_lock);
  file_close (mmap_file->file);
  lock_release (&dir_lock);
*/}
#endif
