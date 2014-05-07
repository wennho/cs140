#ifdef VM
#include "userprog/mmap_file.h"
#include <stddef.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

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

void
write_back_mmap_file (struct mmap_file * mmap_file)
{
  char * cur = (char*) mmap_file->vaddr;
  int num_bytes_left = mmap_file->num_bytes;
  while (num_bytes_left > 0)
    {
      int bytes_to_write = PGSIZE;
      if (num_bytes_left <= PGSIZE)
        {
          bytes_to_write = num_bytes_left;
        }
      lock_acquire (&dir_lock);
      file_write (mmap_file->file, cur, bytes_to_write);
      lock_release (&dir_lock);
      frame_unallocate (cur);
      num_bytes_left -= bytes_to_write;
    }
  lock_acquire (&dir_lock);
  file_close (mmap_file->file);
  lock_release (&dir_lock);
}
#endif
