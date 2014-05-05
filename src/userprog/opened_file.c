#include "userprog/opened_file.h"
#include <stddef.h>
#include <stdio.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/thread.h"


/* Returns a hash value for opened_file f. */
unsigned
opened_file_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct opened_file *f = hash_entry(e, struct opened_file, elem);
  return hash_int(f->fd);
}

/* Returns true if frame a precedes frame b. */
bool
opened_file_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  struct opened_file *fa = hash_entry(a, struct opened_file, elem);
  struct opened_file *fb = hash_entry(b, struct opened_file, elem);
  return fa->fd < fb->fd;
}

/* Destructor function for opened_file hash. */
void opened_file_hash_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct opened_file *f = hash_entry(e, struct opened_file, elem);
  file_destruct(f);
  free(f);
}

/* Removes a file using fd in the thread's hash of files. */
void
remove_file (int fd)
{
  struct opened_file * fe = get_file(fd);
  if (fe != NULL)
  {
	  file_destruct(fe);
	  struct thread *t = thread_current ();
	  hash_delete (&t->file_hash, &fe->elem);
	  free (fe);
  }
}

void
file_destruct (struct opened_file * fe)
{
	lock_acquire (&dir_lock);
	file_close (fe->f);
	lock_release (&dir_lock);
}

/* Takes a file using fd in the thread's list of files. */
struct opened_file*
get_file (int fd)
{
  struct thread *t = thread_current ();
  struct opened_file f;
  struct hash_elem *e;
  f.fd = fd;
  e = hash_find (&t->file_hash, &f.elem);
  if (e != NULL)
  {
  	  return hash_entry(e, struct opened_file, elem);
  }
  return NULL;
}



