#include "userprog/process_data.h"
#include <stddef.h>
#include <stdio.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Returns a hash value for process_data p. */
unsigned
process_data_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct process_data *p = hash_entry(e, struct process_data, elem);
  return hash_int (p->pid);
}

/* Returns true if process_data a precedes process_data b. */
bool
process_data_hash_less (const struct hash_elem *a, const struct hash_elem *b,
                        void *aux UNUSED)
{
  struct process_data *pa = hash_entry(a, struct process_data, elem);
  struct process_data *pb = hash_entry(b, struct process_data, elem);
  return pa->pid < pb->pid;
}

/* Destructor function for opened_file hash. */
void
process_data_hash_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct process_data *p = hash_entry(e, struct process_data, elem);
  ASSERT(is_process_data (p));
  /* So that child thread will not try to update freed process struct. */
  p->thread->process = NULL;
  p->thread->parent = NULL;
  free (p);
}

/* Checks that a process hasn't been corrupted and is a process. */
bool
is_process_data (struct process_data *process_data)
{
  return process_data != NULL && process_data->magic == PROCESS_DATA_MAGIC;
}

struct process_data*
process_data_create (tid_t tid)
{
  struct process_data *process_data = malloc (sizeof(struct process_data));
  ASSERT(process_data != NULL);
  sema_init (&process_data->exec_child, 0);
  cond_init (&process_data->cond_on_child);
  process_data->pid = tid;
  process_data->magic = PROCESS_DATA_MAGIC;
  process_data->exit_status = 0;
  process_data->finished = false;
  return process_data;
}

/* Gets the hash_elem specified by child_tid in the current thread's hash
 * of children. If the hash_elem is not found, it returns a NULL pointer. */
struct process_data*
process_from_tid (tid_t child_tid, struct hash *child_hash)
{
  struct process_data d;
  struct hash_elem *e;
  d.pid = child_tid;
  e = hash_find (child_hash, &d.elem);
  if (e == NULL)
    {
      return NULL;
    }
  return hash_entry(e, struct process_data, elem);
}
