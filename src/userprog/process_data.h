#ifndef PROCESS_DATA_H_
#define PROCESS_DATA_H_

#include <hash.h>
#include <stdbool.h>
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"

typedef int tid_t;

/* Struct containing process-related information.
 * This is separate from the main thread struct because we need
 * this information to persist even if the current thread exits.  */
struct process_data
{
  int pid;
  int exit_status;                    /* Process's exit status. */
  struct condition cond_on_child;     /* Used in wait. */
  struct semaphore exec_child;        /* Used in exec. */
  struct hash_elem elem;              /* For inclusion in a hash. */
  struct thread* thread;              /* The process's own thread. */
  bool finished;                      /* Indicates if exit_status is valid. */
  /* For checking if we are dealing with a valid process struct */
  unsigned magic;
};

#define PROCESS_DATA_MAGIC 0xdeadbeef

unsigned process_data_hash (const struct hash_elem *e, void *aux);
bool process_data_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void process_data_hash_destroy(struct hash_elem *e, void *aux);

bool is_process_data (struct process_data *process_data);
struct process_data* process_data_create (tid_t tid);
struct process_data* process_from_tid (tid_t child_tid, struct hash *child_hash);

#endif /* PROCESS_DATA_H_ */
