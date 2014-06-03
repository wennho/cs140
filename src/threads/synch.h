#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

/* A counting semaphore. */
struct semaphore 
  {
    unsigned value;             /* Current value. */
    struct list waiters;        /* List of waiting threads. */
  };

void sema_init (struct semaphore *, unsigned value);
void sema_down (struct semaphore *);
bool sema_try_down (struct semaphore *);
void sema_up (struct semaphore *);
void sema_self_test (void);

/* Lock. */
struct lock 
  {
    struct thread *holder;      /* Thread holding lock (for debugging). */
    struct semaphore semaphore; /* Binary semaphore controlling access. */
    struct list_elem elem;
  };

void lock_init (struct lock *);
void lock_acquire (struct lock *);
bool lock_try_acquire (struct lock *);
void lock_release (struct lock *);
bool lock_held_by_current_thread (const struct lock *);

/* Condition variable. */
struct condition 
  {
    struct list waiters;        /* List of waiting threads. */
  };

void cond_init (struct condition *);
void cond_wait (struct condition *, struct lock *);
void cond_signal (struct condition *, struct lock *);
void cond_broadcast (struct condition *, struct lock *);

/* reader-writer lock. allows multiple readers to read it simultaneously */
struct rw_lock
{
  struct lock lock;
  struct condition can_write;
  struct condition can_read;
  int num_reading;
  int num_writing;
  int num_wait_writers;
};

void rw_lock_init(struct rw_lock* lock);
void rw_lock_reader_acquire(struct rw_lock* lock);
void rw_lock_writer_acquire(struct rw_lock* lock);
void rw_lock_reader_release(struct rw_lock* lock);
void rw_lock_writer_release(struct rw_lock* lock);

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile ("" : : : "memory")
int get_sem_priority_from_elem (const struct list_elem *le);
bool compare_sem_priority (const struct list_elem *a,
    const struct list_elem *b, void *aux);
void update_priority_after_acquiring_lock(struct lock *lock);
void priority_donate(struct thread *t, int priority, int level);

#endif /* threads/synch.h */
