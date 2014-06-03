#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "userprog/syscall.h"
#endif
#ifdef VM
#include "vm/backed_file.h"
#include "vm/page.h"
#endif

#define max(a,b) a > b ? a : b

/* Random value for struct thread's `magic' member.
 Used to detect stack overflow.  See the big comment at the top
 of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
 that are ready to run but not actually running. */
/* threads are inserted in priority order, with highest priority at the head */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
 when they are first scheduled and removed when they exit. */
static struct list all_list;

struct list sleep_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
{
  void *eip; /* Return address. */
  thread_func *function; /* Function to call. */
  void *aux; /* Auxiliary data for function. */
};

/* Statistics. */
static long long idle_ticks; /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks; /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */
static fixed_point_t load_avg; /* Load average on CPU. */

/* If false (default), use round-robin scheduler.
 If true, use multi-level feedback queue scheduler.
 Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread * running_thread (void);
static struct thread * next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void * alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
 that's currently running into a thread.  This can't work in
 general and it is possible in this case only because loader.S
 was careful to put the bottom of the stack at a page boundary.

 Also initializes the run queue and the tid lock.

 After calling this function, be sure to initialize the page
 allocator before trying to create any threads with
 thread_create().

 It is not safe to call thread_current() until this function
 finishes. */
void
thread_init (void)
{
  ASSERT(intr_get_level () == INTR_OFF);
  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  list_init (&sleep_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
  //initial_thread->current_directory = dir_open_root();
  /* Initializes load average to zero. */
  load_avg = __mk_fix (0);
}

/* Starts preemptive thread scheduling by enabling interrupts.
 Also creates the idle thread. */
void
thread_start (void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
 Thus, this function runs in an external interrupt context. */
void
thread_tick (void)
{
  struct thread *t = thread_current ();
  /* Adds one to current thread's cpu time. */
  t->recent_cpu = fix_add (t->recent_cpu, fix_int (1));
  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void)
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
 PRIORITY, which executes FUNCTION passing AUX as the argument,
 and adds it to the ready queue.  Returns the thread identifier
 for the new thread, or TID_ERROR if creation fails.

 If thread_start() has been called, then the new thread may be
 scheduled before thread_create() returns.  It could even exit
 before thread_create() returns.  Contrariwise, the original
 thread may run for any amount of time before the new thread is
 scheduled.  Use a semaphore or some other form of
 synchronization if you need to ensure ordering.

 The code provided sets the new thread's `priority' member to
 PRIORITY, but no actual priority scheduling is implemented.
 Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority, thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT(function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);

  tid = t->tid = allocate_tid ();

#ifdef USERPROG
  t->parent = thread_current ();
  t->process = process_data_create (tid);
  t->process->thread = t;
  if (t->parent->parent == NULL)
    {
      hash_init (&t->parent->child_hash, &process_data_hash,
                 &process_data_hash_less, NULL);
    }
  hash_init (&t->child_hash, &process_data_hash, &process_data_hash_less, NULL);
  hash_insert (&thread_current ()->child_hash, &t->process->elem);
  hash_init (&t->file_hash, &opened_file_hash, &opened_file_hash_less, NULL);
#endif

#ifdef VM
  t->next_backed_file_id = 0;
  hash_init (&t->backed_file_hash_table, &backed_file_hash, &backed_file_hash_less, NULL);
  hash_init (&t->supplemental_page_table, &page_hash, &page_less, NULL);
#endif

  //t->current_directory = t->parent->current_directory;
  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void
  (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  /* Add to run queue. */
  thread_unblock (t);
  thread_yield ();
  return tid;
}

/* Finds a thread priority from the linked-list element referring
 to the thread. */
int
get_thread_priority_from_elem (const struct list_elem *le)
{
  struct thread *t = list_entry(le, struct thread, elem);
  ASSERT(is_thread (t));
  return t->priority;
}

/* Don't use this for sorting the list. It is used for the list_max function
 * only */
bool
compare_thread_priority (const struct list_elem *a, const struct list_elem *b,
                         void *aux UNUSED)
{
  ASSERT(intr_get_level () == INTR_OFF);
  return get_thread_priority_from_elem (a) < get_thread_priority_from_elem (b);

}

/* Puts the current thread to sleep.  It will not be scheduled
 again until awoken by thread_unblock().

 This function must be called with interrupts turned off.  It
 is usually a better idea to use one of the synchronization
 primitives in synch.h. */
void
thread_block (void)
{
  ASSERT(!intr_context ());
  ASSERT(intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
 This is an error if T is not blocked.  (Use thread_yield() to
 make the running thread ready.)

 This function does not preempt the running thread.  This can
 be important: if the caller had disabled interrupts itself,
 it may expect that it can atomically unblock a thread and
 update other data. */
void
thread_unblock (struct thread *t)
{
  enum intr_level old_level;

  ASSERT(is_thread (t));

  old_level = intr_disable ();
  ASSERT(t->status == THREAD_BLOCKED);
  list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void)
{
  return thread_current ()->name;
}

/* Returns the running thread.
 This is running_thread() plus a couple of sanity checks.
 See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void)
{
  struct thread *t = running_thread ();

  /* Make sure T is really a thread.
   If either of these assertions fire, then your thread may
   have overflowed its stack.  Each thread has less than 4 kB
   of stack, so a few big automatic arrays or moderate
   recursion can cause stack overflow. */
  ASSERT(is_thread (t));
  ASSERT(t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void)
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
 returns to the caller. */
void
thread_exit (void)
{
  ASSERT(!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif
  /* Remove thread from all threads list, set our status to dying,
   and schedule another process.  That process will destroy us
   when it calls thread_schedule_tail(). */

  intr_disable ();
  struct thread *t = thread_current ();

  ASSERT(list_empty (&t->lock_list));

  list_remove (&t->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ()
  ;
}

/* Yields the CPU.  The current thread is not put to sleep and
 may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void)
{
  struct thread *cur = thread_current ();
  ASSERT(!intr_context ());

  enum intr_level old_level = intr_disable ();

  /* Check if we are the highset priority. if we are, do nothing. */
  if (!list_empty (&ready_list))
    {
      struct thread *t = list_entry(
          list_max(&ready_list, &compare_thread_priority, NULL), struct thread,
          elem);
      ASSERT(is_thread (t));
      if (t->priority >= cur->priority)
        {
          if (cur != idle_thread)
            list_push_back (&ready_list, &cur->elem);
          cur->status = THREAD_READY;
          schedule ();
        }
    }

  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
 This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT(intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list); e = list_next (e))
    {

      struct thread *t = list_entry(e, struct thread, allelem);
      func (t, aux);
    }
}

/* Resets the priority of the current thread based on the locks it holds. */
void
thread_reset_current_priority (void)
{
  int maxPriority = thread_current ()->original_priority;
  struct list_elem *e;
  struct list *list = &thread_current ()->lock_list;

  for (e = list_begin (list); e != list_end (list); e = list_next (e))
    {
      struct lock *lock = list_entry(e, struct lock, elem);
      if (!list_empty (&(lock->semaphore.waiters)))
        {
          struct list_elem *max_elem = list_max (&(lock->semaphore.waiters),
                                                 &compare_thread_priority,
                                                 NULL);
          struct thread *max_thread = list_entry(max_elem, struct thread, elem);
          ASSERT(is_thread (max_thread));
          maxPriority = max(maxPriority, max_thread->priority);
        }
    }

  thread_current ()->priority = maxPriority;
}

/* Update current thread's priority (taking donations into account) before
 calling a function which checks whether it is necessary to yield. */
void
thread_reset_priority_and_yield (void)
{
  if (!thread_mlfqs)
    {
      thread_reset_current_priority ();
    }
  thread_yield ();
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority)
{
  if (new_priority < PRI_MIN)
    new_priority = PRI_MIN;
  if (new_priority > PRI_MAX)
    new_priority = PRI_MAX;

  enum intr_level old_level = intr_disable ();
  thread_current ()->original_priority = new_priority;
  thread_reset_priority_and_yield ();
  intr_set_level (old_level);
}
/* Returns the current thread's priority. */
int
thread_get_priority (void)
{
  return thread_current ()->priority;
}

/* Recalculates priority of thread. */
void
thread_recalculate_priority (struct thread *t, void *aux UNUSED)
{
  fixed_point_t fix_priority = fix_int (PRI_MAX);
  fix_priority = fix_sub (fix_priority, fix_div (t->recent_cpu, fix_int (4)));
  fix_priority = fix_sub (fix_priority, fix_int (t->niceness * 2));
  int m = fix_trunc (fix_priority);
  if (m < PRI_MIN)
    m = PRI_MIN;
  if (m > PRI_MAX)
    m = PRI_MAX;
  t->priority = m;
}

/* Sets the current thread's nice value to NICE, recalculates priority. */
void
thread_set_nice (int nice)
{
  enum intr_level old_level = intr_disable ();
  thread_current ()->niceness = nice;
  thread_recalculate_priority (thread_current (), NULL);
  thread_yield ();
  intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void)
{
  return thread_current ()->niceness;
}

/* Recalculates the load average. */
void
recalculate_load_avg (void)
{
  enum intr_level old_level = intr_disable ();
  fixed_point_t scaled_load_avg = fix_mul (fix_frac (59, 60), load_avg);
  int num_ready_threads = list_size (&ready_list);
  if (thread_current () != idle_thread)
    num_ready_threads++;
  fixed_point_t add_amount = fix_mul (fix_frac (1, 60),
                                      fix_int (num_ready_threads));
  load_avg = fix_add (scaled_load_avg, add_amount);
  intr_set_level (old_level);
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void)
{
  return fix_round (fix_mul (load_avg, fix_int (100)));
}

/* Recalculates recent_cpu value for a given thread. */
void
thread_recalculate_recent_cpu (struct thread *t, void *aux UNUSED)
{
  fixed_point_t double_load_avg = fix_mul (load_avg, fix_int (2));
  fixed_point_t coefficient = fix_div (double_load_avg,
                                       fix_add (double_load_avg, fix_int (1)));
  fixed_point_t intermediate_num = fix_mul (coefficient, t->recent_cpu);
  t->recent_cpu = fix_add (intermediate_num, fix_int (t->niceness));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void)
{
  return fix_round (fix_mul (thread_current ()->recent_cpu, fix_int (100)));
}

/* Idle thread.  Executes when no other thread is ready to run.

 The idle thread is initially put on the ready list by
 thread_start().  It will be scheduled once initially, at which
 point it initializes idle_thread, "up"s the semaphore passed
 to it to enable thread_start() to continue, and immediately
 blocks.  After that, the idle thread never appears in the
 ready list.  It is returned by next_thread_to_run() as a
 special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;)
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

       The `sti' instruction disables interrupts until the
       completion of the next instruction, so these two
       instructions are executed atomically.  This atomicity is
       important; otherwise, an interrupt could be handled
       between re-enabling interrupts and waiting for the next
       one to occur, wasting as much as one clock tick worth of
       time.

       See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
       7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux)
{
  ASSERT(function != NULL);

  intr_enable (); /* The scheduler runs with interrupts off. */
  function (aux); /* Execute the thread function. */
  thread_exit (); /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
   down to the start of a page.  Because `struct thread' is
   always at the beginning of a page and the stack pointer is
   somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
 NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT(t != NULL);
  ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT(name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->original_priority = priority;
  list_init (&t->lock_list);

  t->magic = THREAD_MAGIC;
  t->lock_blocked_by = NULL;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);

#ifdef USERPROG
  t->next_fd = 2;
  lock_init (&t->child_hash_lock);
  t->process = NULL;
#endif

  /* Added fields. */
  t->niceness = 0;
  t->recent_cpu = fix_int (0);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
 returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT(is_thread (t));
  ASSERT(size % sizeof(uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
 return a thread from the run queue, unless the run queue is
 empty.  (If the running thread can continue running, then it
 will be in the run queue.)  If the run queue is empty, return
 idle_thread. */
static struct thread *
next_thread_to_run (void)
{
  ASSERT(intr_get_level () == INTR_OFF);
  if (list_empty (&ready_list))
    return idle_thread;
  else
    {
      struct list_elem* elem = list_pop_max (&ready_list,
                                             &compare_thread_priority, NULL);
      return list_entry(elem, struct thread, elem);
    }
}

/* Completes a thread switch by activating the new thread's page
 tables, and, if the previous thread is dying, destroying it.

 At this function's invocation, we just switched from thread
 PREV, the new thread is already running, and interrupts are
 still disabled.  This function is normally invoked by
 thread_schedule() as its final action before returning, but
 the first time a thread is scheduled it is called by
 switch_entry() (see switch.S).

 It's not safe to call printf() until the thread switch is
 complete.  In practice that means that printf()s should be
 added at the end of the function.

 After this function and its caller returns, the thread switch
 is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();

  ASSERT(intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
   thread.  This must happen late so that thread_exit() doesn't
   pull out the rug under itself.  (We don't free
   initial_thread because its memory was not obtained via
   palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
    {
      ASSERT(prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
 the running process's state must have been changed from
 running to some other state.  This function finds another
 thread to run and switches to it.

 It's not safe to call printf() until thread_schedule_tail()
 has completed. */
static void
schedule (void)
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT(intr_get_level () == INTR_OFF);
  ASSERT(cur->status != THREAD_RUNNING);
  ASSERT(is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);

}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
 Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof(struct thread, stack);
