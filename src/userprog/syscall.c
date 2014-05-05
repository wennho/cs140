#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static void syscall_handler(struct intr_frame *);
static struct lock dir_lock;

static void halt(void);
static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);

static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);

static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const char *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);

static void remove_file(int fd);
static struct file* get_file(int fd);
static void close_all_fd(void);

#ifdef VM
static mapid_t mmap (int fd, void *addr);
static void munmap (mapid_t mapping);

static void write_back_mmap_file(struct mmap_file * mmap_file);

/* Returns a hash value for mmap_file f. */
unsigned
mmap_file_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct mmap_file *f = hash_entry(e, struct mmap_file, elem);
  return hash_int(f->mapping);
}

/* Returns true if frame a precedes frame b. */
bool
mmap_file_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  struct mmap_file *fa = hash_entry(a, struct mmap_file, elem);
  struct mmap_file *fb = hash_entry(b, struct mmap_file, elem);
  return fa->mapping < fb->mapping;
}

/* Destructor function for mmap_file hash. */
void mmap_file_hash_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct mmap_file *f = hash_entry(e, struct mmap_file, elem);
  write_back_mmap_file(f);
  free(f);
}

#endif

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&dir_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  void *stack_pointer = f->esp;
  /* Must check that all four arguments are in valid memory before
   dereferencing. */
  check_memory (stack_pointer);
  check_memory ((char *) stack_pointer + 15);
  int syscall_num = *((int *) stack_pointer);
  void *arg_1 = (char *) stack_pointer + 4;
  void *arg_2 = (char *) arg_1 + 4;
  void *arg_3 = (char *) arg_2 + 4;
  /* If the caller has a return value, it stores it into
   register EAX. */
  switch (syscall_num)
    {
    case SYS_HALT:
      halt ();
      break;
    case SYS_EXIT:
      exit (*(int *) arg_1);
      break;
    case SYS_EXEC:
      f->eax = exec (*(const char **) arg_1);
      break;
    case SYS_WAIT:
      f->eax = wait (*(pid_t *) arg_1);
      break;
    case SYS_CREATE:
      f->eax = create (*(const char **) arg_1, *(unsigned *) arg_2);
      break;
    case SYS_REMOVE:
      f->eax = remove (*(const char **) arg_1);
      break;
    case SYS_OPEN:
      if (arg_1 == NULL)
        exit (-1);
      f->eax = open (*(const char **) arg_1);
      break;
    case SYS_FILESIZE:
      f->eax = filesize (*(int *) arg_1);
      break;
    case SYS_READ:
      f->eax = read (*(int *) arg_1, *(void **) arg_2, *(unsigned *) arg_3);
      break;
    case SYS_WRITE:
      f->eax = write (*(int *) arg_1, *(const char **) arg_2,
                      *(unsigned *) arg_3);
      break;
    case SYS_SEEK:
      seek (*(int *) arg_1, *(unsigned *) arg_2);
      break;
    case SYS_TELL:
      f->eax = tell (*(int *) arg_1);
      break;
    case SYS_CLOSE:
      close (*(int *) arg_1);
      break;
#ifdef VM
    case SYS_MMAP:
      f->eax = mmap (*(int *) arg_1, *(void **) arg_2);
      break;
    case SYS_MUNMAP:
      munmap (*(mapid_t *) arg_1);
      break;
#endif
    default:
      exit (-1);
      break;
    }
}

/* Terminates Pintos. Should only be seldom used. */
static
void
halt (void)
{
  shutdown_power_off ();
}

static void release_all_locks(struct thread * t){
	if(list_empty(&t->lock_list)){
		return;
	}
	struct list_elem * item = list_front(&t->lock_list);
	while (item != NULL){
		struct lock * l = list_entry(item,struct lock,elem);
		lock_release(l);
	}
}

/* Terminates the current user program, returning status to the kernel. */
void
exit (int status)
{
  struct thread *current = thread_current ();
  release_all_locks(current);
  /* Have to check that the parent has not terminated yet. */
  if (current->parent != NULL)
    {
      lock_acquire (&current->parent->child_hash_lock);
    }
  if (current->process != NULL)
    {
      ASSERT(is_process (current->process));
      /* Set exit status for child. */
      current->process->exit_status = status;
      current->process->finished = true;
    }
  file_close (current->executable);
  close_all_fd ();
#ifdef VM
  hash_destroy (&current->mmap_hash, &mmap_file_hash_destroy);
#endif
  printf ("%s: exit(%d)\n", current->name, status);
  if (current->parent != NULL)
    {
      cond_signal (&current->process->cond_on_child,
                   &current->parent->child_hash_lock);
      lock_release (&current->parent->child_hash_lock);
    }

  /* Deallocate own child_list */
  lock_acquire (&current->child_hash_lock);
  while (!list_empty (&current->child_hash))
    {
      struct list_elem *e = list_pop_front (&current->child_hash);
      struct process *p = list_entry(e, struct process, elem);
      ASSERT(is_process (p));
      /* So that child thread will not try to update freed process struct. */
      p->thread->process = NULL;
      p->thread->parent = NULL;
      free (p);
    }
  lock_release (&current->child_hash_lock);
  thread_exit ();
}

/* Closes all open files for a thread. */
static void
close_all_fd (void)
{
  struct thread *t = thread_current ();
  while (!list_empty (&t->file_hash))
    {
      struct list_elem *e = list_pop_front (&t->file_hash);
      struct opened_file *fe = list_entry(e, struct opened_file, elem);
      lock_acquire(&dir_lock);
      file_close (fe->f);
      lock_release(&dir_lock);
      free (fe);
    }
}

/* Runs the executable whose name is given in cmd_line, passing any given
 arguments, and returns the new process's program id (pid). */
static pid_t
exec (const char *cmd_line)
{
  check_string_memory (cmd_line);
  pid_t pid = process_execute (cmd_line);
  if (pid == PID_ERROR)
    {
      return pid;
    }
  struct thread* cur = thread_current ();
  lock_acquire (&cur->child_hash_lock);
  struct process* cp = process_from_tid (pid, &cur->child_hash);
  lock_release (&cur->child_hash_lock);

  /* Wait for child to check if load is successful. */
  sema_down (&cp->exec_child);

  if (cp->exit_status == -1)
    {
      return PID_ERROR;
    }
  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int
wait (pid_t pid)
{
  return process_wait (pid);
}

/* Creates a new file called file initially initial_size bytes in size. 
 Returns true if successful, false otherwise. */
static bool
create (const char *file, unsigned initial_size)
{
  check_string_memory (file);
  lock_acquire (&dir_lock);
  bool ans = filesys_create (file, initial_size);
  lock_release (&dir_lock);
  return ans;
}

/* Deletes the file called file. Returns true if successful, false 
 otherwise. */
static bool
remove (const char *file)
{
  check_string_memory (file);
  lock_acquire (&dir_lock);
  bool ans = filesys_remove (file);
  lock_release (&dir_lock);
  return ans;
}

/* Opens a file and returns its fd. */
static int
open (const char *file)
{
  check_string_memory (file);
  lock_acquire (&dir_lock);
  struct file *f = filesys_open (file);
  lock_release (&dir_lock);
  if (f == NULL)
    {
      return -1;
    }
  int fd = thread_current ()->next_fd++;
  struct opened_file * temp = malloc (sizeof(struct opened_file));
  if (temp == NULL)
    {
      return -1;
    }
  temp->f = f;
  temp->fd = fd;
  list_push_back (&thread_current ()->file_hash, &temp->elem);
  return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int
filesize (int fd)
{
  struct file *f = get_file (fd);
  int filesize = file_length (f);
  return filesize;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
 of bytes actually read (0 at end of file), or -1 if the file could not be 
 read (due to a condition other than end of file). */
static int
read (int fd, void *buffer, unsigned size)
{
  check_memory (buffer);
  check_memory ((char *) buffer + size);
  unsigned bytes = 0;
  unsigned buf = 0;
  if (fd == STDIN_FILENO)
    {
      uint8_t * temp = buffer;
      while ((temp[buf] = input_getc ()))
        {
          buf++;
          bytes++;
          if (bytes == size)
            {
              return bytes;
            }
        }
      return bytes;
    }
  struct file *f = get_file (fd);
  if (!f)
    {
      return -1;
    }

  lock_acquire (&dir_lock);
  bytes = file_read (f, buffer, size);
  lock_release (&dir_lock);

  return bytes;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
 bytes actually written, which may be less than size if some bytes could not
 be written. */
static int
write (int fd, const char *buffer, unsigned size)
{
  check_memory ((void *) buffer);
  check_memory ((char *) buffer + size);
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      return size;
    }
  struct file * f = get_file (fd);
  if (!f)
    return -1;
  int bytes = 0;
  lock_acquire (&dir_lock);
  bytes = file_write (f, buffer, size);
  lock_release (&dir_lock);
  return bytes;
}

/* Changes the next byte to be read or written in open file fd to position,
 expressed in bytes from the beginning of the file. */
static void
seek (int fd, unsigned position)
{
  struct file *f = get_file (fd);
  file_seek (f, position);
  return;
}

/* Returns the position of the next byte to be read or written in open file
 fd, expressed in bytes from the beginning of the file. */
static unsigned
tell (int fd)
{
  struct file *f = get_file (fd);
  if (!f)
    return 0;
  unsigned pos = file_tell (f);
  return pos;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly 
 closes all its open file descriptors, as if by calling this function 
 for each one. */
static
void
close (int fd)
{
  remove_file (fd);
}

#ifdef VM
/* Maps the file open as fd into the process's virtual address space.
 The entire file is mapped into consecutive virtual pages starting at addr.
 If successful, this function returns a "mapping ID" that uniquely
 identifies the mapping within the process. On failure, it returns -1. */
static
mapid_t mmap (int fd, void *addr)
{
  check_memory (addr);
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
  {
	  return MAPID_ERROR;
  }
  if ((int)addr % PGSIZE != 0 || addr == 0x0)
  {
	  return MAPID_ERROR;
  }
  struct file * file = get_file (fd);

  if (file == NULL)
  {
  	return MAPID_ERROR;
  }
  int num_bytes = filesize(fd);
  if (num_bytes == 0)
  {
	  return MAPID_ERROR;
  }
  char* current_pos = (char*)addr;
  while(true)
  {
	  check_memory(current_pos);
	  struct page_data *data = page_create_data(current_pos);
	  if (!(read(fd, (char *)current_pos, PGSIZE) > 0))
	  {
		  break;
	  }
	  current_pos += PGSIZE;
  }
  struct mmap_file * temp = malloc (sizeof(struct mmap_file));
    if (temp == NULL)
      {
        return MAPID_ERROR;
      }
  /* Should reopen file for mmap. */
  lock_acquire(&dir_lock);
  file = file_reopen(file);
  lock_release(&dir_lock);
  if (file == NULL)
  {
	  return MAPID_ERROR;
  }
  temp->file = file;
  temp->num_bytes = num_bytes;
  temp->vaddr = addr;
  mapid_t mapping = thread_current ()->next_mapping;
  temp->mapping = mapping;
  thread_current () ->next_mapping++;
  hash_insert (&thread_current ()->mmap_hash, &temp->elem);
  return mapping;
}

/* Unmaps the mapping designated by mapping, which must be a mapping ID
 returned by a previous call to mmap by the same process that has not yet
 been unmapped. */
static
void munmap (mapid_t mapping)
{
  struct thread *t = thread_current ();
  struct mmap_file f;
  struct hash_elem *e;
  f.mapping = mapping;
  e = hash_find (&t->mmap_hash, &f.elem);
  if (e != NULL)
  	  {
	  	  struct mmap_file * fp = hash_entry(e, struct mmap_file, elem);
  		  write_back_mmap_file(fp);
  		  hash_delete(&t->mmap_hash, &fp->elem);
  		  free(fp);
  	  }
}

static
void write_back_mmap_file(struct mmap_file * mmap_file)
{
  char * cur = (char*)mmap_file->vaddr;
  int num_bytes_left = mmap_file->num_bytes;
  while(num_bytes_left > 0)
  {
	  lock_acquire (&dir_lock);
	  int bytes_to_write = PGSIZE;
	  if (num_bytes_left <= PGSIZE)
	  {
		  bytes_to_write = num_bytes_left;
	  }
	  file_write (mmap_file->file, cur, bytes_to_write);
	  lock_release (&dir_lock);
	  frame_unallocate(cur);
	  num_bytes_left -= bytes_to_write;
  }
  lock_acquire(&dir_lock);
  file_close(mmap_file->file);
  lock_release(&dir_lock);
}

#endif

/* Removes a file using fd in the thread's list of files. */
static void
remove_file (int fd)
{
  struct thread *t = thread_current ();
  if (list_empty (&t->file_hash))
    return;
  struct list_elem * item;
  for (item = list_front (&t->file_hash); item != list_end (&t->file_hash);
       item = list_next (item))
  {
	  struct opened_file * fe = list_entry(item, struct opened_file, elem);
	  if (fe->fd == fd)
	  {
		  lock_acquire (&dir_lock);
		  file_close (fe->f);
		  lock_release (&dir_lock);
		  list_remove (&fe->elem);
		  free (fe);
		  return;
	  }
  }
}

/* Takes a file using fd in the thread's list of files. */
static struct file*
get_file (int fd)
{
  struct thread *t = thread_current ();
  if (list_empty (&t->file_hash))
    return NULL;
  struct list_elem * item = list_front (&t->file_hash);
  for (item = list_front (&t->file_hash); item != list_end (&t->file_hash);
          item = list_next (item))
    {
      struct opened_file * fe = list_entry(item, struct opened_file, elem);
      if (fe->fd == fd)
        return fe->f;
    }
  return NULL;
}

/* Checks that a string is entirely in valid memory and is less than PGSIZE
 in length. */
void
check_string_memory (const char *orig_address)
{
  char* str = (char*) orig_address;
  check_memory (str);
  /* If the end of the max length of the string is not in valid memory,
   check every byte until you get to the end. */
  char* max_end = str + PGSIZE;
  if (!is_user_vaddr (max_end) || (void *)max_end < (void *) 0x08048000
      || !pagedir_get_page (thread_current ()->pagedir, max_end))
  {
	  while (*str != 0)
		{
		  str += 1;
		  check_memory (str);
		}
	 }
}


/* Checks that a given memory address is valid. */
void
check_memory (void *vaddr)
{
#ifdef VM
if (!is_user_vaddr (vaddr) || vaddr < (void *) 0x08048000)
{
	exit(-1);
}
#else
  if (!is_user_vaddr (vaddr) || vaddr < (void *) 0x08048000
      || !pagedir_get_page (thread_current ()->pagedir, vaddr))
    {
      exit (-1);
    }
#endif
}
