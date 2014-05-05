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

static mapid_t mmap (int fd, void *addr);
static void munmap (mapid_t mapping);

static void remove_file(int fd);
static struct file* get_file(int fd);
static void close_all_fd(void);

static void write_back_mmap_file(struct mmap_file * mmap_file);
static void munmap_all_mmap(void);

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
    case SYS_MMAP:
      mmap (*(int *) arg_1, *(void **) arg_2);
      break;
    case SYS_MUNMAP:
      munmap (*(mapid_t *) arg_1);
      break;
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
      lock_acquire (&current->parent->child_list_lock);
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
  munmap_all_mmap ();
  printf ("%s: exit(%d)\n", current->name, status);
  if (current->parent != NULL)
    {
      cond_signal (&current->process->cond_on_child,
                   &current->parent->child_list_lock);
      lock_release (&current->parent->child_list_lock);
    }

  /* Deallocate own child_list */
  lock_acquire (&current->child_list_lock);
  while (!list_empty (&current->child_list))
    {
      struct list_elem *e = list_pop_front (&current->child_list);
      struct process *p = list_entry(e, struct process, elem);
      ASSERT(is_process (p));
      /* So that child thread will not try to update freed process struct. */
      p->thread->process = NULL;
      p->thread->parent = NULL;
      free (p);
    }
  lock_release (&current->child_list_lock);
  thread_exit ();
}

/* Closes all open files for a file. */
static void
close_all_fd (void)
{
  struct thread *t = thread_current ();
  while (!list_empty (&t->file_list))
    {
      struct list_elem *e = list_pop_front (&t->file_list);
      struct opened_file *fe = list_entry(e, struct opened_file, elem);
      file_close (fe->f);
      free (fe);
    }
}

/* Closes all open files for a file. */
static void
munmap_all_mmap (void)
{
  struct thread *t = thread_current ();
  while (!list_empty (&t->mmap_list))
    {
	  struct list_elem *e = list_pop_front (&t->mmap_list);
	  struct mmap_file *fe = list_entry(e, struct mmap_file, elem);
	  write_back_mmap_file(fe);
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
  lock_acquire (&cur->child_list_lock);
  struct process* cp = process_from_tid (pid, &cur->child_list);
  lock_release (&cur->child_list_lock);

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
  list_push_back (&thread_current ()->file_list, &temp->elem);
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
  if (file == NULL || filesize(fd) == 0)
  {
  	return MAPID_ERROR;
  }
  int pages_read = 0;
  char* current_pos = (char*)addr;
  while(true)
  {
	  check_memory(current_pos);
	  struct page_data *data = page_create_data(current_pos);
	  if (!read(fd, (char *)current_pos, PGSIZE) > 0)
	  {
		  break;
	  }
	  pages_read++;
	  current_pos += PGSIZE;
  }
  struct mmap_file * temp = malloc (sizeof(struct mmap_file));
    if (temp == NULL)
      {
        return MAPID_ERROR;
      }
  /* Should reopen file for mmap. */
  file = file_reopen(file);
  if (file == NULL)
  {
	  return MAPID_ERROR;
  }
  temp->file = file;
  temp->num_pages = pages_read;
  temp->vaddr = addr;
  temp->mapping = thread_current ()->next_mapping++;
  list_push_back (&thread_current ()->mmap_list, &temp->elem);
  return temp->mapping;
}

/* Unmaps the mapping designated by mapping, which must be a mapping ID
 returned by a previous call to mmap by the same process that has not yet
 been unmapped. */
static
void munmap (mapid_t mapping)
{
  struct thread *t = thread_current ();
    struct list_elem * item;
    for (item = list_front (&t->mmap_list); item != list_end (&t->mmap_list);
  		  item = list_next (item))
    {
  	  struct mmap_file * fe = list_entry(item, struct mmap_file, elem);
  	  if (fe->mapping == mapping)
  	  {
  		  write_back_mmap_file(fe);
  		  break;
  	  }
    }
}

static
void write_back_mmap_file(struct mmap_file * mmap_file)
{
  int i = 0;
  char * cur = (char*)mmap_file->vaddr;
  for(i = 0; i < mmap_file->num_pages; i++)
  {
	  lock_acquire (&dir_lock);
	  file_write (mmap_file->file, cur, PGSIZE);
	  lock_release (&dir_lock);
	  frame_unallocate(cur);
	  cur += PGSIZE;
  }
}

/* Removes a file using fd in the thread's list of files. */
static void
remove_file (int fd)
{
  struct thread *t = thread_current ();
  if (list_empty (&t->file_list))
    return;
  struct list_elem * item;
  for (item = list_front (&t->file_list); item != list_end (&t->file_list);
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
  if (list_empty (&t->file_list))
    return NULL;
  struct list_elem * item = list_front (&t->file_list);
  for (item = list_front (&t->file_list); item != list_end (&t->file_list);
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
