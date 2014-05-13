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
#include "userprog/mmap_file.h"
#include "userprog/opened_file.h"
#include "userprog/process_data.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/page.h"

struct lock dir_lock;
static void syscall_handler(struct intr_frame *);

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

#ifdef VM
static mapid_t mmap (int fd, void *addr, void *stack_pointer);
static void munmap (mapid_t mapping);
static bool is_valid_mmap_memory(const void *vaddr, const void *stack_pointer);
#endif

static bool is_valid_memory(const void *vaddr);

#define CODE_SEGMENT_END (void *) 0x08048000

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
#ifdef VM
  thread_current()->esp = stack_pointer;
#endif
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
      f->eax = mmap (*(int *) arg_1, *(void **) arg_2, stack_pointer);
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

static void
release_all_locks (struct thread * t)
{
  if (list_empty (&t->lock_list))
    {
      return;
    }
  struct list_elem * item = list_front (&t->lock_list);
  while (item != NULL)
    {
      struct lock * l = list_entry(item, struct lock, elem);
      lock_release (l);
    }
}

/* Terminates the current user program, returning status to the kernel. */
void
exit (int status)
{
  struct thread *current = thread_current ();
  release_all_locks (current);
  /* Have to check that the parent has not terminated yet. */
  if (current->parent != NULL)
    {
      lock_acquire (&current->parent->child_hash_lock);
    }
  if (current->process != NULL)
    {
      ASSERT(is_process_data (current->process));
      /* Set exit status for child. */
      current->process->exit_status = status;
      current->process->finished = true;
    }
  printf ("%s: exit(%d)\n", current->name, status);
  lock_acquire (&dir_lock);
  file_close (current->executable);
  lock_release (&dir_lock);
  hash_destroy (&current->file_hash, &opened_file_hash_destroy);
  /* Consult the supplemental page table, decide what resource to free */
#ifdef VM
  hash_destroy (&current->mmap_hash, &mmap_file_hash_destroy);
#endif
  if (current->parent != NULL)
    {
      cond_signal (&current->process->cond_on_child,
                   &current->parent->child_hash_lock);
      lock_release (&current->parent->child_hash_lock);
    }
  /* Deallocate own child_list */
  lock_acquire (&current->child_hash_lock);
  hash_destroy (&current->child_hash, &process_data_hash_destroy);
  lock_release (&current->child_hash_lock);
  thread_exit ();
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
  struct process_data* cp = process_from_tid (pid, &cur->child_hash);
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
  if(file == NULL)
	  exit(-1);
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
  if(file == NULL)
	  exit(-1);
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
  hash_insert (&thread_current ()->file_hash, &temp->elem);
  return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int
filesize (int fd)
{
  struct file *f = get_file (fd);
  if (!f)
    {
      return 0;
    }
  lock_acquire (&dir_lock);
  int filesize = file_length (f);
  lock_release (&dir_lock);
  return filesize;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
 of bytes actually read (0 at end of file), or -1 if the file could not be 
 read (due to a condition other than end of file). */
static int
read (int fd, void *buffer, unsigned size)
{
#ifdef VM
  /* Check memory on each page. */
  char* i;
  for(i = (char*)buffer; i < (char*)buffer + size; i += PGSIZE)
  {
	  check_memory_write(i, thread_current()->esp);
  }
#else
  check_memory (buffer);
  check_memory ((char *) buffer + size);
#endif
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
  struct file *f = get_file (fd);
  if (!f)
    {
      return -1;
    }
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
  if (!f)
    {
      return;
    }
  lock_acquire (&dir_lock);
  file_seek (f, position);
  lock_release (&dir_lock);
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
 The entire file is mapped into consecutive virtual pages starting at vaddr.
 If successful, this function returns a "mapping ID" that uniquely
 identifies the mapping within the process. On failure, it returns -1. */
static mapid_t
mmap (int fd, void *vaddr, void* stack_pointer)
{
  check_memory (vaddr);
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
  {
	  return MAPID_ERROR;
  }
  if ((int) vaddr % PGSIZE != 0 || vaddr == 0x0)
    {
      return MAPID_ERROR;
    }
  struct file * file = get_file (fd);
  if (file == NULL)
    {
      return MAPID_ERROR;
    }
  int num_bytes = filesize (fd);
  if (num_bytes == 0)
    {
	  /* Have to create page and set it correctly to prevent reading. */


	  struct page_data* data = page_create_data (vaddr);
	  data->is_mapped = true;
	  pagedir_clear_page(thread_current()->pagedir, vaddr);
      return MAPID_ERROR;
    }
  char* current_pos = (char*) vaddr;
  /* set all pages that mmap memories are to be mapped
   * using the page-set_is_mapped function
   */
  while (true)
    {
      if (!is_valid_mmap_memory(current_pos, stack_pointer))
      {
    	 /* We have to free the frames we've allocated. */
    	 char* i;
    	 for(i = (char*)vaddr; i < current_pos; i += PGSIZE)
    	 {
    		 frame_unallocate((void*)i);
    	 }
         return MAPID_ERROR;
      }
      if (!(read (fd, current_pos, PGSIZE) > 0))
        {
          break;
        }
      page_set_is_mapped (current_pos, true);
      current_pos += PGSIZE;
    }

  struct mmap_file * temp = malloc (sizeof(struct mmap_file));
  if (temp == NULL)
    {
      return MAPID_ERROR;
    }
  /* Should reopen file for mmap. */
  lock_acquire (&dir_lock);
  file = file_reopen (file);
  lock_release (&dir_lock);
  if (file == NULL)
    {
      return MAPID_ERROR;
    }
  temp->file = file;
  temp->num_bytes = num_bytes;
  temp->vaddr = vaddr;
  mapid_t mapping = thread_current ()->next_mapping;
  temp->mapping = mapping;
  thread_current ()->next_mapping++;
  hash_insert (&thread_current ()->mmap_hash, &temp->elem);
  return mapping;
}

/* Unmaps the mapping designated by mapping, which must be a mapping ID
 returned by a previous call to mmap by the same process that has not yet
 been unmapped. */
static
void
munmap (mapid_t mapping)
{
  struct thread *t = thread_current ();
  struct mmap_file f;
  struct hash_elem *e;
  f.mapping = mapping;
  e = hash_find (&t->mmap_hash, &f.elem);
  if (e != NULL)
    {
      struct mmap_file * fp = hash_entry(e, struct mmap_file, elem);
      write_back_mmap_file (fp);
      hash_delete (&t->mmap_hash, &fp->elem);
      free (fp);
    }
}

#endif

static bool
is_valid_memory (const void *vaddr)
{
#ifdef VM
  return is_user_vaddr (vaddr);
#else
  return is_user_vaddr (vaddr) && (void *)vaddr > CODE_SEGMENT_END
  && pagedir_get_page (thread_current ()->pagedir, vaddr);
#endif
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

  if (!is_valid_memory (max_end))
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
check_memory (const void *vaddr)
{
  if (!is_valid_memory (vaddr))
    {
      exit (-1);
    }
}

#ifdef VM
/* Checks that we are reading from a valid address. Must be above stack pointer */
void
check_memory_read (const void *vaddr, const void *stack_pointer)
{
  if (!is_valid_memory (vaddr) || vaddr < stack_pointer || !page_get_data(vaddr))
    {
      exit (-1);
    }
}

/* Checks that we are writing into an good address. Must be at most 32 bytes
 * below stack pointer (PUSHA instruction accesses 32 bytes below) */
void
check_memory_write (const void *vaddr, const void *stack_pointer)
{

  if (!is_valid_memory (vaddr) || page_is_read_only (vaddr)
      || stack_pointer > vaddr + 32)
    {
      exit (-1);
    }
}

/* Checks that a given memory address is valid for mmap. */
static
bool is_valid_mmap_memory(const void *vaddr, const void *stack_pointer)
{
	if (!is_valid_memory (vaddr) || vaddr + PGSIZE - 1 > stack_pointer
	    || page_is_read_only(vaddr) || page_is_mapped(vaddr))
	  {
	    return false;
	  }
	return true;
}
#endif
