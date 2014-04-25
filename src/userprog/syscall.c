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

void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&dir_lock);
}

static void syscall_handler(struct intr_frame *f) {
	void *stack_pointer = f->esp;
	/* Must check that all four arguments are in valid memory before
	 dereferencing. */
	check_memory(stack_pointer);
	check_memory((char *) stack_pointer + 15);
	int syscall_num = *((int *) stack_pointer);
	void *arg_1 = (char *) stack_pointer + 4;
	void *arg_2 = (char *) arg_1 + 4;
	void *arg_3 = (char *) arg_2 + 4;
	/* If the caller has a return value, it stores it into
	 register EAX. */
	switch (syscall_num) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(*(int *) arg_1);
		break;
	case SYS_EXEC:
		f->eax = exec(*(const char **) arg_1);
		break;
	case SYS_WAIT:
		f->eax = wait(*(pid_t *) arg_1);
		break;
	case SYS_CREATE:
		f->eax = create(*(const char **) arg_1, *(unsigned *) arg_2);
		break;
	case SYS_REMOVE:
		f->eax = remove(*(const char **) arg_1);
		break;
	case SYS_OPEN:
		if (arg_1 == NULL)
			exit(-1);
		f->eax = open(*(const char **) arg_1);
		break;
	case SYS_FILESIZE:
		f->eax = filesize(*(int *) arg_1);
		break;
	case SYS_READ:
		f->eax = read(*(int *) arg_1, *(void **) arg_2, *(unsigned *) arg_3);
		break;
	case SYS_WRITE:
		f->eax = write(*(int *) arg_1, *(const char **) arg_2,
				*(unsigned *) arg_3);
		break;
	case SYS_SEEK:
		seek(*(int *) arg_1, *(unsigned *) arg_2);
		break;
	case SYS_TELL:
		f->eax = tell(*(int *) arg_1);
		break;
	case SYS_CLOSE:
		close(*(int *) arg_1);
		break;
	default:
		exit(-1);
		break;
	}
}

/* Terminates Pintos. Should only be seldom used. */
static
void halt(void) {
	shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. */
void
exit (int status)
{
  struct thread *current = thread_current();

  lock_acquire (&current->parent->child_list_lock);

  if (current->process != NULL){
      ASSERT(is_process (current->process));
      /* Set exit status for child. */
      current->process->exit_status = status;
      current->process->finished = true;
    }

  file_close(current->executable);
  close_all_fd();
  printf("%s: exit(%d)\n", current->name, status);

  cond_signal(&current->process->cond_on_child, &current->parent->child_list_lock);

  lock_release (&current->parent->child_list_lock);

  /* deallocate own child_list */
  lock_acquire(&current->child_list_lock);
  while (!list_empty(&current->child_list)){
      struct list_elem *e = list_pop_front (&current->child_list);
      struct process *p = list_entry(e, struct process, elem);
      ASSERT(is_process(p));
      /* so that child thread will not try to update freed process struct */
      p->thread->process = NULL;
      free(p);
  }

  lock_release(&current->child_list_lock);
  thread_exit();
}

void
close_all_fd(void){

  struct thread *t = thread_current();

  while (!list_empty (&t->file_list))
    {
      struct list_elem *e = list_pop_front (&t->file_list);
      struct opened_file *fe = list_entry(e, struct opened_file, elem);
      file_close(fe->f);
      free(fe);
    }

}

/* Runs the executable whose name is given in cmd_line, passing any given
 arguments, and returns the new process's program id (pid). */
static pid_t
exec (const char *cmd_line)
{
	lock_acquire(&dir_lock);
  check_string_memory (cmd_line);
  pid_t pid = process_execute (cmd_line);
  if (pid == -1)
  {
	  lock_release(&dir_lock);
	  return pid;
  }

  struct thread* cur = thread_current();
  lock_acquire(&cur->child_list_lock);
  struct process* cp = process_from_tid (pid, &cur->child_list);
  lock_release(&cur->child_list_lock);

  /* Wait for child to check if load is successful. */
  sema_down(&cp->exec_child);

  if (cp->exit_status == -1)
  {
      pid = -1;
  }
  lock_release(&dir_lock);
  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int wait(pid_t pid) {
	return process_wait(pid);
}



/* Creates a new file called file initially initial_size bytes in size. 
 Returns true if successful, false otherwise. */
static bool create(const char *file, unsigned initial_size) {
	lock_acquire(&dir_lock);
	check_string_memory(file);
	bool ans = filesys_create(file, initial_size);
	lock_release(&dir_lock);
	return ans;
}

/* Deletes the file called file. Returns true if successful, false 
 otherwise. */
static bool remove(const char *file) {
<<<<<<< HEAD
	lock_acquire(&dir_lock);
	check_memory((void *) file);
	check_memory((char *) file + NAME_MAX);
	bool ans = filesys_remove(file);
	lock_release(&dir_lock);
	return ans;

=======
  check_string_memory(file);
	return filesys_remove(file);
>>>>>>> 41390626ea4959e45111f1b4efc41e1350e76861
}

static int
open (const char *file)
{
<<<<<<< HEAD
  lock_acquire(&dir_lock);
  check_memory((void *)file);
  check_memory((char *)file + NAME_MAX);
=======
  check_string_memory(file);
>>>>>>> 41390626ea4959e45111f1b4efc41e1350e76861
  struct file *f = filesys_open(file);
  if(f == NULL) return -1;
  int fd = thread_current()->next_fd++;
  struct opened_file * temp = malloc(sizeof(struct opened_file));
  if (temp == NULL)
  {
	  lock_release(&dir_lock);
	  return -1;
  }
  temp->f = f;
  temp->fd = fd;
  list_push_back(&thread_current()->file_list, &temp->elem);
  lock_release(&dir_lock);
  return fd;
}


/* Returns the size, in bytes, of the file open as fd. */
static int 
filesize (int fd)
{
  struct file *f = get_file(fd);
  int filesize = file_length(f);
  return filesize;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
 of bytes actually read (0 at end of file), or -1 if the file could not be 
 read (due to a condition other than end of file). */
static int read(int fd, void *buffer, unsigned size) {
	lock_acquire(&dir_lock);
	check_memory(buffer);
	check_memory((char *) buffer + size);
	unsigned bytes = 0;
	unsigned buf = 0;
	if (fd == STDIN_FILENO) {
		uint8_t * temp = buffer;
		while ((temp[buf] = input_getc())) {
			buf++;
			bytes++;
			if (bytes == size){
				lock_release(&dir_lock);
				return bytes;
			}
		}
		return bytes;
	}
	struct file *f = get_file(fd);
	if (!f){
		lock_release(&dir_lock);
		return -1;
	}

	bytes = file_read(f, buffer, size);
	lock_release(&dir_lock);
	return bytes;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
 bytes actually written, which may be less than size if some bytes could not
 be written. */

static int write(int fd, const char *buffer, unsigned size)
{
	check_memory((void *)buffer);
	check_memory((char *)buffer + size);
	if(fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		return size;
	}
	struct file * f = get_file(fd);
	if (!f)
		return -1;
	int bytes = 0;
	bytes = file_write(f, buffer, size);
	return bytes;
}

/* Changes the next byte to be read or written in open file fd to position,
 expressed in bytes from the beginning of the file. */
static void seek(int fd, unsigned position) {
	struct file *f = get_file(fd);
	file_seek(f, position);
	return;
}

/* Returns the position of the next byte to be read or written in open file
 fd, expressed in bytes from the beginning of the file. */
static unsigned tell(int fd) {
	struct file *f = get_file(fd);
	if (!f)
		return 0;
	unsigned pos = file_tell(f);
	return pos;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly 
 closes all its open file descriptors, as if by calling this function 
 for each one. */
static
void close(int fd)
{
	remove_file(fd);
}


/* Removes a file using fd in the thread's list of files. */
void remove_file(int fd) {
	struct thread *t = thread_current();
	if (list_empty(&t->file_list))
		return;
	struct list_elem * item = list_front(&t->file_list);
	while (item != NULL) {
		struct opened_file * fe = list_entry(item, struct opened_file, elem);
		if (fe->fd == fd) {
		  file_close(fe->f);
			list_remove (&fe->elem);
			free (fe);
			return;
		}
		item = list_next(item);
	}
}



/* Takes a file using fd in the thread's list of files. */
struct file* get_file(int fd) {
	struct thread *t = thread_current();
	if (list_empty(&t->file_list))
		return NULL;
	struct list_elem * item = list_front(&t->file_list);
	while (item != NULL) {
		struct opened_file * fe = list_entry(item, struct opened_file, elem);
		if (fe->fd == fd)
			return fe->f;
		item = list_next(item);
	}
	return NULL;
}

void
check_string_memory (const char *orig_address)
{
  char* str = (char*) orig_address;
  check_memory (str);
  while (*str != 0)
    {
      str += 4;
      check_memory (str);
      if ((uint32_t) str - (uint32_t) orig_address > PGSIZE)
        {
          exit (-1);
        }
    }
}

void check_memory(void *vaddr) {
	if (!is_user_vaddr(vaddr) || vaddr < (void *) 0x08048000
			|| !pagedir_get_page(thread_current()->pagedir, vaddr)) {
		exit(-1);
	}
}
