#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame *);

static void halt(void);
static void convert_ptr(void *vaddr);
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
}

static void syscall_handler(struct intr_frame *f)
{
	void *stack_pointer = f->esp;
	/* Must check that all four arguments are in valid memory before
	 dereferencing. */
	check_mem(stack_pointer);
	check_mem((char *)stack_pointer + 15);
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
		f->eax = wait(*(pid_t *)arg_1);
		break;
	case SYS_CREATE:
		f->eax = create(*(const char **)arg_1,*(unsigned *) arg_2);
		break;
	case SYS_REMOVE:
		f->eax = remove(*(const char **) arg_1);
		break;
	case SYS_OPEN:
		if(arg_1 == NULL) exit(-1);
		f->eax = open(*(const char **) arg_1);
		break;
	case SYS_FILESIZE:
		f->eax = filesize(*(int *) arg_1);
		break;
	case SYS_READ:
		f->eax = read(*(int *) arg_1, *(void **)arg_2, *(unsigned *) arg_3);
		break;
	case SYS_WRITE:
		f->eax = write(*(int *) arg_1, *(const char **) arg_2, *(unsigned *) arg_3);
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
void halt(void)
{
	shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. */
void
exit (int status)
{
	const char* format = "%s: exit(%d)\n";
	/* maybe should use snprintf? */
	// int length = strlen(thread_current ()->name) + strlen(format) + 2;
	printf(format, thread_current()->name, status);
  intr_disable ();
  thread_unblock (thread_current()->parent);
  thread_current()->parent->child_exit_status = status;
  thread_exit();
}

/* Runs the executable whose name is given in cmd_line, passing any given
 arguments, and returns the new process's program id (pid). */
static pid_t
exec (const char *cmd_line)
{
  convert_ptr((void *)cmd_line);
  pid_t pid = process_execute (cmd_line);
  return pid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int
wait (pid_t pid)
{
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in size. 
 Returns true if successful, false otherwise. */
static bool create(const char *file, unsigned initial_size)
{
	convert_ptr((void *)file);
	return filesys_create(file, initial_size);
}

/* Deletes the file called file. Returns true if successful, false 
 otherwise. */
static bool
remove (const char *file)
{
	convert_ptr((void *)file);
  return filesys_remove(file);
}

/* Opens the file called file. */
static int
open (const char *file)
{
  convert_ptr((void *)file);
  struct file *f = filesys_open(file);
  if(f == NULL) return -1;
  int fd = thread_current()->next_fd++;
  struct opened_file * temp = malloc(sizeof(struct opened_file));
  if (!temp) return -1;
  /* deny write to an open file */
	file_deny_write(f);
  temp->f = f;
  temp->fd = fd;
  list_push_back(&thread_current()->file_list,&temp->elem);
  return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int 
filesize (int fd)
{
  struct file *f = get_file(fd);
  int filesize = file_length(f);
  /* TO IMPLEMENT. */
  return filesize;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
 of bytes actually read (0 at end of file), or -1 if the file could not be 
 read (due to a condition other than end of file). */
static int read(int fd, void *buffer, unsigned size) {
	convert_ptr((void *)buffer);
	unsigned bytes = 0;
	unsigned buf = 0;
	if(fd == STDIN_FILENO){
		uint8_t * temp = buffer;
		while ((temp[buf] = input_getc())){
			buf++;
			bytes++;
			if (bytes == size) return bytes;
		}
		return bytes;
	}
	struct file *f = get_file(fd);
	if (!f) return -1;
	bytes = file_read(f, buffer, size);
	return bytes;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
 bytes actually written, which may be less than size if some bytes could not
 be written. */
static int write(int fd, const char *buffer, unsigned size) {
	convert_ptr((void *)buffer);
	if(fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		return size;
	}
	struct file * f = get_file(fd);
	if (!f) return -1;
	int bytes = file_write(f, buffer, size);
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
	if (!f) return 0;
	unsigned pos = file_tell(f);
	return pos;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly 
 closes all its open file descriptors, as if by calling this function 
 for each one. */
static
void close(int fd)
{
	struct file *f = get_file(fd);
	file_close(f);
	remove_file(fd);
}

/* Removes a file using fd in the thread's list of files. */
void remove_file(int fd)
{
	struct thread *t = thread_current();

	if (list_empty(&t->file_list))
		return;
	struct list_elem * item = list_front(&t->file_list);
	while (item != NULL) {
		struct opened_file * fe = list_entry(item, struct opened_file, elem);
		if (fe->fd == fd) {
			list_remove (&fe->elem);
			free (fe);
			return;
		}
		item = list_next(item);
	}
}

/* Takes a file using fd in the thread's list of files. */
struct file* get_file(int fd)
{
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

void convert_ptr(void *vaddr){
	check_mem(vaddr);
	void * ptr = pagedir_get_page(thread_current()->pagedir,vaddr);
	if(!ptr) exit(-1);
	return;
}


void check_mem(void *vaddr) {
	if (!is_user_vaddr(vaddr) || vaddr < (void *)0x08048000)
	{
		exit(-1);
	}
}
