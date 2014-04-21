#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame *);

static void halt(void);
static void exit(int status);

static pid_t exec(const char *cmd_line);

static int wait(pid_t pid);

static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);
static int open(const char *file);

static int filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);
static void seek(int fd, unsigned position);
static unsigned tell(int fd);
static void close(int fd);

struct file_elem {
	struct file * f;
	int fd;
	struct list_elem elem;
};

void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f) {
	void *stack_pointer = f->esp;
	int syscall_num = *((int *) stack_pointer);
	void *arg_1 = (char *) stack_pointer + 4;
	void *arg_2 = (char *) arg_1 + 4;
	void *arg_3 = (char *) arg_2 + 4;
	switch (syscall_num) {
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(*(int *) arg_1);
		break;
	case SYS_EXEC:
		exec((const char *) arg_1);
		break;
	case SYS_WAIT:
		wait(*(pid_t *) arg_1);
		break;
	case SYS_CREATE:
		create((const char *) arg_1, *(unsigned *) arg_2);
		break;
	case SYS_REMOVE:
		remove((const char *) arg_1);
		break;
	case SYS_OPEN:
		open((const char *) arg_1);
		break;
	case SYS_FILESIZE:
		filesize(*(int *) arg_1);
		break;
	case SYS_READ:
		read(*(int *) arg_1, arg_2, *(unsigned *) arg_3);
		break;
	case SYS_WRITE:
		write(*(int *) arg_1, (const void *) arg_2, *(unsigned *) arg_3);
		break;
	case SYS_SEEK:
		seek(*(int *) arg_1, *(unsigned *) arg_2);
		break;
	case SYS_TELL:
		tell(*(int *) arg_1);
		break;
	case SYS_CLOSE:
		close(*(int *) arg_1);
		break;
	default:
		break;
	}
}

/* Terminates Pintos. Should only be seldom used. */
static
void halt(void) {
	shutdown_power_off();
}

/* Terminates the current user program, returning status to the kernel. */
static void
exit (int status)
{
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_exit();
}

/* Runs the executable whose name is given in cmd_line, passing any given
 arguments, and returns the new process's program id (pid). */
static pid_t
exec (const char *cmd_line)
{
  pid_t = process_execute (cmd_line);
  /* Must also wait to see if error. */
  if (pid_t != -1)
  {
	  list_push_back (&thread_current ()->child_list, pid_t);
  }
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int
wait (pid_t pid)
{
  return process_wait(pid);
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int wait(pid_t pid) {
	/* TO IMPLEMENT. */
	return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in size. 
 Returns true if successful, false otherwise. */
static bool create(const char *file UNUSED, unsigned initial_size UNUSED) {
	return filesys_create(file, initial_size);
}

/* Deletes the file called file. Returns true if successful, false 
 otherwise. */
static bool
remove (const char *file)
{
  return filesys_remove(file);
}

static int
open (const char *file UNUSED)
{
  struct file *f = filesys_open(file);
  if(f == NULL) return 0;
  /* TO IMPLEMENT. */
  int fd = 1;
  return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int 
filesize (int fd)
{
  struct file *f = getFile(fd);
  int filesize = file_length(f);
  /* TO IMPLEMENT. */
  return filesize;
=======
static int open(const char *file) {
	struct file *f = filesys_open(file);
	if (f == NULL)
		return -1; /* file could not be opened */

	int fd = thread_current()->fd;
	thread_current()->fd++;
	struct file_elem *temp = malloc(sizeof(struct file_elem));
	if (!temp)
		printf("we died we failed to malloc\n");
	temp->f = f;
	temp->fd = fd;
	list_push_back(&thread_current()->fd_list, &temp->elem);
	return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int filesize(int fd) {
	struct file *f = getFile(fd);
	int filesize = file_length(f);
	return filesize;
>>>>>>> 0745e6563cc256f861f6abd58284d730a3e9173b
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
 of bytes actually read (0 at end of file), or -1 if the file could not be 
 read (due to a condition other than end of file). */
<<<<<<< HEAD
static int
read (int fd, void *buffer, unsigned size)
{
  struct file *f = getFile(fd);
  int bytes = file_read(f,buffer,size);
  return bytes;
=======
static int read(int fd, void *buffer, unsigned size) {
	struct file *f = getFile(fd);
	int bytes = file_read(f, buffer, size);
	return bytes;
>>>>>>> 0745e6563cc256f861f6abd58284d730a3e9173b
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
 bytes actually written, which may be less than size if some bytes could not
 be written. */
<<<<<<< HEAD
static int
write (int fd, const void *buffer, unsigned size)
{
  /* TO IMPLEMENT. */
  struct file * f = getFile(fd);
  int bytes = file_write(f, buffer, size);
  return bytes;
=======
static int write(int fd, const void *buffer, unsigned size) {
	/* TO IMPLEMENT. */
	struct file * f = getFile(fd);
	int bytes = file_write(f, buffer, size);
	return bytes;
>>>>>>> 0745e6563cc256f861f6abd58284d730a3e9173b
}

/* Changes the next byte to be read or written in open file fd to position,
 expressed in bytes from the beginning of the file. */
static void seek(int fd, unsigned position) {
	struct file *f = getFile(fd);
<<<<<<< HEAD
	file_seek(f,position);
=======
	file_seek(f, position);
	return;
>>>>>>> 0745e6563cc256f861f6abd58284d730a3e9173b
}

/* Returns the position of the next byte to be read or written in open file
 fd, expressed in bytes from the beginning of the file. */
static unsigned tell(int fd) {
	struct file *f = getFile(fd);
	unsigned pos = file_tell(f);
	return pos;
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly 
 closes all its open file descriptors, as if by calling this function 
 for each one. */
static
void close(int fd) {
	struct file *f = getFile(fd);
	file_close(f);
	removeFile(fd);
	/* TO IMPLEMENT shut down of file descriptors */
}

/* removes a file using fd in the thread's list of files. */
void removeFile(int fd) {
	struct thread *t = thread_current();
	if (list_empty(t->fd_list))
		return;
	struct list_elem * item = list_front(t->fd_list);
	while (item != NULL) {
		struct file_elem * fe = list_entry(item, struct file_elem, elem);
		if (fe->fd == fd) {
			free(fe);
			return;
		}
		item = list_next(item);
	}
	//To implement
	/* Takes a file using fd in the thread's list of files */
	return;
}

/* takes a file using fd in the thread's list of files. */
struct file* getFile(int fd) {
	struct thread *t = thread_current();
	if (list_empty(t->fd_list))
		return NULL;
	struct list_elem * item = list_front(t->fd_list);
	while (item != NULL) {
		struct file_elem * fe = list_entry(item, struct file_elem, elem);
		if (fe->fd == fd)
			return fe->f;
		item = list_next(item);
	}
	//To implement
	/* Takes a file using fd in the thread's list of files */
	return NULL;
}
