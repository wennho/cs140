#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

static void halt (void);
static void exit (int status);

static pid_t exec (const char *cmd_line);

static int wait (pid_t pid);

static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);

static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  void *stack_pointer = f->esp;
  int syscall_num = *((int *)stack_pointer);
  void *arg_1 = (char *)stack_pointer + 4;
  void *arg_2 = (char *)arg_1 + 4;
  void *arg_3 = (char *)arg_2 + 4;
  switch(syscall_num)
    {
      case SYS_HALT:
	     halt ();
	     break;
      case SYS_EXIT:
	     exit (*(int *)arg_1);
	     break;
      case SYS_EXEC:
	     exec ((const char *)arg_1);
	     break;
      case SYS_WAIT:
    	 wait (*(pid_t *)arg_1);
    	 break;
      case SYS_CREATE:
    	 create ((const char *)arg_1, *(unsigned *)arg_2);
    	 break;
      case SYS_REMOVE:
    	 remove ((const char *)arg_1);
    	 break;
      case SYS_OPEN:
    	 open ((const char *)arg_1);
    	 break;
      case SYS_FILESIZE:
    	 filesize (*(int *)arg_1);
    	 break;
      case SYS_READ:
    	 read (*(int *)arg_1, arg_2, *(unsigned *)arg_3);
    	 break;
      case SYS_WRITE:
    	 write (*(int *)arg_1, (const void *)arg_2, *(unsigned *)arg_3);
    	 break;
      case SYS_SEEK:
    	 seek (*(int *)arg_1, *(unsigned *)arg_2);
    	 break;
      case SYS_TELL:
    	 tell (*(int *)arg_1);
    	 break;
      case SYS_CLOSE:
    	 close(*(int *)arg_1);
    	 break;
      default:
    	 break;
  }
}

/* Terminates Pintos. Should only be seldom used. */
static
void halt (void)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel. */
static void
exit (int status UNUSED)
{

}

/* Runs the executable whose name is given in cmd_line, passing any given
 arguments, and returns the new process's program id (pid). */
static pid_t
exec (const char *cmd_line)
{
  return process_execute (cmd_line);
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int
wait (pid_t pid UNUSED)
{
  /* TO IMPLEMENT. */	
  return 0;
}

/* Creates a new file called file initially initial_size bytes in size. 
 Returns true if successful, false otherwise. */
static bool
create (const char *file UNUSED, unsigned initial_size UNUSED)
{
  /* TO IMPLEMENT. */
  return false;
}

/* Deletes the file called file. Returns true if successful, false 
 otherwise. */
static bool
remove (const char *file UNUSED)
{
  /* TO IMPLEMENT. */
  return false;
}

/* Opens the file called file. Returns a nonnegative integer handle 
 called a "file descriptor" (fd), or -1 if the file could not be opened. */
static int
open (const char *file UNUSED)
{
  /* TO IMPLEMENT. */
  return 0;
}

/* Returns the size, in bytes, of the file open as fd. */
static int 
filesize (int fd UNUSED)
{
  /* TO IMPLEMENT. */
  return 0;
}

/* Reads size bytes from the file open as fd into buffer. Returns the number
 of bytes actually read (0 at end of file), or -1 if the file could not be 
 read (due to a condition other than end of file). */
static int
read (int fd UNUSED, void *buffer UNUSED, unsigned size UNUSED)
{
  /* TO IMPLEMENT. */
  return 0;
}

/* Writes size bytes from buffer to the open file fd. Returns the number of 
 bytes actually written, which may be less than size if some bytes could not
 be written. */
static int
write (int fd UNUSED, const void *buffer UNUSED, unsigned size UNUSED)
{
  /* TO IMPLEMENT. */
  return 0;
}

/* Changes the next byte to be read or written in open file fd to position,
 expressed in bytes from the beginning of the file. */
static void
seek (int fd UNUSED, unsigned position UNUSED)
{
  /* TO IMPLEMENT. */
  return;
}

/* Returns the position of the next byte to be read or written in open file
 fd, expressed in bytes from the beginning of the file. */
static unsigned 
tell (int fd UNUSED)
{
  /* TO IMPLEMENT. */
  return 0;
}
/* Closes file descriptor fd. Exiting or terminating a process implicitly 
 closes all its open file descriptors, as if by calling this function 
 for each one. */
static
void close (int fd UNUSED)
{
  /* TO IMPLEMENT. */
}
