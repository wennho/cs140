#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
  //syscall handler switch function.
  int syscallNum = 3;
  int status = 3;
  const char * cmdLine = "hi";
  const char * file = "hello";
  unsigned initial_size = 0;
  int fd = 0;
  void * buffer;
  unsigned size;
  unsigned position;
  pid_t pid;
  switch(syscallNum)
  {
  case 1:
	  halt();
	  break;
  case 2:
	  exit(status);
	  break;
  case 3:
	  pid_t execRet = exec(cmdLine);
	  break;
  case 4:
	  int waitRet = wait(pid);
	  break;
  case 5:
	  bool createRet = create(file,initial_size);
	  break;
  case 6:
	  bool removeRet = remove(file);
	  break;
  case 7:
	  int openRet = open(file);
	  break;
  case 8:
	  int filesizeRet = filesize(fd);
	  break;
  case 9:
	  int readRet = read(fd,buffer,size);
	  break;
  case 10:
	  int writeRet = write(fd,buffer, size);
	  break;
  case 11:
	  seek(fd,position);
	  break;
  case 12:
	  unsigned tellRet = tell(fd);
	  break;
  case 13:
	  close(fd);
	  break;
  default:
	  break;

  }
}

static
void halt (void)
{

}

static void
exit (int status)
{

}

static pid_t
exec (const char *cmd_line)
{

}

static int
wait (pid_t pid)
{

}

static bool
create (const char *file, unsigned initial_size)
{

}

static bool
remove (const char *file)
{

}

static int
open (const char *file)
{

}

static int 
filesize (int fd)
{

}

static int
read (int fd, void *buffer, unsigned size)
{

}

static int
write (int fd, const void *buffer, unsigned size)
{

}

static void
seek (int fd, unsigned position)
{

}

static unsigned 
tell (int fd)
{

}

static
void close (int fd)
{
	
}
