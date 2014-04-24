#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);


struct file* get_file(int fd);
void remove_file(int fd);
void check_memory (void *vaddr);
void exit (int status);
void close_all_fd(void);

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) - 1)

#endif /* userprog/syscall.h */
