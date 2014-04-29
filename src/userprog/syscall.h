#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);


struct file* get_file(int fd);
void remove_file(int fd);
void check_memory (void *vaddr);
void exit (int status);
void close_all_fd(void);
void check_string_memory(const char *str);

/* Process identifiers. */
typedef int pid_t;
typedef int mapid_t;
#define PID_ERROR ((pid_t) - 1)

#endif /* userprog/syscall.h */
