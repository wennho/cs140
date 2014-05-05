#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <hash.h>

extern struct lock dir_lock;
void syscall_init (void);

void check_memory (void *vaddr);
void exit (int status);
void check_string_memory(const char *str);

/* Process identifiers. */
typedef int pid_t;
typedef int mapid_t;
#define PID_ERROR ((pid_t) - 1)
#define MAPID_ERROR ((mapid_t) - 1)


#endif /* userprog/syscall.h */
