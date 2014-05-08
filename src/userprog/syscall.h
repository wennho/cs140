#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <hash.h>

extern struct lock dir_lock;
void syscall_init (void);

void exit (int status);

void check_memory (const void *vaddr);
void check_string_memory(const char *str);
void check_memory_read(const void *vaddr, const void *stack_pointer);
void check_memory_write(const void *vaddr, const void *stack_pointer);

/* Process identifiers. */
typedef int pid_t;
typedef int mapid_t;
#define PID_ERROR ((pid_t) - 1)
#define MAPID_ERROR ((mapid_t) - 1)


#endif /* userprog/syscall.h */
