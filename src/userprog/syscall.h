#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <hash.h>

void syscall_init (void);

void check_memory (void *vaddr);
void exit (int status);
void check_string_memory(const char *str);

unsigned mmap_file_hash (const struct hash_elem *f_, void *aux);
bool mmap_file_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void mmap_file_hash_destroy(struct hash_elem *e, void *aux);

unsigned opened_file_hash (const struct hash_elem *f_, void *aux);
bool opened_file_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void opened_file_hash_destroy(struct hash_elem *e, void *aux);

/* Process identifiers. */
typedef int pid_t;
typedef int mapid_t;
#define PID_ERROR ((pid_t) - 1)
#define MAPID_ERROR ((mapid_t) - 1)


#endif /* userprog/syscall.h */
