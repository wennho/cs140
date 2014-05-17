#ifdef VM
#ifndef MMAP_FILE_H_
#define MMAP_FILE_H_

#include <hash.h>
#include <stdbool.h>
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

/* Struct containing an mmaped file opened by a thread and a reference to it
 for the list. */
struct mmap_file
{
	struct file *file;
	int byte_offset;
	void * vaddr;
	mapid_t mapping;
	struct hash_elem elem;
};
struct mmap_file * get_mmap_file_by_vaddr(void * vaddr);
unsigned mmap_file_hash (const struct hash_elem *e, void *aux);
bool mmap_file_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void mmap_file_hash_destroy(struct hash_elem *e, void *aux);
void write_back_mmap_file(struct mmap_file * mmap_file);

#endif /* MMAP_FILE_H_ */

#endif
