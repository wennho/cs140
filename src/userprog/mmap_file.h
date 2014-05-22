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
  int num_bytes;                 /* Length of mmap_file in bytes. */
	struct file *file;             /* Actual file. */
	void * vaddr;                  /* Beginning of map. */
	mapid_t mapping;               /* Map id. */
	struct hash_elem elem;         /* Hash element. */
	bool is_segment;               /* True if segment. */
};
struct mmap_file * get_mmap_file_by_vaddr(void * vaddr);
unsigned mmap_file_hash (const struct hash_elem *e, void *aux);
bool mmap_file_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void mmap_file_hash_destroy(struct hash_elem *e, void *aux);
void write_back_mmap_file(struct mmap_file * mmap_file);
void write_back_mapped_page(struct mmap_file * mmap_file, int offset, int readable_bytes);

#endif /* MMAP_FILE_H_ */

#endif
