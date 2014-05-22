#ifndef MMAP_FILE_H_
#define MMAP_FILE_H_

#include <hash.h>
#include <stdbool.h>
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

/* Struct containing an mmaped file opened by a thread and a reference to it
 for the hash. */
struct backed_file
{
  int num_bytes;                 /* Length of mmap_file in bytes. */
	struct file *file;             /* Actual file. */
	void * vaddr;                  /* Beginning of map. */
	mapid_t mapping;               /* Map id. */
	bool is_segment;               /* True if segment. */
	struct hash_elem elem;         /* Hash element. */
};
struct backed_file * get_backed_file_by_vaddr(void * vaddr);
unsigned backed_file_hash (const struct hash_elem *e, void *aux);
bool backed_file_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void backed_file_hash_destroy(struct hash_elem *e, void *aux);
void backed_file_write_back(struct backed_file * backed_file);
void backed_file_write_back_page(struct backed_file * backed_file, int offset, int readable_bytes);

#endif /* MMAP_FILE_H_ */
