
#ifndef PAGE_H_
#define PAGE_H_

#include <hash.h>
#include <devices/block.h>
#include "userprog/mmap_file.h"

/* Supplemental page data. */
struct page_data
{
  struct mmap_file* mmap_struct;
  struct hash_elem hash_elem; /* Hash table element. */
  void *vaddr;                /* Virtual address. */
  block_sector_t sector;      /* First sector of block if in block. */
  bool is_in_swap;            /* True if page in swap table. */
  bool is_read_only;	        /* True if data is read only. */
  bool is_mapped;			        /* True if page is mapped. */
  bool needs_recreate;        /* True if page needs to be re-allocated */
  unsigned magic;             /* Detects stack overflow. */
};

struct page_data* page_create_data (void* upage);
unsigned page_hash (const struct hash_elem *p_, void *aux);
bool is_page_data(const struct page_data *data);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
struct page_data* page_get_data(const void* vaddr);
void page_hash_destroy(struct hash_elem *e, void *aux);
void page_set_is_mapped (void* vaddr, bool mapped);
bool page_is_mapped (const void* vaddr);
bool page_is_read_only (const void* vaddr);

#endif /* PAGE_H_ */
