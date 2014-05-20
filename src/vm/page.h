
#ifndef PAGE_H_
#define PAGE_H_

#include <hash.h>
#include <devices/block.h>
#include "userprog/mmap_file.h"

/* Supplemental page data. */
struct page_data
{
  struct mmap_file* backing_file;  /* Mmaped_file or executable file. */
  int file_offset;                 /* Offset for backed files. */
  int readable_bytes;              /* Readable bytes in backed_file. */
  struct hash_elem hash_elem;      /* Hash table element. */
  void *vaddr;                     /* Virtual address. */
  block_sector_t sector;           /* First sector of block if in block. */
  bool is_in_swap;                 /* True if page in swap table. */
  bool is_mapped;			             /* True if page is mapped by mmap. */
  bool is_unmapped;                /* True if page was unmapped. */
  bool needs_recreate;             /* True if page needs to be reallocated. */
  bool is_writable;                /* True if page is writable. */
  bool is_dirty;                   /* True if page is dirty. */
  unsigned magic;                  /* Detects stack overflow. */
};


struct page_data* page_create_data (void* upage);
unsigned page_hash (const struct hash_elem *p_, void *aux);
bool is_page_data(const struct page_data *data);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
struct page_data* page_get_data(const void* vaddr);
void page_hash_destroy(struct hash_elem *e, void *aux);
void page_set_mmaped_file (struct page_data *data, struct mmap_file * mmap_file, int offset, int readable_bytes);
bool page_is_mapped (const void* vaddr);
bool page_is_unmapped(const void* vaddr);
bool page_is_read_only (const void* vaddr);
bool page_is_dirty(struct page_data *data);

#endif /* PAGE_H_ */
