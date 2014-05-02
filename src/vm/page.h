
#ifndef PAGE_H_
#define PAGE_H_

#include <hash.h>

/* supplemental page data */
struct page_data {
  struct hash_elem hash_elem; /* Hash table element. */
  void *addr;                 /* Virtual address. */
  bool is_in_swap;
  bool is_in_filesys;         /* Used for mmap */
  unsigned magic;             /* Detects stack overflow. */
};

struct page_data* page_create_data (void* upage);
unsigned page_hash (const struct hash_elem *p_, void *aux);
bool is_page_data(const struct page_data *data);
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
void page_free_data (struct hash_elem *e, void *aux);
struct page_data* page_get_data(struct hash* table, void* vaddr);

#endif /* PAGE_H_ */
