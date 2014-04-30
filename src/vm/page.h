
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

unsigned page_hash (const struct hash_elem *p_, void *aux);

bool is_page_data(const struct page_data *data);

struct page_data* create_page_data (void* upage);

#endif /* PAGE_H_ */
