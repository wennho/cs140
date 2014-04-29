
#ifndef PAGE_H_
#define PAGE_H_

#include <hash.h>

struct supplemental_page_data {
  struct hash_elem hash_elem; /* Hash table element. */
  void *addr;                 /* Virtual address. */
};

unsigned supplemental_page_hash (const struct hash_elem *p_, void *aux);



#endif /* PAGE_H_ */
