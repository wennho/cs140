#include "page.h"

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux)
{
  const struct page_data *p = hash_entry(
      p_, struct page_data, hash_elem);
  return hash_bytes (&p->addr, sizeof p->addr);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux)
{
  const struct page *a = hash_entry (a_, struct page_data, hash_elem);
  const struct page *b = hash_entry (b_, struct page_data, hash_elem);

  return a->addr < b->addr;
}
