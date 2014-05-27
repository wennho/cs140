#include <cache.h>

/* Cache implemented as ordered list for LRU eviction.
 * Head of the list is the least recently used */
static struct list cache_list;

#define CACHE_MAGIC 0x8BADF00D
#define CACHE_SIZE 64

/* Initializes cache. */
void cache_init(void)
{
  list_init(&cache_list);
  int itr;
  /* populate cache with blank entries */
  for (itr = 0; itr < CACHE_SIZE; itr++)
    {
      struct cache_entry* c = malloc(sizeof(struct cache_entry));
      c->magic = CACHE_MAGIC;
      list_push_back(&cache_list,&c->list_elem);
    }
}
