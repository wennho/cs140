#include "filesys/cache.h"
#include "threads/malloc.h"




#define CACHE_MAGIC 0x8BADF00D
#define CACHE_SIZE 64

static unsigned cache_hash (const struct hash_elem *c_, void *aux UNUSED);
static bool cache_hash_less (const struct hash_elem *a,
                             const struct hash_elem *b,
                             void *aux UNUSED);
static void cache_hash_destroy (struct hash_elem *e, void *aux UNUSED);
static bool is_cache_entry (struct cache_entry *ce);

/* Returns a hash value for cache entry c. */
static unsigned
cache_hash (const struct hash_elem *c_, void *aux UNUSED)
{
  const struct cache_entry *c = hash_entry(c_, struct cache_entry, hash_elem);
  return hash_bytes (&c->sector_idx, sizeof(c->sector_idx));
}

/* Returns true if cache entry a precedes cache entry b. */
static bool
cache_hash_less (const struct hash_elem *a, const struct hash_elem *b,
    void *aux UNUSED)
{
  struct cache_entry *ca = hash_entry(a, struct cache_entry, hash_elem);
  struct cache_entry *cb = hash_entry(b, struct cache_entry, hash_elem);
  return ca->sector_idx < cb->sector_idx;
}

/* Destructor function for cache page hash. */
void
cache_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct cache_entry *entry = hash_entry(e, struct cache_entry, hash_elem);
  ASSERT(is_cache_entry (entry));
  free (entry);
}

/* Initializes the cache. */
void cache_init(void)
{
  list_init(&cache_table->list);
  hash_init(&cache_table->hash, &cache_hash, &cache_hash_less, NULL);
  int itr;
  /* Populate cache with blank entries. */
  for (itr = 0; itr < CACHE_SIZE; itr++)
    {
      struct cache_entry* c = malloc(sizeof(struct cache_entry));
      c->magic = CACHE_MAGIC;
      list_push_back(&cache_table->list, &c->list_elem);
    }
}

/* Checks that a cache entry is valid. */
static bool
is_cache_entry (struct cache_entry *ce)
{
  return ce != NULL && ce->magic == CACHE_MAGIC;
}

/* Returns a pointer to the cached data. */
void* cache_get_sector(block_sector_t sector_idx)
{
  struct cache_entry ce;
  ce.sector_idx = sector_idx;
  struct cache_entry *entry;
  struct hash_elem *e = hash_find(&cache_table->hash, &ce.hash_elem);
  if (e == NULL)
    {
      /* Not cached, need to read from block */
      struct list_elem *le = list_pop_front(&cache_table->list);
      entry = list_entry(le, struct cache_entry, list_elem);
      ASSERT(is_cache_entry(entry));
      /* TODO: remove popped entry from hash table, read in sector & update entry, update LRU list
       *
       */
      entry->sector_idx = sector_idx;
    }
  else
    {
      entry = hash_entry(e, struct cache_entry, hash_elem);
      ASSERT(is_cache_entry(entry));
      /* Update LRU list */
      list_remove(&entry->list_elem);
      list_push_back(&cache_table->list, &entry->list_elem);
    }

  return &entry->data;
}

void cache_flush()
{
  hash_empty(&cache_table->hash, &cache_destroy);

}



