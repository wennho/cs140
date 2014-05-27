#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/thread.h"

#define CACHE_MAGIC 0x8BADF00D
#define CACHE_SIZE 64
#define CACHE_FLUSH_WAIT 100

static unsigned cache_hash (const struct hash_elem *c_, void *aux);
static bool cache_hash_less (const struct hash_elem *a,
                             const struct hash_elem *b,
                             void *aux);
static bool is_cache_entry (struct cache_entry *ce);
static void cache_destroy(struct hash_elem *e, void *aux);
static void cache_flush_loop(void *aux);
static struct cache_entry* cache_get_sector(block_sector_t sector_idx);

static const char* cache_flush_thread_name = "cache_flush_thread";

/* Cache implemented as ordered list for LRU eviction.
 Head of the list is the least recently used. */

static struct list cache_list;  /* List of cache entries. */
static struct hash cache_table;  /* Hash of cache entries. */
static struct lock cache_lock;  /* Cache table lock. */


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
static
void
cache_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct cache_entry *entry = hash_entry(e, struct cache_entry, hash_elem);
  ASSERT(is_cache_entry (entry));
  list_remove(&entry->list_elem);
  free (entry);
}

/* Initializes the cache. */
void cache_init(void)
{
  list_init(&cache_list);
  hash_init(&cache_table, &cache_hash, &cache_hash_less, NULL);
  lock_init(&cache_lock);
  /* Pre-populate cache with blank entries. This allows us to avoid checking
   * the cache list size each time we want to cache a new sector, which takes
   * O(n) time */
  int itr;
  for (itr = 0; itr < CACHE_SIZE; itr++)
    {
      struct cache_entry* c = malloc (sizeof(struct cache_entry));
      c->magic = CACHE_MAGIC;
      c->is_dirty = false;
      list_push_back (&cache_list, &c->list_elem);
    }

  thread_create (cache_flush_thread_name, PRI_MAX, &cache_flush_loop, NULL);
}

/* Checks that a cache entry is valid. */
static bool
is_cache_entry (struct cache_entry *ce)
{
  return ce != NULL && ce->magic == CACHE_MAGIC;
}

/* Reads data at sector into buffer */
void
cache_read (block_sector_t sector_idx, const uint8_t* buffer)
{
  cache_read_at (sector_idx, buffer, BLOCK_SECTOR_SIZE, 0);
}

void
cache_read_at (block_sector_t sector_idx, const uint8_t* buffer, size_t size,
    int sector_offset)
{
  struct cache_entry *entry = cache_get_sector (sector_idx);
  void* data = entry->data;
  memcpy ((void*)buffer, data + sector_offset, size);
}

/* Writes data in buffer to cached sector */
void
cache_write (block_sector_t sector_idx, const uint8_t* buffer)
{
  cache_write_at (sector_idx, buffer, BLOCK_SECTOR_SIZE, 0);
}

void
cache_write_at (block_sector_t sector_idx, const uint8_t* buffer, size_t size,
    int sector_offset)
{
  struct cache_entry *entry = cache_get_sector (sector_idx);
  entry->is_dirty = true;
  void* data = entry->data;
  memcpy (data + sector_offset, buffer, size);
}

/* Returns a pointer to the cached data. */
static struct cache_entry* cache_get_sector(block_sector_t sector_idx)
{
  /* TODO: We need finer grained locking, we should not hold the lock while reading from file.
   * We must make sure everything works even if the cache is flushed while the function
   * is being called though. */
  lock_acquire(&cache_lock);
  struct cache_entry ce;
  ce.sector_idx = sector_idx;
  struct cache_entry *entry;
  struct hash_elem *e = hash_find(&cache_table, &ce.hash_elem);
  if (e == NULL)
    {
      /* Not cached, need to read from block. */
      struct list_elem *le = list_pop_front(&cache_list);
      entry = list_entry(le, struct cache_entry, list_elem);
      ASSERT(is_cache_entry(entry));

      /* safe to call delete even if entry is not in the hash table */
      hash_delete(&cache_table, &entry->hash_elem);

      if (entry->is_dirty){
          /* write back to file */
          block_write(fs_device, entry->sector_idx, entry->data);
          entry->is_dirty = false;
      }

      block_read(fs_device, sector_idx, entry->data);
      entry->sector_idx = sector_idx;
    }
  else
    {
      /* Sector is already cached. we only need to move the cache entry from
       * wherever it is in the list to the back to maintain ordering */
      entry = hash_entry(e, struct cache_entry, hash_elem);
      ASSERT(is_cache_entry(entry));
    }
  /* Update LRU list */
  list_remove (&entry->list_elem);
  list_push_back (&cache_list, &entry->list_elem);

  lock_release(&cache_lock);
  return entry;
}

static
void cache_flush_loop(void* aux UNUSED)
{
  while(true)
    {
      timer_sleep(CACHE_FLUSH_WAIT);
      cache_flush();
    }
}


static void cache_flush_entry (struct hash_elem *e, void *aux UNUSED) {
  struct cache_entry *entry = hash_entry(e, struct cache_entry, hash_elem);
  ASSERT(is_cache_entry (entry));
  if (entry->is_dirty){
      block_write (fs_device, entry->sector_idx, entry->data);
      entry->is_dirty = false;
  }
}

/* Flushes the cache by writing entries to file. */
void cache_flush(void)
{
  lock_acquire(&cache_lock);
  hash_apply(&cache_table, &cache_flush_entry);
  lock_release(&cache_lock);
}

/* Only call this when we are exiting */
void cache_clear(void)
{
  cache_flush();
  lock_acquire(&cache_lock);
  hash_destroy(&cache_table, &cache_destroy);

  /* remove blank entries that were not in the hashtable */
  while (!list_empty (&cache_list))
    {
      struct list_elem *e = list_pop_front (&cache_list);
      struct cache_entry *entry = list_entry(e, struct cache_entry, list_elem);
      ASSERT(is_cache_entry (entry));
      free (entry);
    }
  lock_release(&cache_lock);
}


