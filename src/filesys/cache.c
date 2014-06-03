#include <string.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/thread.h"

#define CACHE_MAGIC 0x8BADF00D
#define CACHE_SIZE 64
#define CACHE_FLUSH_WAIT 100

#define READ_AHEAD_MAGIC 0xDEADC0DE

static unsigned cache_hash (const struct hash_elem *c_, void *aux);
static bool cache_hash_less (const struct hash_elem *a,
                             const struct hash_elem *b,
                             void *aux);
static bool is_cache_entry (struct cache_entry *ce);
static void cache_flush_loop(void *aux);
static void cache_read_ahead_thread (void* aux);
static struct cache_entry* cache_get_sector(block_sector_t sector_idx);

static const char* cache_flush_thread_name = "cache_flush_thread";

/* Cache implemented as ordered list for LRU eviction.
 Head of the list is the least recently used. */

static struct list cache_list;  /* List of cache entries. */
static struct hash cache_table;  /* Hash of cache entries. */
static struct rw_lock cache_table_lock;  /* Cache table lock. */
static struct lock cache_list_lock;
static struct semaphore cache_read_ahead_sema;
static struct list cache_read_ahead_list;
static struct lock cache_read_ahead_lock;

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

/* Initializes the cache. */
void cache_init(void)
{
  list_init(&cache_list);
  hash_init(&cache_table, &cache_hash, &cache_hash_less, NULL);
  rw_lock_init(&cache_table_lock);
  lock_init(&cache_list_lock);
  sema_init(&cache_read_ahead_sema, 0);
  list_init(&cache_read_ahead_list);
  lock_init(&cache_read_ahead_lock);
  /* Pre-populate cache with blank entries. This allows us to avoid checking
   * the cache list size each time we want to cache a new sector, which takes
   * O(n) time */
  int itr;
  for (itr = 0; itr < CACHE_SIZE; itr++)
    {
      struct cache_entry* c = malloc (sizeof(struct cache_entry));
      c->magic = CACHE_MAGIC;
      rw_lock_init(&c->lock);
      c->is_dirty = false;
      c->pin_num = 0;
      lock_init(&c->pin_lock);
      cond_init(&c->pin_cond);
      list_push_back (&cache_list, &c->list_elem);
    }

  thread_create (cache_flush_thread_name, PRI_MAX, &cache_flush_loop, NULL);
  thread_create ("cache_read_ahead_thread", PRI_DEFAULT, &cache_read_ahead_thread, NULL);
}

/* Checks that a cache entry is valid. */
static bool
is_cache_entry (struct cache_entry *ce)
{
  return ce != NULL && ce->magic == CACHE_MAGIC;
}

static void
cache_unpin (struct cache_entry* entry)
{
  lock_acquire (&entry->pin_lock);
  entry->pin_num--;
  cond_signal (&entry->pin_cond, &entry->pin_lock);
  lock_release (&entry->pin_lock);
}

/* Reads data at sector into buffer */
void
cache_read (block_sector_t sector_idx, void *buffer)
{
  cache_read_at (sector_idx, buffer, BLOCK_SECTOR_SIZE, 0);
}

void
cache_read_at (block_sector_t sector_idx, void *buffer, size_t size,
    int sector_offset)
{
  struct cache_entry *entry = cache_get_sector (sector_idx);
  rw_lock_reader_acquire(&entry->lock);
  ASSERT(entry->sector_idx == sector_idx);
  void* data = entry->data;
  memcpy ((void*)buffer, data + sector_offset, size);
  rw_lock_reader_release(&entry->lock);
  cache_unpin (entry);
}

/* Writes data in buffer to cached sector */
void
cache_write (block_sector_t sector_idx, const void *buffer)
{
  cache_write_at (sector_idx, buffer, BLOCK_SECTOR_SIZE, 0);
}

void
cache_write_at (block_sector_t sector_idx, const void *buffer, size_t size,
    int sector_offset)
{
  struct cache_entry *entry = cache_get_sector (sector_idx);
  rw_lock_writer_acquire(&entry->lock);
  ASSERT(entry->sector_idx == sector_idx);
  entry->is_dirty = true;
  void* data = entry->data;
  memcpy (data + sector_offset, buffer, size);
  rw_lock_writer_release(&entry->lock);
  cache_unpin (entry);
}


/* Returns a pointer to the cached data. Need to call lock_release on the
 * returned entry to allow it for other use */
static struct cache_entry* cache_get_sector(block_sector_t sector_idx)
{
  struct cache_entry ce;
  ce.sector_idx = sector_idx;
  struct cache_entry *entry;
  rw_lock_reader_acquire(&cache_table_lock);
  struct hash_elem *e = hash_find(&cache_table, &ce.hash_elem);
  if (e == NULL)
    {
      rw_lock_reader_release(&cache_table_lock);
      /* Not cached, need to read from block. */
      lock_acquire(&cache_list_lock);
      struct list_elem *le = list_pop_front(&cache_list);
      lock_release(&cache_list_lock);
      entry = list_entry(le, struct cache_entry, list_elem);
      ASSERT(is_cache_entry(entry));

      rw_lock_writer_acquire(&cache_table_lock);
      /* Safe to call delete even if entry is not in the hash table. */
      hash_delete(&cache_table, &entry->hash_elem);
      /* Release the lock while doing filesystem IO. */
      rw_lock_writer_release(&cache_table_lock);

      lock_acquire(&entry->pin_lock);
      while (entry->pin_num > 0) {
          cond_wait(&entry->pin_cond, &entry->pin_lock);
      }

      rw_lock_writer_acquire(&entry->lock);
      if (entry->is_dirty)
        {
          /* Write back to file. */
          block_write(fs_device, entry->sector_idx, entry->data);
          entry->is_dirty = false;
        }
      block_read(fs_device, sector_idx, entry->data);
      entry->sector_idx = sector_idx;
      rw_lock_writer_release(&entry->lock);

      entry->pin_num++;
      lock_release(&entry->pin_lock);

      rw_lock_writer_acquire(&cache_table_lock);
      hash_insert(&cache_table, &entry->hash_elem);
      rw_lock_writer_release(&cache_table_lock);
    }
  else
    {
      /* Sector is already cached. we only need to move the cache entry from
       wherever it is in the list to the back to maintain ordering */
      entry = hash_entry(e, struct cache_entry, hash_elem);
      ASSERT(is_cache_entry(entry));
      lock_acquire(&entry->pin_lock);
      entry->pin_num++;
      lock_release(&entry->pin_lock);

      /* We only release the read lock here, so that we can guarantee that our
       * cache entry has not been evicted before we put a pin in it */
      rw_lock_reader_release(&cache_table_lock);
    }

  /* Update LRU list */
  lock_acquire(&cache_list_lock);
  if (e != NULL) {
      list_remove (&entry->list_elem);
  }
  list_push_back (&cache_list, &entry->list_elem);
  lock_release(&cache_list_lock);
  return entry;
}

/* Flushes the cache every CACHE_FLUSH_WAIT ticks. */
static
void cache_flush_loop(void* aux UNUSED)
{
  while(true)
    {
      timer_sleep(CACHE_FLUSH_WAIT);
      cache_flush();
    }
}

/* Flushes a single entry from the cache. */
static void cache_flush_entry (struct hash_elem *e, void *aux UNUSED)
{
  struct cache_entry *entry = hash_entry(e, struct cache_entry, hash_elem);
  ASSERT(is_cache_entry (entry));
  if (entry->is_dirty)
    {
      block_write (fs_device, entry->sector_idx, entry->data);
      entry->is_dirty = false;
    }
}

/* Flushes the cache by writing entries to file. */
void cache_flush(void)
{
  rw_lock_reader_acquire(&cache_table_lock);
  hash_apply(&cache_table, &cache_flush_entry);
  rw_lock_reader_release(&cache_table_lock);
}

static bool
is_read_ahead_info (struct read_ahead_info* info)
{
  return info != NULL && info->magic == READ_AHEAD_MAGIC;
}

void
cache_add_read_ahead_task (block_sector_t sector_idx)
{
  struct read_ahead_info* info = malloc (sizeof(struct read_ahead_info));
  info->sector = sector_idx;
  info->magic = READ_AHEAD_MAGIC;
  lock_acquire(&cache_read_ahead_lock);
  list_push_back(&cache_read_ahead_list, &info->list_elem);
  lock_release(&cache_read_ahead_lock);
  sema_up(&cache_read_ahead_sema);

}

void
cache_load_entry (block_sector_t sector_idx)
{
  struct cache_entry* entry = cache_get_sector(sector_idx);
  cache_unpin (entry);
}

static void
cache_read_ahead_thread (void* aux UNUSED)
{
  while (true)
    {
      sema_down (&cache_read_ahead_sema);
      lock_acquire (&cache_read_ahead_lock);
      struct list_elem *e = list_pop_front (&cache_read_ahead_list);
      struct read_ahead_info* info = list_entry(e, struct read_ahead_info,
                                                list_elem);
      lock_release (&cache_read_ahead_lock);
      ASSERT(is_read_ahead_info (info));
      cache_load_entry (info->sector);
      free (info);
    }
}



