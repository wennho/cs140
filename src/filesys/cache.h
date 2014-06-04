#ifndef CACHE_H_
#define CACHE_H_

#include <list.h>
#include <hash.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "filesys/inode.h"

/* Cache entry data. */
struct cache_entry
{
  block_sector_t sector_idx;    /* Sector index of cached data. */
  char data[BLOCK_SECTOR_SIZE]; /* Cached data */
  struct list_elem list_elem;   /* List element. */
  struct hash_elem hash_elem;   /* Hash element. */
  struct rw_lock lock;          /* Read-write lock to prevent data races */
  bool is_dirty;                /* True if entry is dirty. */
  unsigned magic;               /* Used for detecting corruption. */

  /* We need to pin cache entries so that, after finding the correct entry, it
   * is not evicted and replaced before we have a chance to do the necessary
   * read/write */
  struct lock pin_lock;         /* Lock for pinning */
  struct condition pin_cond;    /* Condition variable for pinning */
  int pin_num;                  /* Keep a count of the number of pins */
};

struct read_ahead_info
{
  block_sector_t sector;
  struct list_elem list_elem;
  unsigned magic;                 /* Used for detecting corruption. */
};

void cache_init(void);
void cache_read_at(block_sector_t sector_idx, void* buffer, size_t size,
    int sector_offset);
void cache_read(block_sector_t sector_idx, void* buffer);
void cache_write_at(block_sector_t sector_idx, const void* buffer, size_t size,
    int sector_offset);
void cache_write(block_sector_t sector_idx, const void* buffer);
void cache_load_entry (block_sector_t sector_idx);
void cache_flush(void);
void cache_add_read_ahead_task (block_sector_t sector_idx);

#endif /* CACHE_H_ */
