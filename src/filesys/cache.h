#ifndef CACHE_H_
#define CACHE_H_

#include <list.h>
#include <hash.h>
#include "devices/block.h"
#include "threads/synch.h"

/* Cache entry data. */
struct cache_entry
{
   block_sector_t sector_idx;      /* Sector index of cached data. */
   char data[BLOCK_SECTOR_SIZE];   /* Cached data */
   struct list_elem list_elem;     /* List element. */
   struct hash_elem hash_elem;     /* Hash element. */
   unsigned magic;                 /* Used for detecting corruption. */
};

/* Cache implemented as ordered list for LRU eviction.
 Head of the list is the least recently used. */
struct cache_table
{
  struct list list;  /* List of cache entries. */
  struct hash hash;  /* Hash of cache entries. */
  struct lock lock;  /* Cache table lock. */
};

struct cache_table *cache_table;
void cache_init(void);
void* cache_get_sector(block_sector_t sector_idx);
void cache_flush(void);

#endif /* CACHE_H_ */
