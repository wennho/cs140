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
   block_sector_t sector_idx;      /* Sector index of cached data. */
   char data[BLOCK_SECTOR_SIZE];   /* Cached data */
   struct list_elem list_elem;     /* List element. */
   struct hash_elem hash_elem;     /* Hash element. */
   struct lock lock;               /* Lock */
   bool is_dirty;                  /* True if entry is dirty. */
   unsigned magic;                 /* Used for detecting corruption. */
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
void create_read_ahead_info (block_sector_t sector_idx);

#endif /* CACHE_H_ */
