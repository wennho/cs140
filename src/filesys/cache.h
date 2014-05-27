#ifndef CACHE_H_
#define CACHE_H_


#include <list.h>
#include <hash.h>
#include "devices/block.h"

/* Cache entry data. */
struct cache_entry
{
   block_sector_t sector_idx;      /* sector index of cached data */
   char data[BLOCK_SECTOR_SIZE];   /* cached data */
   struct list_elem list_elem;     /* List element. */
   struct hash_elem hash_elem;     /* List element. */
   unsigned magic;                 /* Used for detecting corruption. */
};


void cache_init(void);
void* cache_get_sector(block_sector_t sector_idx);

#endif /* CACHE_H_ */
