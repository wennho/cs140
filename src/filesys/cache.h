#ifndef CACHE_H_
#define CACHE_H_

#include <list.h>
#include "devices/block.h"

/* Cache entry data. */
struct cache_entry
{
   block_sector_t sector_idx;      /* Sector index of cached data */
   char data[BLOCK_SECTOR_SIZE];   /* Cached data */
   struct list_elem list_elem;     /* List element. */
   unsigned magic;                 /* Used for detecting corruption. */
};

void cache_init(void);

#endif /* CACHE_H_ */
