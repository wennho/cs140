#ifndef SWAP_H_
#define SWAP_H_

#include "../kernel/bitmap.h"
#include "vm/frame.h"
#include "vm/page.h"


struct swap_table
{

   struct bitmap* bitmap;      /* Bitmap showing available pages.
                                A bit is false if the slot is available. */
   struct block * swap_block;  /* Swap block. */
   struct lock lock;           /* Swap table lock. */
};

void swap_write_page(struct frame* frame);
void swap_read_page(struct page_data * data, struct frame * frame);
void swap_mark_as_free(block_sector_t sector);
void swap_init(void);
#endif /* SWAP_H_ */
