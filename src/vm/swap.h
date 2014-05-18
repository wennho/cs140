#ifndef SWAP_H_
#define SWAP_H_

#include "../kernel/bitmap.h"
#include "vm/frame.h"
#include "vm/page.h"


struct swap_table
{
   struct bitmap* bitmap;
   struct block * swap_block;
};

void swap_write_page(struct frame* frame);
void swap_read_page(struct page_data * data, struct frame * frame);
void swap_init(void);
#endif /* SWAP_H_ */
