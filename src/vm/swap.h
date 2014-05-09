#ifndef SWAP_H_
#define SWAP_H_

#include <hash.h>
#include <list.h>
#include "../lib/debug.h"
#include "../lib/stdbool.h"
#include "filesys/file.h"
#include "vm/page.h"
#include "devices/block.h"
#include "vm/frame.h"
#include "threads/synch.h"

struct swap_table
{
   struct list list;
   struct lock lock;
};

struct swap_frame
{
	struct list_elem elem;
	block_sector_t sector;      /* First sector of eight holding frame. */
};

void swap_write_page(struct frame* frame);
void swap_read_page(struct page_data * data, struct frame * frame);
void swap_init(void);
#endif /* SWAP_H_ */
