#include "swap.h"

#include "../devices/block.h"
#include "../lib/debug.h"
#include "../lib/kernel/hash.h"
#include "../lib/kernel/list.h"
#include "../lib/stdbool.h"
#include "../lib/stddef.h"
#include "../threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

#define NUM_SECTORS_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)

static struct block * swap_block;
static struct swap_table* swap_table;

/* Initializes swap table. */
void swap_init(void)
{
	swap_table = malloc(sizeof(struct swap_table));
	list_init(&swap_table->list);
	lock_init(&swap_table->lock);
	block_sector_t i;
	swap_block = block_get_role(BLOCK_SWAP);
	ASSERT(swap_block != NULL);
	for (i = 0; i < block_size(swap_block) - NUM_SECTORS_PER_PAGE + 1; i += NUM_SECTORS_PER_PAGE)
	{
		struct swap_frame * sf = malloc(sizeof(struct swap_frame));
		sf->sector = i;
		list_push_back (&swap_table->list, &sf->elem);
	}
}

/* Writes page to swap table. */
void swap_write_page(struct frame* frame)
{
	lock_acquire(&swap_table->lock);
	if (list_empty(&swap_table->list))
	{
		PANIC ("Ran out of space in swap table.");
	}
	struct list_elem* elem = list_pop_front (&swap_table->list);
	struct swap_frame *sf = list_entry(elem, struct swap_frame, elem);
	block_sector_t sector = sf->sector;
	block_sector_t i;
	for (i = sector; i < sector + NUM_SECTORS_PER_PAGE; i++)
	{
		block_write(swap_block, i, (char*)frame->paddr + i*BLOCK_SECTOR_SIZE);
	}
	struct page_data * data = page_get_data (frame->vaddr);
	data->is_in_swap = true;
	data->sector = sector;
	lock_release(&swap_table->lock);
}

/* Reads page from swap table. */
void swap_read_page(struct page_data * data, struct frame * frame)
{
	lock_acquire(&swap_table->lock);
	block_sector_t sector = data->sector;
	block_sector_t i;
	for (i = sector; i < sector + NUM_SECTORS_PER_PAGE; i++)
	{
		block_read(swap_block, i, (char*)frame->paddr + i*BLOCK_SECTOR_SIZE);
	}
	/* puts a free swap frame back into the swap table */
	struct swap_frame * sf = malloc(sizeof(struct swap_frame));
	sf->sector = sector;
	list_push_back (&swap_table->list, &sf->elem);
	data->is_in_swap = false;
	data->sector = 0;
	lock_release(&swap_table->lock);
}

