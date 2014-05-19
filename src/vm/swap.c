#include "swap.h"

#include "../devices/block.h"
#include "../lib/debug.h"
#include "../lib/stdbool.h"
#include "../lib/stddef.h"
#include "../threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

#define NUM_SECTORS_PER_ENTRY (PGSIZE/BLOCK_SECTOR_SIZE)

static struct swap_table* swap_table;

/* Initializes swap table. */
void swap_init(void)
{
	swap_table = malloc(sizeof(struct swap_table));
	swap_table->swap_block = block_get_role(BLOCK_SWAP);
	ASSERT(swap_table->swap_block != NULL);
	int num_slots_in_block = block_size(swap_table->swap_block) / NUM_SECTORS_PER_ENTRY;
	swap_table->bitmap = bitmap_create(num_slots_in_block);
	bitmap_set_all(swap_table->bitmap, true);
}

/* Writes page to swap table. */
/* called by frame_get_new */
void swap_write_page(struct frame* frame)
{
	size_t bit = bitmap_scan_and_flip(swap_table->bitmap, 0, bitmap_size(swap_table->bitmap), false);
	ASSERT(bit != BITMAP_ERROR);
	block_sector_t sector = bit * NUM_SECTORS_PER_ENTRY;
	block_sector_t i;
	for (i = sector; i < sector + NUM_SECTORS_PER_ENTRY; i++)
	{
		block_write(swap_table->swap_block, i, (char*)frame->paddr + i*BLOCK_SECTOR_SIZE);
	}
	struct page_data * data = page_get_data (frame->vaddr);
	data->is_in_swap = true;
	data->sector = sector;
}

/* Reads page from swap table. */
/* called by frame_get_from_swap */
void swap_read_page(struct page_data * data, struct frame * frame)
{
	block_sector_t sector = data->sector;
	block_sector_t i;
	for (i = sector; i < sector + NUM_SECTORS_PER_ENTRY; i++)
	{
		block_read(swap_table->swap_block, i, (char*)frame->paddr + i*BLOCK_SECTOR_SIZE);
	}
	/* Resets bit in bitmap for swap block. */
	bitmap_flip(swap_table->bitmap, sector / NUM_SECTORS_PER_ENTRY);
	data->is_in_swap = false;
	data->sector = 0;
}

