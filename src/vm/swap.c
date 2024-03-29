#include "swap.h"

#include "../devices/block.h"
#include "../lib/debug.h"
#include "../lib/stdbool.h"
#include "../lib/stddef.h"
#include "../threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

#define NUM_SECTORS_PER_PAGE (PGSIZE/BLOCK_SECTOR_SIZE)

static struct swap_table* swap_table;

/* Initializes swap table. */
void
swap_init (void)
{
  swap_table = malloc (sizeof(struct swap_table));
  swap_table->swap_block = block_get_role (BLOCK_SWAP);
  ASSERT(swap_table->swap_block != NULL);
  int num_pages_in_block = block_size (
      swap_table->swap_block) / NUM_SECTORS_PER_PAGE;
  swap_table->bitmap = bitmap_create (num_pages_in_block);
  bitmap_set_all (swap_table->bitmap, false);
  lock_init (&swap_table->bitmap_lock);
}

/* Writes page to swap table. */
void
swap_write_page (struct frame* frame)
{
  lock_acquire (&swap_table->bitmap_lock);
  size_t bit = bitmap_scan_and_flip (swap_table->bitmap, 0, 1, false);
  lock_release (&swap_table->bitmap_lock);
  if (bit == BITMAP_ERROR)
    {
      PANIC("Out of space in swap block!");
    }
  block_sector_t sector = bit * NUM_SECTORS_PER_PAGE;
  block_sector_t i;
  int offset = 0;
  for (i = sector; i < sector + NUM_SECTORS_PER_PAGE; i++)
    {
      block_write (swap_table->swap_block, i,
          (char*) frame->paddr + offset * BLOCK_SECTOR_SIZE);
      offset++;
    }
  struct page_data * data = frame->data;
  ASSERT(is_page_data (data));
  data->is_in_swap = true;
  data->sector = sector;
}

/* Reads page from swap table. */
void
swap_read_page (struct page_data * data, struct frame * frame)
{
  block_sector_t i;
  int offset = 0;
  ASSERT(data->is_in_swap);
  for (i = data->sector; i < data->sector + NUM_SECTORS_PER_PAGE; i++)
    {
      block_read (swap_table->swap_block, i,
          (char*) frame->paddr + offset * BLOCK_SECTOR_SIZE);
      offset++;
    }
  /* Resets bit in bitmap for swap block. */
  size_t bit = data->sector / NUM_SECTORS_PER_PAGE;
  lock_acquire (&swap_table->bitmap_lock);
  bitmap_flip (swap_table->bitmap, bit);
  lock_release (&swap_table->bitmap_lock);
  data->is_in_swap = false;
  data->sector = 0;
}

/* Marks a swap block as free. */
void
swap_mark_as_free (block_sector_t sector)
{
  size_t bit = sector / NUM_SECTORS_PER_PAGE;
  lock_acquire (&swap_table->bitmap_lock);
  bitmap_flip (swap_table->bitmap, bit);
  lock_release (&swap_table->bitmap_lock);
}

