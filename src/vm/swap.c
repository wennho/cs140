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

#define SECTORS (PGSIZE/BLOCK_SECTOR_SIZE)

static struct block * swap_block;
static struct swap_table* swap_table;

/* Hash for swap table. */
unsigned
swap_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct swap_frame *f = hash_entry(f_, struct swap_frame, hash_elem);
  return hash_bytes(&f->paddr, sizeof(f->paddr));
}

/* Hash comparator for swap slots. */
bool
swap_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  struct swap_frame *fa = hash_entry(a, struct swap_frame, hash_elem);
  struct swap_frame *fb = hash_entry(b, struct swap_frame, hash_elem);
  return fa->paddr < fb->paddr;
}

/* Initializes swap table. */
void swap_init(void)
{
	swap_table = malloc(sizeof(struct swap_table));
	ASSERT(hash_init(&swap_table->hash, &swap_hash, &swap_hash_less, NULL));
	swap_block = block_get_role(BLOCK_SWAP);
	ASSERT(swap_block != NULL);
}

/* Writes page to swap table. */
void swap_write_page(struct frame* frame UNUSED)
{
	int i;
	for (i = 0; i < SECTORS; i++)
	{
		//block_write(swap_block,freeSlot*SECTORS+i,(uint8_t)frame+i*BLOCK_SECTOR_SIZE);
	}

	//block_sector_t sector = NULL;
	//const void *buffer = NULL;
}

/* Reads page from swap table. */
void swap_read_page(struct frame * fram UNUSED)
{
	block_sector_t sector = 0;
	const void *buffer = NULL;
	//block_read(swap_block,sector,buffer);
}

