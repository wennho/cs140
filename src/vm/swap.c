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



/*tracks in use and free swap slots. Picks up unused swap slot
 * for evicting a page from its frame to the swap partition
 * Should allow freeing a swap slot when its page is read back
 * or the process whose page was swapped is terminated.
 */


unsigned
swap_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct swap_frame *f = hash_entry(f_, struct swap_frame, hash_elem);
  return hash_bytes(&f->paddr, sizeof(f->paddr));
}

bool
swap_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  struct swap_frame *fa = hash_entry(a, struct swap_frame, hash_elem);
  struct swap_frame *fb = hash_entry(b, struct swap_frame, hash_elem);
  return fa->paddr < fb->paddr;
}

void swap_init(void){
	swap_table = malloc(sizeof(struct swap_table));
	ASSERT(hash_init(&swap_table->hash, &swap_hash,&swap_hash_less,NULL));
	list_init(&swap_table->list);
	swapBlock = block_get_role(BLOCK_SWAP);
}

/* Writes page to swap table. */
void swap_write_page(struct frame* frame UNUSED)
{
	if (swapBlock == NULL){
			/* no block device fulfilling the given role. */
			/* no frame can be evicted without allocating a swap slot
			 * but swap is full. Panic the kernel.
			 */
			PANIC("We don't have a swap block");
		}

	int i;
	for (i = 0;i<SECTORS;i++){
		//block_write(swapBlock,freeSlot*SECTORS+i,(uint8_t)frame+i*BLOCK_SECTOR_SIZE);
	}

	//block_sector_t sector = NULL;
	//const void *buffer = NULL;
}

void swap_read_page(struct frame * fram UNUSED)
{
	struct block *swapBlock = block_get_role(BLOCK_SWAP);
		if (swapBlock == NULL){
			/* no block device fulfilling the given role. */
			/* no frame can be evicted without allocating a swap slot
			 * but swap is full. Panic the kernel.
			 */
			PANIC("We don't have a swap block");
		}
		block_sector_t sector = NULL;
		const void *buffer = NULL;
	//block_read(swapBlock,sector,buffer);

}

