#include "swap.h"
#include <debug.h>
#include <stddef.h>
#include "devices/block.h"

/*tracks in use and free swap slots. Picks up unused swap slot
 * for evicting a page from its frame to the swap partition
 * Should allow freeing a swap slot when its page is read back
 * or the process whose page was swapped is terminated.
 */

/* Writes page to swap table. */
void swap_write_page(struct frame* frame UNUSED)
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
	block_write(swapBlock,sector,buffer);
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
	block_read(swapBlock,sector,buffer);

}

