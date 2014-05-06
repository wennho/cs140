#include "swap.h"
#include <debug.h>
#include <stddef.h>

/*tracks in use and free swap slots. Picks up unsued swap slot
 * for evicting a page from its frame to the swap partition
 * Should allow freeing a swap slot when its page is read back
 * or the process whose page was swapped is terminated.
 */

/* Writes page to swap table. */
void swap_write_page(struct frame* frame UNUSED)
{

}
