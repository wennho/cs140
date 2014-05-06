#ifndef SWAP_H_
#define SWAP_H_

#include "frame.h"

struct swap_table
{
   struct list list;
};

struct swap_frame
{
	struct list_elem list_elem;
};

void swap_write_page(struct frame* frame);

#endif /* SWAP_H_ */
