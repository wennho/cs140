#ifndef SWAP_H_
#define SWAP_H_

#include "frame.h"

struct swap_table
{
   struct hash hash;
};

struct swap_frame
{
	struct hash_elem hash_elem;
};

void swap_write_page(struct frame* frame);

#endif /* SWAP_H_ */
