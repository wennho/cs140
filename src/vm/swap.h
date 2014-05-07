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


struct swap_table
{
   struct hash hash;
};

struct swap_frame
{
	struct hash_elem hash_elem;
	void *paddr;
};

bool swap_hash_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);
unsigned swap_hash(const struct hash_elem *f_, void *aux);
void swap_write_page(struct frame* frame);
void swap_read_page(struct frame * fram UNUSED);
void swap_init(void);
#endif /* SWAP_H_ */
