#include "vm/frame.h"
#include <debug.h>
#include <hash.h>
#include "threads/palloc.h"

/* inits the single frame table that the kernel and all programs use */
static struct frame_table frame_table;

void compare_frame_hashes ()
{
}

void frame_table_init()
{
	ASSERT (hash_init(frame_hash, hash_bytes, ));
};

bool frame_is_dirty(struct frame * f)
{
	return true;
}

void frame_free(struct frame * f)
{
	palloc_free_page(f->paddr);
	list_remove(&f->elem);
	free(f);
}

/* Adds a page to the frame table.
 returns the page's physical address for use*/
void * get_new_frame()
{
	//obtains a single free page from user pool and
	//returns its physical address (aka kernel virtual address)
	void * a = palloc_get_page(PAL_USER);

	//if no page found returned;
	//if palloc_get_page fails,
	//frame must be made free by evicting some page
	//from its frame.
	while (a == NULL){
		struct frame * fold = frameToEvict(ft);
		removeReferences(fold);
		if(frame_is_dirty(fold))
			writePage(fold);
		frame_free(fold);
		a = palloc_get_page(PAL_USER);
	}

	struct frame * fnew = malloc(sizeof(struct frame));
	fnew->paddr = a;
	//adds a to the frame_table.
	list_push_front (&ft->frame_list, &fnew->elem);

	return a;
}


struct frame * frameToEvict(struct frame_table * ft)
{
	ft= ft;
	return NULL;
}

void removeReferences(struct frame * f)
{
	f = f;
}

void writePage(struct frame * f)
{
	f=f;
}

