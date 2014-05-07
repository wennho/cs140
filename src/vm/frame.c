#include "vm/frame.h"
#include <debug.h>
#include <stddef.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/swap.h"




static unsigned frame_hash (const struct hash_elem *f, void *aux UNUSED);
static bool frame_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux);
static struct frame* frame_to_evict(void);
static void frame_free(struct frame * f);
static bool frame_is_dirty(struct frame *f);

/* Returns a hash value for frame f. */
unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame *f = hash_entry(f_, struct frame, hash_elem);
  return hash_bytes(&f->paddr, sizeof(f->paddr));
}

/* Returns true if frame a precedes frame b. */
bool
frame_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  struct frame *fa = hash_entry(a, struct frame, hash_elem);
  struct frame *fb = hash_entry(b, struct frame, hash_elem);
  return fa->paddr < fb->paddr;
}

/* Initializes the frame_table, called by paging_init in init.c */
void frame_table_init(void)
{
  frame_table = malloc(sizeof(struct frame_table));
  ASSERT (hash_init(&frame_table->hash, &frame_hash, &frame_hash_less, NULL));
  list_init(&frame_table->list);
  frame_table->clockPointer = NULL;
};

/* Checks whether a frame is dirty. */
bool frame_is_dirty(struct frame * f)
{
	return pagedir_is_dirty(thread_current ()->pagedir, f->vaddr);
}

/* Checks whether a frame is dirty. */
bool frame_is_accessed(struct frame * f)
{
	return pagedir_is_accessed(thread_current ()->pagedir, f->vaddr);
}

/* Checks whether a frame is dirty. */
void frame_set_accessed(struct frame * f,bool accessed)
{
	pagedir_set_accessed(thread_current ()->pagedir, f->vaddr,accessed);
}

/* Frees the frame so that a new one can be allocated. */
void frame_free(struct frame * f)
{
	pagedir_clear_page(thread_current()->pagedir, f->vaddr);
	list_remove(&f->list_elem);
	hash_delete(&frame_table->hash, &f->hash_elem);
	free(f);
}

void frame_unallocate(void *vaddr)
{
	void * paddr = pagedir_get_page (thread_current ()->pagedir, vaddr);
	ASSERT (paddr != NULL);
	struct frame frame;
	struct hash_elem *e;
	frame.paddr = paddr;
	e = hash_find (&frame_table->hash, &frame.hash_elem);
	ASSERT (e != NULL);
	frame_free(hash_entry(e, struct frame, hash_elem));
}

/* Adds a new page to the frame table.
 Returns the page's physical address for use. */
void * frame_get_new(void *vaddr, bool user)
{
	/* Obtains a single free page from and returns its physical address. */
	int bit_pattern = PAL_ZERO;
	if (user)
	{
		ASSERT(is_user_vaddr(vaddr));
		bit_pattern |= PAL_USER;
	}
	void * paddr = palloc_get_page(bit_pattern);

	/* If palloc_get_page fails, the frame must be made free by evicting some
	 page from its frame. */
	if (paddr == NULL)
	{
		struct frame* evict = frame_to_evict();
		if(frame_is_dirty(evict))
		{
			swap_write_page(evict);
		}
		frame_free(evict);
		paddr = palloc_get_page(bit_pattern);
	}

	struct frame * fnew = malloc(sizeof(struct frame));
	fnew->paddr = paddr;
	fnew->vaddr = vaddr;

	/* Adds the new frame to the frame_table. */
	hash_insert(&frame_table->hash, &fnew->hash_elem);
	list_push_back(&frame_table->list, &fnew->list_elem);
	return paddr;
}

/* Finds the correct frame to evict in the event of a swap. */
struct frame* frame_to_evict(void)
{
	/*clockPointer is a list_elem. */
	if (frame_table->clockPointer == NULL){
		frame_table->clockPointer = list_head(&frame_table->list);
	}
	struct frame * implicated = NULL;
	while(true){
		frame_table->clockPointer = list_next(frame_table->clockPointer);
		implicated = list_entry(frame_table->clockPointer,struct frame,list_elem);
		/*if its 1, make it zero, else return it */
		if(frame_is_accessed(implicated)){
			frame_set_accessed(implicated,false);
		}
		else{
			return implicated;
		}
	}
	return NULL;
}

