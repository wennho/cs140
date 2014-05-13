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
#include "userprog/mmap_file.h"

static unsigned frame_hash (const struct hash_elem *f, void *aux UNUSED);
static bool frame_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux);
static struct frame* frame_to_evict(void);
static void frame_free(struct frame * f);
static bool frame_is_dirty(struct frame *f);
static bool frame_is_accessed(struct frame *f);
static void frame_set_accessed(struct frame * f, bool accessed);
static struct frame * frame_get_new(void *vaddr, bool user);

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
  frame_table->clock_pointer = NULL;
  lock_init(&frame_table->lock);
};

/* Checks whether a frame is dirty. */
bool frame_is_dirty(struct frame * f)
{
	return pagedir_is_dirty(thread_current ()->pagedir, f->vaddr);
}

/* Checks whether a frame is accessed. */
bool frame_is_accessed(struct frame * f)
{
	return pagedir_is_accessed(thread_current ()->pagedir, f->vaddr);
}

/* Sets a frame's accessed bit. */
void frame_set_accessed(struct frame * f, bool accessed)
{
	pagedir_set_accessed(thread_current ()->pagedir, f->vaddr,accessed);
}

/* Frees the frame so that a new one can be allocated.
 * also frees a page in palloc for a new one to enter */
static void frame_free(struct frame * f)
{
	lock_acquire(&frame_table->lock);
	pagedir_clear_page(thread_current()->pagedir, f->vaddr);
	list_remove(&f->list_elem);
	hash_delete(&frame_table->hash, &f->hash_elem);
	palloc_free_page(f->paddr);
	free(f);
	lock_release(&frame_table->lock);
}

/* Unallocates a frame at address vaddr. */
void frame_unallocate(void *vaddr)
{
	lock_acquire(&frame_table->lock);
	void * paddr = pagedir_get_page (thread_current ()->pagedir, vaddr);
	ASSERT (paddr != NULL);
	struct frame frame;
	struct hash_elem *e;
	frame.paddr = paddr;
	e = hash_find (&frame_table->hash, &frame.hash_elem);
	ASSERT (e != NULL);
	frame_free(hash_entry(e, struct frame, hash_elem));
	lock_release(&frame_table->lock);
}

/* Adds a new page to the frame table.
 Returns the page's physical address for use.
 No locks required, called within frame_get_new_page and frame_get_from_swap*/
static struct frame * frame_get_new(void *vaddr, bool user)
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

	return fnew;
}


/* based on a virtual address, and whether a user called the function
 * initialises a frame, returns an appropriate physical address.
 * The frame is created and stored in the frame table with
 * frame_get_new
 * called by exception.c page_fault and process.c load_segment
 */
void * frame_get_new_paddr(void *vaddr, bool user)
{
	lock_acquire(&frame_table->lock);
	struct frame * f = frame_get_new(vaddr, user);
	lock_release(&frame_table->lock);
	return f->paddr;
}

/* takes data that is in swap, creates a new frame for it,
 * reads data from the swap table into it.
 * called by exception.c page_fault.
 */
void * frame_get_from_swap(struct page_data * data, bool user)
{
	lock_acquire(&frame_table->lock);
	struct frame * f = frame_get_new(data->vaddr, user);
	swap_read_page(data, f);
	lock_release(&frame_table->lock);
	return f->paddr;
}

/* Finds the correct frame to evict in the event of a swap.
 * called by frame_get_new when palloc_get_page fails */
static struct frame* frame_to_evict(void)
{
	/* clock_pointer is a list_elem. */
	struct list_elem * clock_pointer = frame_table->clock_pointer;
	if (clock_pointer == NULL)
	{
		clock_pointer = list_head(&frame_table->list);
	}
	struct frame * next = NULL;
	while(true)
	{
		clock_pointer = list_next(clock_pointer);
		if (clock_pointer == NULL)
		{
				clock_pointer = list_head(&frame_table->list);
		}
		next = list_entry(clock_pointer, struct frame, list_elem);
		/* Currently never evicts a mapped page.
		 * If it's one, make it zero, else return it. */
		if(frame_is_accessed(next) || page_is_mapped(next->vaddr))
		{
			frame_set_accessed(next,false);
		}
		else
		{
			return next;
		}
	}
	return NULL;
}

