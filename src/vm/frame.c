#include "vm/frame.h"
#include <debug.h>
#include <stddef.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"


static struct frame_table* frame_table;

static unsigned frame_hash (const struct hash_elem *f, void *aux UNUSED);
static bool frame_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux);
static struct frame* frame_to_evict(void);
static void write_page_to_table(struct frame* frame);
static void frame_free(struct frame * f);
static bool frame_is_dirty(struct frame *f);

/* Returns a hash value for frame f. */
unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
  const struct frame *f = hash_entry(f_, struct frame, hash_elem);
  return hash_bytes(&f->vaddr, sizeof(f->vaddr));
}

/* Returns true if page a precedes page b. */
bool
frame_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  struct frame *fa = hash_entry(a, struct frame, hash_elem);
  struct frame *fb = hash_entry(b, struct frame, hash_elem);
  return fa->vaddr < fb->vaddr;
}

/* Initializes the frame_table, called by paging_init in init.c */
void frame_table_init(void)
{
	ASSERT (hash_init(frame_table->hash, frame_hash, frame_hash_less, NULL));
	list_init(&frame_table->list);
	frame_table = malloc(sizeof(struct frame_table));
};

/* Checks whether a frame is dirty. */
bool frame_is_dirty(struct frame * f UNUSED)
{
	/* TO IMPLEMENT. */
	return true;
}

/* Frees the frame so that a new one can be allocated. */
void frame_free(struct frame * f)
{
	palloc_free_page(f->paddr);
	list_remove(&f->list_elem);
	hash_delete(frame_table->hash, &f->hash_elem);
	free(f);
}


/* Adds a page to the frame table.
returns the page's physical address for use*/
void * frame_get_new(void *vaddr)
{
	/* Obtains a single free page from user pool and
	 returns its physical address. */
	void * paddr = palloc_get_page(PAL_USER);

	 /* If palloc_get_page fails, frame must be made free by evicting some page
	 from its frame. */
	if (paddr == NULL)
	{
		struct frame* evict = frame_to_evict();
		if(frame_is_dirty(evict))
		{
			write_page_to_table(evict);
		}
		frame_free(evict);
		paddr = palloc_get_page(PAL_USER);
	}

	struct frame * fnew = malloc(sizeof(struct frame));
	fnew->paddr = paddr;
	fnew->vaddr = vaddr;

	/* Adds the new frame to the frame_table. */
	hash_insert(frame_table->hash, &fnew->hash_elem);
	list_push_back(&frame_table->list, &fnew->list_elem);

	return paddr;
}

/* Writes page to swap table. */
void write_page_to_table(struct frame* frame UNUSED)
{
}

struct frame* frame_to_evict(void)
{
	return NULL;
}

