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

#define FRAME_MAGIC 0xFEE1DEAD

static unsigned frame_hash (const struct hash_elem *f, void *aux UNUSED);
static bool frame_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux);
static struct frame* frame_to_evict(void);
static void frame_free(struct frame * f);
static bool frame_is_dirty(struct frame *f);
static bool frame_is_accessed(struct frame *f);
static void frame_set_accessed(struct frame * f, bool accessed);
static struct frame * frame_get_new(void *vaddr, bool user);
static struct frame* frame_get_data(void *paddr);

static bool is_frame(struct frame *frame)
{
  return frame != NULL && frame->magic == FRAME_MAGIC;
}

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
  bool is_dirty = pagedir_is_dirty (thread_current ()->pagedir, f->vaddr);
  struct page_data *data = page_get_data (f->vaddr);
  ASSERT(is_page_data (data));
  data->is_dirty |= is_dirty;
  return data->is_dirty;
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
 Also frees a page in palloc for a new one to enter.
 Must have acquired frame table lock before calling this function. */
static void frame_free(struct frame * f)
{
	pagedir_clear_page(thread_current()->pagedir, f->vaddr);
	list_remove(&f->list_elem);
	hash_delete(&frame_table->hash, &f->hash_elem);
	palloc_free_page(f->paddr);
	free(f);
}

/* Unpins a frame. */
void frame_set_pin(void *vaddr, bool setting)
{
  void *paddr = pagedir_get_page (thread_current ()->pagedir, vaddr);
  ASSERT(paddr != NULL);
  struct frame *f = frame_get_data(paddr);
  f->is_pinned = setting;
}

/* Deallocates a frame based on a virtual address. */
void frame_deallocate (void *vaddr)
{
  void *paddr = pagedir_get_page (thread_current ()->pagedir, vaddr);
  if(paddr != NULL)
    {
      frame_deallocate_paddr(paddr);
    }
  else
    {
      /* If in swap table, mark the blocks used as free. */
      struct page_data *data = page_get_data(vaddr);
      ASSERT(data != NULL);
      if(data->is_in_swap)
        {
          swap_mark_as_free(data->sector);
        }
    }
}

/* Destroys the frame, leaves behind the supplemental page entry and
 the pagedir. */
void frame_deallocate_paddr (void *paddr)
{
  lock_acquire (&frame_table->lock);
  frame_free (frame_get_data(paddr));
  lock_release (&frame_table->lock);
}

/* Gets a frame from a physical address. */
static struct frame* frame_get_data(void *paddr)
{
  struct frame frame;
  struct hash_elem *e;
  frame.paddr = paddr;
  e = hash_find (&frame_table->hash, &frame.hash_elem);
  ASSERT(e != NULL);
  struct frame *f = hash_entry(e, struct frame, hash_elem);
  ASSERT(is_frame (f));
  return f;
}

/* Adds a new page to the frame table.
 Returns the page's physical address for use.
 No locks required, called within frame_get_new_page and frame_get_from_swap*/
static struct frame * frame_get_new(void *vaddr, bool user)
{
  lock_acquire(&frame_table->lock);
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
		  struct page_data *data = page_get_data(evict->vaddr);
		  /* Check to make sure that this is an actual mapped file. */
			if(page_is_mapped(evict->vaddr) && data->backing_file->mapping != -1)
			  {
			    write_back_mapped_page(data->backing_file, data->file_offset, data->readable_bytes);
			  }
			else
			  {
			    swap_write_page(evict);
			  }
		}
		frame_free(evict);
		paddr = palloc_get_page(bit_pattern);
	}

	struct frame * fnew = malloc(sizeof(struct frame));
	fnew->paddr = paddr;
	fnew->vaddr = vaddr;
	fnew->magic = FRAME_MAGIC;
	/* Adds the new frame to the frame_table. */
	hash_insert(&frame_table->hash, &fnew->hash_elem);
	list_push_back(&frame_table->list, &fnew->list_elem);
	lock_release(&frame_table->lock);
	return fnew;
}


/* Based on a virtual address, and whether a user called the function,
 initializes a frame and returns an appropriate physical address.
 The frame is created and stored in the frame table with frame_get_new.
 Called by page fault in exception.c and load_segment in process.c. */
void * frame_get_new_paddr(void *vaddr, bool user)
{
	struct frame * f = frame_get_new(vaddr, user);
	return f->paddr;
}

/* Takes data that is in swap, creates a new frame for it,
 and reads data from the swap table into it.
 Called by page_fault in exception.c. */
void * frame_get_from_swap(struct page_data * data, bool user)
{
	struct frame *f = frame_get_new(data->vaddr, user);
	swap_read_page(data, f);
	return f->paddr;
}

/* Finds the correct frame to evict in the event of a swap.
 Called by frame_get_new when palloc_get_page fails. */
static struct frame* frame_to_evict(void)
{
	/* Clock_pointer is a list_elem. */
  if (frame_table->clock_pointer == NULL)
    {
      frame_table->clock_pointer = list_front (&frame_table->list);
    }
  struct frame * next = NULL;
  while (true)
    {
      frame_table->clock_pointer = list_next (frame_table->clock_pointer);
      if (frame_table->clock_pointer == list_end (&frame_table->list))
        {
          frame_table->clock_pointer = list_front (&frame_table->list);
        }
      next = list_entry(frame_table->clock_pointer, struct frame, list_elem);
      ASSERT(is_frame (next));
      /*  If it's one, make it zero, else return it. */
      if (frame_is_accessed (next))
        {
          frame_set_accessed (next, false);
        }
      /* If it's pinned, move on to the next one. */
      else if (next->is_pinned == false)
        {
          return next;
        }
    }
  return NULL;
}

