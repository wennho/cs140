#include "vm/frame.h"
#include <debug.h>
#include <stddef.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/swap.h"
#include "userprog/mmap_file.h"

#define FRAME_MAGIC 0xFEE1DEAD

static unsigned frame_hash (const struct hash_elem *f, void *aux UNUSED);
static bool frame_hash_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux);
static struct frame* frame_to_evict(void);
static void frame_remove(struct frame * f);
static bool frame_is_dirty(struct frame *f);
static bool frame_is_accessed(struct frame *f);
static void frame_set_accessed(struct frame * f, bool accessed);
static struct frame* frame_get_data(void *paddr);
static void evict_frame(void);

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
  lock_init(&frame_table->palloc_lock);
};

/* Checks whether a frame is dirty. */
bool frame_is_dirty(struct frame * f)
{
  struct page_data *data = f->data;
  ASSERT(is_page_data (data));
  bool is_dirty = pagedir_is_dirty (data->pagedir, data->vaddr);
  data->is_dirty |= is_dirty;
  return data->is_dirty;
}

/* Checks whether a frame is accessed. */
bool frame_is_accessed(struct frame * f)
{
	return pagedir_is_accessed(f->data->pagedir, f->data->vaddr);
}

/* Sets a frame's accessed bit. */
void frame_set_accessed(struct frame * f, bool accessed)
{
	pagedir_set_accessed(f->data->pagedir, f->data->vaddr,accessed);
}

/* Frees the frame so that a new one can be allocated.
 Also frees a page in palloc for a new one to enter.
 Must have acquired frame table lock before calling this function. */
static void frame_remove(struct frame * f)
{
	pagedir_clear_page(f->data->pagedir, f->data->vaddr);
	if (frame_table->clock_pointer == &f->list_elem){
	    /* Safest to set it to NULL, so it works even if the list is empty */
	    frame_table->clock_pointer = NULL;
	}
	list_remove(&f->list_elem);
	hash_delete(&frame_table->hash, &f->hash_elem);
	palloc_free_page(f->paddr);
	free(f);
}

/* Deallocates a frame based on a virtual address. */
void frame_deallocate (void *vaddr, bool is_in_swap, block_sector_t sector )
{
  void *paddr = pagedir_get_page (thread_current ()->pagedir, vaddr);
  if(paddr != NULL)
    {
      frame_deallocate_paddr(paddr);
    }
  else if(is_in_swap)
    {
      /* If in swap table, mark the blocks used as free. */
      swap_mark_as_free(sector);
    }
}

/* Destroys the frame, leaves behind the supplemental page entry and
 the pagedir. */
void frame_deallocate_paddr (void *paddr)
{
  lock_acquire (&frame_table->lock);
  struct frame* f = frame_get_data(paddr);
  frame_remove (f);
  lock_release (&frame_table->lock);
}

/* Gets a frame from a physical address. Must have acquired frame table lock */
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

static void evict_frame()
{
	struct frame* evict = frame_to_evict();
	struct page_data *evict_data = evict->data;
	lock_acquire (&evict_data->lock);
	if (frame_is_dirty (evict))
    {
      swap_write_page (evict);
    }
	lock_acquire(&frame_table->lock);
	frame_remove(evict);
	lock_release(&frame_table->lock);
	evict_data->is_pinned = false;
	lock_release(&evict_data->lock);
}

/* Adds a new page to the frame table.
 Returns the page's physical address for use.
 No locks required, called within frame_get_new_page and frame_get_from_swap*/
struct frame * frame_get_new(void *vaddr, bool user, struct page_data* data, bool pin_data)
{

	/* Obtains a single free page from and returns its physical address. */
	int bit_pattern = PAL_ZERO;
	if (user)
	{
		ASSERT(is_user_vaddr(vaddr));
		bit_pattern |= PAL_USER;
	}

  /* Need to acquire a lock to prevent other processes from sneakily stealing our
   * evicted pages later. We cannot release the lock even when calling evict
   * frames, since other processes shouldn't be able to get a page if we can't
   */
  lock_acquire (&frame_table->palloc_lock);
	void * paddr = palloc_get_page(bit_pattern);
	/* If palloc_get_page fails, the frame must be made free by evicting some
   page from its frame. */
  if (paddr == NULL)
    {
      evict_frame();
      paddr = palloc_get_page (bit_pattern);
    }
  lock_release (&frame_table->palloc_lock);

  struct frame * fnew = malloc (sizeof(struct frame));
  if (fnew == NULL)
    {
      PANIC("Unable to allocate new memory");
    }
	fnew->paddr = paddr;
	fnew->magic = FRAME_MAGIC;

	if (data != NULL)
    {
	    data->is_pinned = pin_data;
      ASSERT(is_page_data (data));
      ASSERT(data->vaddr == vaddr);
      fnew->data = data;
      /* Reinstall page, but don't create new supplemental page entry. */
      if (!pagedir_set_page (data->pagedir, vaddr, paddr,
          data->is_writable))
        {
          frame_deallocate_paddr(paddr);
          exit (-1);
        }
    }
  else
    {
      /* Point the page table entry to the physical page. Since we are making a
       new page, it is always writable */
      if (!install_page (vaddr, paddr, true))
        {
          frame_deallocate_paddr (paddr);
          exit (-1);
        }
      data = page_get_data(vaddr);
      ASSERT(data != NULL);
      fnew->data = data;
      data->is_pinned = pin_data;
    }


  /* Adds the new frame to the frame_table. */
	lock_acquire(&frame_table->lock);
  hash_insert(&frame_table->hash, &fnew->hash_elem);
  list_push_back(&frame_table->list, &fnew->list_elem);
	lock_release(&frame_table->lock);
	return fnew;
}

/* Takes data that is in swap, creates a new frame for it,
 and reads data from the swap table into it.
 Called by page_fault in exception.c. */
struct frame * frame_get_from_swap(struct page_data * data, bool user)
{
	struct frame *f = frame_get_new(data->vaddr, user, data, true);
	swap_read_page(data, f);
	data->is_in_swap = false;
	data->sector = 0;
	data->is_pinned = false;
	return f;
}

void frame_load_data(struct page_data* data, bool user)
{
  lock_acquire(&data->lock);
  if (data->is_in_swap)
    {
      frame_get_from_swap (data, user);
    }
  else if (data->is_mapped)
    {
      struct frame *frame = frame_get_new (data->vaddr, user, data, true);
      void *paddr = frame->paddr;
      /* Populate page with contents from file. */
      struct mmap_file *backing_file = data->backing_file;
      int bytes_read = 0;

      lock_acquire (&filesys_lock);
      bytes_read = file_read_at (backing_file->file, paddr,
          data->readable_bytes, data->file_offset);
      lock_release (&filesys_lock);

      if (bytes_read != data->readable_bytes)
        {
          /* Read in the wrong number of bytes. */
          frame_deallocate_paddr(paddr);
          exit(-1);
        }
      data->is_pinned = false;
    }
  else
    {
      /* Recreate page. */
      frame_get_new (data->vaddr, user, data, false);
    }
  lock_release(&data->lock);
}

/* Finds the correct frame to evict in the event of a swap.
 Called by frame_get_new when palloc_get_page fails. */
static struct frame* frame_to_evict(void)
{
  lock_acquire(&frame_table->lock);
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
      else if (next->data->is_pinned == false)
        {
          next->data->is_pinned = true;
          lock_release(&frame_table->lock);
          return next;
        }
    }
  NOT_REACHED();
  return NULL;
}

