#ifndef FRAME_H_
#define FRAME_H_

#include <list.h>
#include <hash.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/synch.h"
#include "vm/page.h"

struct page_data;

struct frame_table
{
   struct list list;                  /* Frame list. */
   struct hash hash;                  /* Frame hash. */
   struct list_elem * clock_pointer;  /* Used for eviction. */
   struct lock lock;                  /* Frame table lock. */
};

struct frame
{
   void* paddr;                 /* Physical address of frame. */
   void* vaddr;                 /* Virtual address of page linked to frame. */
   struct hash_elem hash_elem;  /* Hash element. */
   struct list_elem list_elem;  /* List element. */
   bool is_pinned;              /* True if frame is pinned. */
   unsigned magic;              /* Used for detecting corruption. */
};

struct frame_table* frame_table;
void * frame_get_new_paddr(void* vaddr, bool user);
void * frame_get_from_swap(struct page_data* data, bool user);
void frame_table_init(void);
void frame_deallocate(void* vaddr);
void frame_deallocate_paddr (void *paddr);
void frame_set_pin(void* vaddr, bool setting);

#endif /* FRAME_H_ */
