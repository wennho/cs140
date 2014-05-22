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
   struct page_data *data;      /* Supplemental page entry linked to frame */
   struct hash_elem hash_elem;  /* Hash element. */
   struct list_elem list_elem;  /* List element. */
   unsigned magic;              /* Used for detecting corruption. */
};

struct frame_table* frame_table;
struct frame * frame_get_new(void *vaddr, bool user, struct page_data *data, bool pin_data);
struct frame * frame_get_from_swap(struct page_data* data, bool user);
void frame_table_init(void);
void frame_deallocate(void* vaddr, bool is_in_swap, block_sector_t sector);
void frame_deallocate_paddr (void *paddr);
void frame_load_data(struct page_data *data, bool user);

#endif /* FRAME_H_ */
