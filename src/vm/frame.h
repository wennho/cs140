#ifndef FRAME_H_
#define FRAME_H_

#include <list.h>
#include <hash.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "vm/page.h"
#include "threads/synch.h"

struct frame_table
{
   struct list list;
   struct hash hash;
   struct list_elem * clock_pointer;
   struct lock lock;
};

struct frame
{
   void* paddr;
   void* vaddr;
   struct hash_elem hash_elem;
   struct list_elem list_elem;
};

struct frame_table* frame_table;
void * frame_get_new_paddr(void* vaddr, bool user);
void * frame_get_from_swap(struct page_data * data, bool user);
void frame_table_init(void);
void frame_unallocate(void* vaddr);
static void frame_free(struct frame * f);

#endif /* FRAME_H_ */
