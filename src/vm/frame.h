#ifndef FRAME_H_
#define FRAME_H_

#include <stdbool.h>
#include <filesys/file.h>
#include "kernel/hash.h"
#include <list.h>
#include <hash.h>

struct frame_table
{
   struct list list;
   struct hash hash;
};

struct frame
{
   void* paddr;
   void* vaddr;
   struct hash_elem hash_elem;
   struct list_elem list_elem;
};

void * frame_get_new(void* vaddr);
void frame_table_init(void);


#endif /* FRAME_H_ */
