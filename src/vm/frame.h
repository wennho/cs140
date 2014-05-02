#ifndef FRAME_H_
#define FRAME_H_

#include <stdbool.h>
#include <filesys/file.h>
#include <list.h>

struct frame_table
{
   struct list frame_list;
   struct hash frame_hash;
};

struct frame
{
   void * paddr;
   void * vaddr;
   struct hash_elem hash_elem;
   struct list_elem list_elem;
};

void * get_new_frame();
bool frame_is_dirty(struct frame *f);
void frame_free(struct frame * f);
struct frame * frameToEvict(struct frame_table * ft);
void removeReferences(struct frame * f);
void writePage(struct frame * f);

struct frame_table * frame_table_init();

#endif /* FRAME_H_ */
