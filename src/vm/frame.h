#ifndef FRAME_H_
#define FRAME_H_

#include <stdbool.h>
#include <filesys/file.h>
#include <list.h>

struct frame_table
{
   struct list frame_list;
};

struct frame
{
   uint32_t faddr;
   struct list_elem elem;
};

struct frame * frameToEvict(struct frame_table * ft);
void removeReferences(struct frame * f);
void writePage(struct frame * f);

struct frame_table * frame_table_init();

#endif /* FRAME_H_ */
