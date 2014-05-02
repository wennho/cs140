#ifndef FRAME_H_
#define FRAME_H_

#include <stdbool.h>
#include <filesys/file.h>
#include <list.h>
#include <hash.h>

struct frame_table
{
   struct hash frame_list;
};

struct frame
{
   void * paddr;
   void * vaddr; // the virtual address using it.

   struct hash_elem elem;
};

unsigned frame_hash (const struct hash_elem *a, void *aux);
bool frame_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux);

void * new_frame(struct frame_table *ft,void* vaddr);

bool frame_is_dirty(struct frame *f);
void frame_free(struct frame * f);
struct frame * frameToEvict(struct frame_table * ft);
void removeReferences(struct frame * f);
void writePage(struct frame * f);

struct frame_table * frame_table_init(void);

#endif /* FRAME_H_ */
