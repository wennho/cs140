#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

typedef struct{
  //20 bit page number, 12 bit offset.
  uint32_t page_address;
  bool valid;
} page_entry;

typedef struct{
  struct frame_entry * frame_entries[PGSIZE];
}frame_table;

typedef struct{
  struct page_entry* page_entries[PGSIZE];
}page_table;

typedef struct{
  uint32_t frame_address;
  bool valid;
} frame_entry;

/* inits a page , puts it in page table */
struct page_entry * init_page_entry(){
  uint32_t physicalAddress = pagedir_create();
  struct page_entry * p = malloc(sizeof(struct page_entry));
  if (p == NULL)
  {
    return -1;
  }
  p->page_address = physicalAddress;

  p->valid = 1;
  return p;
}




/* insert new page in page table */
bool insert_page_entry(struct page_table * page_table){
  struct page_entry * p = init_page_entry();

  for(int i = 0;i<PGSIZE; i++){
	if(page_table->page_entries[i]->valid == 0){
		page_table->page_entries[i] = p;
		return 1;
	}
  }
  //no availability.
  return 0;

}



