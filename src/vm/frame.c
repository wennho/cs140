#include "vm/frame.h"
#include "kernel/hash.h"

/* inits the single frame table that the kernel and all programs use */
bool frame_is_dirty(struct frame * f){
	return true;
}

/* frees the frame so that a new one can be allocated. */
void frame_free(struct frame * f){
	palloc_free_page(f->paddr);
	list_remove(f->elem);
	free(f);
}

/* initialises the frame_table, called by paging_init in init.c */
frame_table_init(){
	frame_table = malloc(sizeof(struct frame_table));
	hash_init(&frame_table->frame_list, frame_hash,frame_less,NULL);
	return;
}


/* adds a page to the frame table.
returns the page's physical address for use*/
void * new_frame(struct frame_table *ft, void* vaddr)
{
	//obtains a single free page from user pool and
	//returns its physical address (aka kernel virtual address)
	void * a = palloc_get_page(PAL_USER);

	//if no page found returned;
	//if palloc_get_page fails,
	//frame must be made free by evicting some page
	//from its frame.
	while (a == NULL){
		struct frame * fold = frameToEvict(ft);
		removeReferences(fold);
		if(frame_is_dirty(fold))
			writePage(fold);
		frame_free(fold);
		a = palloc_get_page(PAL_USER);
	}

	struct frame * fnew = malloc(sizeof(struct frame));
	fnew->paddr = a;
	fnew->vaddr = vaddr;

	//adds a to the frame_table.
	hash_insert(&ft->frame_list, &fnew->elem);

	return a;
}


struct frame * frameToEvict(struct frame_table * ft){
	ft= ft;
	return NULL;
}

/* for all pages in page table, set valid bit to 0, */
void removeReferences(struct frame * f){
	//for all page tables.
	//if f->vaddr == entry's vaddr.
	//valid bit = 0;
}

void writePage(struct frame * f){
	f=f;
}

/* Returns a hash value for page p. */
unsigned
frame_hash (const struct hash_elem *a, void *aux)
{
  const struct frame *f = hash_entry(a, struct frame, elem);
  return hash_bytes(&f->vaddr, sizeof(f->vaddr));
}

/* Returns true if page a precedes page b. */
bool
frame_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux)
{

struct frame *fa = hash_entry(a,struct frame, elem);
struct frame *fb = hash_entry(b,struct frame, elem);

  return fa->paddr < fb->paddr;
}

