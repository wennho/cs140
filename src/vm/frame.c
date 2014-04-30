#include "vm/frame.h"


/* inits the single frame table that the kernel and all programs use */
struct frame_table * frame_table_init(){
	return NULL;
};

/* adds a page to the frame table. 
returns the page's physical address for use*/
uint32_t new_frame(struct frame_table *ft UNUSED)
{
	uint32_t a = palloc_get_page(PAL_USER);

	//if palloc_get_page fails,
	//frame must be made free by evicting some page
	//from its frame.

	
	return NULL;
}


struct frame * frameToEvict(struct frame_table * ft UNUSED){
	return NULL;
}

void removeReferences(strucdt frame * f){
	f = f;
}

void writePage(struct frame * f){
	f=f;
}

