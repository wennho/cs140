#ifndef OPENED_FILE_H_
#define OPENED_FILE_H_

#include <hash.h>
#include <stdbool.h>

/* Struct containing a file opened by a thread and a reference to it
 for the list. */
struct opened_file
{
	struct file *f;
	int fd;
	struct hash_elem elem;
};

unsigned opened_file_hash (const struct hash_elem *e, void *aux);
bool opened_file_hash_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
void opened_file_hash_destroy(struct hash_elem *e, void *aux);

void remove_file(int fd);
struct file* get_file(int fd);
struct opened_file* get_opened_file (int fd);
void file_destruct(struct opened_file * fe);

#endif /* OPENED_FILE_H_ */
