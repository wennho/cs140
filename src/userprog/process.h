#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct list_elem* child_elem_of_current_thread (tid_t child_tid, struct list *list);

#define PROCESS_MAGIC 0xdeadbeef
#define MAX_CMD_LINE_LENGTH 200

#endif /* userprog/process.h */
