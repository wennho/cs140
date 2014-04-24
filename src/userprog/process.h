#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct child_process* child_process_from_tid (tid_t child_tid,
    struct list *child_list);

struct child_process* process_create_list_elem(tid_t tid);

#define PROCESS_MAGIC 0xdeadbeef
#define MAX_CMD_LINE_LENGTH 200

bool is_process(struct child_process *process);

#endif /* userprog/process.h */
