#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include <list.h>
#include "threads/synch.h"

struct bitmap;

/* In-memory inode. */
struct inode
  {
	  struct lock modify_lock;           /* Modification lock. */
	  struct lock extend_lock;           /* Extension lock. */
	  struct lock directory_ops_lock;    /* Lock for directory operations. */
    struct list_elem elem;             /* Element in inode list. */
    block_sector_t sector;             /* Sector number on disk. */
    int open_cnt;                      /* Number of openers. */
    bool removed;                      /* True if deleted. */
    int deny_write_cnt;                /* 0: writes ok, >0: no writes. */
    off_t extended_length;             /* For use in write synchronization. */
    off_t length;                      /* File size in bytes. */
    bool is_dir;                       /* True if inode is a directory. */
  };

void inode_init (void);
bool inode_create (block_sector_t sector, off_t length, bool is_dir);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

#define NUM_DIRECT_BLOCKS 12
#define NUM_POINTERS_PER_BLOCK (BLOCK_SECTOR_SIZE/(int)sizeof(block_sector_t))

#endif /* filesys/inode.h */
