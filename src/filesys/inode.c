#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t
    direct_block[NUM_DIRECT_BLOCKS];       /* Direct blocks. */
    block_sector_t indirect_block;         /* Indirect block sector. */
    block_sector_t doubly_indirect_block;  /* Doubly indirect block sector. */
    off_t length;                          /* File size in bytes. */
    unsigned magic;                        /* Magic number. */
    bool is_dir;                           /* Is directory. */
    uint32_t unused[111];                  /* Not used. */
  };


static bool is_direct_block(int location);
static bool is_in_singly_indirect_block(int location);
static bool is_in_doubly_indirect_block(int location);

static bool is_inode_disk (struct inode_disk* disk);

static block_sector_t byte_to_sector (struct inode_disk *disk, off_t pos);

static int calculate_indirect_offset(int location);
static void calculate_doubly_indirect_offsets(int location, int* first_offset,
                                              int *second_offset);
static bool allocate_new_indirect_block(block_sector_t *indirect_block);
static bool allocate_new_block (struct inode_disk *disk, off_t pos);

static void inode_disk_free (struct inode_disk *disk);
static int round_up_to_block_boundary (int pos);

static bool
is_inode_disk (struct inode_disk* disk)
{
  return disk != NULL && disk->magic == INODE_MAGIC;
}

/* Calculates offsets for block pointers in indirect blocks. */
static int
calculate_indirect_offset(int location)
{
  ASSERT(is_in_singly_indirect_block(location));
  return (location - NUM_DIRECT_BLOCKS) * (int)sizeof(block_sector_t);
}

/* Calculates offsets for block pointers in doubly indirect blocks. */
static void
calculate_doubly_indirect_offsets(int location, int* first_offset,
                                  int *second_offset)
{
  ASSERT(is_in_doubly_indirect_block(location));
  *first_offset = ((location - NUM_DIRECT_BLOCKS - NUM_POINTERS_PER_BLOCK)
                  / NUM_POINTERS_PER_BLOCK) * sizeof(block_sector_t);
  *second_offset = ((location - NUM_DIRECT_BLOCKS - NUM_POINTERS_PER_BLOCK)
                   % NUM_POINTERS_PER_BLOCK) * sizeof(block_sector_t);
}

/* True if location represents a direct block. */
static bool
is_direct_block(int location)
{
  return location < NUM_DIRECT_BLOCKS;
}

/* True if the location is in a singly indirect block. */
static bool
is_in_singly_indirect_block(int location)
{
  return !is_direct_block(location)
         && location < (NUM_DIRECT_BLOCKS + NUM_POINTERS_PER_BLOCK);
}

/*/ True if the location is in a doubly indirect block. */
static bool
is_in_doubly_indirect_block(int location)
{
  return (!is_direct_block(location)
         && !is_in_singly_indirect_block(location));
}

static void inode_disk_free (struct inode_disk *disk)
{
	ASSERT (is_inode_disk(disk));
	int i;
	for(i = 0; i < disk->length; i += BLOCK_SECTOR_SIZE)
	{
		block_sector_t next = byte_to_sector(disk, i);
		ASSERT(next != 0 && next != (block_sector_t)-1);
		free_map_release(next, 1);
	}
	if (disk->indirect_block != 0)
	{
		free_map_release(disk->indirect_block, 1);
	}
	if (disk->doubly_indirect_block != 0)
	  {
	    block_sector_t base[NUM_POINTERS_PER_BLOCK];
	    cache_read_at(disk->doubly_indirect_block, &base, BLOCK_SECTOR_SIZE, 0);
	    for (i = 0; i < NUM_POINTERS_PER_BLOCK; i++)
	      {
	        if(base[i] == 0)
	          {
	            /* Unallocated, so break. */
	            break;
	          }
	        free_map_release(base[i], 1);
	      }
	    free_map_release(disk->doubly_indirect_block, 1);
	  }
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (struct inode_disk *disk, off_t pos)
{
  ASSERT (is_inode_disk(disk));
  if (pos >= disk->length)
    {
      return -1;
    }
  size_t bytes_per_entry = sizeof(block_sector_t);
  block_sector_t read_location = pos / BLOCK_SECTOR_SIZE;
  if (is_direct_block(read_location))
    {
      return disk->direct_block[read_location];
    }
  else if(is_in_singly_indirect_block(read_location))
    {
      /* Indirect block case. */
      block_sector_t result;
      int offset = calculate_indirect_offset(read_location);
      cache_read_at(disk->indirect_block, &result, bytes_per_entry, offset);
      return result;
    }
  else
    {
      /* Doubly indirect case. */
      int first_offset;
      int second_offset;
      calculate_doubly_indirect_offsets(read_location, &first_offset,
                                        &second_offset);
      block_sector_t indirect_block;
      cache_read_at(disk->doubly_indirect_block, &indirect_block, 
                    bytes_per_entry, first_offset);
      block_sector_t result;
      cache_read_at(indirect_block, &result, bytes_per_entry, second_offset);
      return result;
    }
}

/* Allocates indirect and doubly indirect blocks. */
static bool
allocate_new_indirect_block(block_sector_t *indirect_block)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  bool allocated = free_map_allocate(1, indirect_block);
  if(!allocated)
    {
      return false;
    }
  cache_write(*indirect_block, zeros);
  return true;
}

/* Gets a new block for an inode. */
static bool
allocate_new_block (struct inode_disk *disk, off_t pos)
{
  ASSERT(is_inode_disk(disk));
  block_sector_t new_block_num;
  bool allocated = free_map_allocate(1, &new_block_num);
  size_t bytes_per_entry = sizeof(block_sector_t);
  if(!allocated)
    {
      return false;
    }
  block_sector_t write_location = pos / BLOCK_SECTOR_SIZE;
  if (is_direct_block(write_location))
    {
      disk->direct_block[write_location] = new_block_num;
    }
  else if(is_in_singly_indirect_block(write_location))
    {
      /* Indirect block case. */
      if(disk->indirect_block == 0)
        {
          block_sector_t indirect_sector;
          if(!allocate_new_indirect_block(&indirect_sector))
            {
              return false;
            }
          disk->indirect_block = indirect_sector;
        }
      int offset = calculate_indirect_offset(write_location);
      cache_write_at(disk->indirect_block, &new_block_num,
                     bytes_per_entry, offset);
    }
  else
    {
      /* Doubly indirect case. */
      if(disk->doubly_indirect_block == 0)
        {
          block_sector_t doubly_indirect_sector;
          if(!allocate_new_indirect_block(&doubly_indirect_sector))
            {
              return false;
            }
          disk->doubly_indirect_block = doubly_indirect_sector;
        }
      int first_offset;
      int second_offset;
      calculate_doubly_indirect_offsets(write_location, &first_offset,
                                       &second_offset);
      block_sector_t indirect_block;
      cache_read_at(disk->doubly_indirect_block, &indirect_block,
                    bytes_per_entry, first_offset);
      if(indirect_block == 0)
        {
          if(!allocate_new_indirect_block(&indirect_block))
            {
              return false;
            }
          cache_write_at(disk->doubly_indirect_block, &indirect_block,
                         bytes_per_entry, first_offset);
        }
      cache_write_at(indirect_block, &new_block_num,
                     bytes_per_entry, second_offset);
    }
  return true;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  ASSERT (length >= 0);
  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      disk_inode->indirect_block = 0;
      disk_inode->doubly_indirect_block = 0;
      int j;
      for(j = 0; j < length; j+= BLOCK_SECTOR_SIZE)
        {
          bool allocated = allocate_new_block(disk_inode, j);
          if(!allocated)
            {
              inode_disk_free (disk_inode);
              free (disk_inode);
              return false;
            }
        }
      cache_write(sector, disk_inode);
      return true;
    }
  return false;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  lock_init(&inode->modify_lock);
  lock_init(&inode->extend_lock);
  lock_init(&inode->directory_ops_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  /* Find length and start sector of inode */
  struct inode_disk disk;
  cache_read(inode->sector, &disk);
  ASSERT(is_inode_disk(&disk));
  inode->length = disk.length;
  inode->is_dir = disk.is_dir;
  inode->extended_length = 0;
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
  {
	  lock_acquire(&inode->modify_lock);
    inode->open_cnt++;
    lock_release(&inode->modify_lock);
  }
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&inode->modify_lock);
  inode->open_cnt--;
  lock_release(&inode->modify_lock);
  if (inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk disk;
          cache_read (inode->sector, &disk);
          inode_disk_free (&disk);
          free_map_release(inode->sector, 1);
        }
      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}


/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;

  struct inode_disk disk;
  cache_read(inode->sector, &disk);
  ASSERT(is_inode_disk(&disk));

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&disk, offset);
      if(sector_idx == (block_sector_t) -1)
        {
          /* End of file. */
          break;
        }
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;


      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;


      /* Do read-ahead for the next block */
      block_sector_t next_block_sector = byte_to_sector (
          &disk, offset + BLOCK_SECTOR_SIZE);
      if (next_block_sector != (block_sector_t) -1)
        {
          cache_add_read_ahead_task(next_block_sector);
        }
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read(sector_idx, buffer + bytes_read);
        }
      else 
        {
          cache_read_at(sector_idx, buffer + bytes_read, chunk_size, sector_ofs);
        }
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  return bytes_read;
}

/* Rounds a position up to a block boundary. */
static int
round_up_to_block_boundary (int pos)
{
  if(pos % BLOCK_SECTOR_SIZE == 0)
    {
      return pos;
    }
  return (pos + BLOCK_SECTOR_SIZE - (pos % BLOCK_SECTOR_SIZE));
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 Returns the number of bytes actually written, which may be
 less than SIZE if an error occurs. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  off_t original_offset = offset;

  if (inode->deny_write_cnt > 0)
    {
      return 0;
    }

  struct inode_disk disk;
  cache_read(inode->sector, &disk);
  ASSERT(is_inode_disk(&disk));
  int block_boundary = round_up_to_block_boundary(disk.length);
  if(offset + size > block_boundary)
    {
      lock_acquire(&inode->extend_lock);
      if(inode->extended_length != 0)
        {
          block_boundary = round_up_to_block_boundary(inode->extended_length);
        }
      /* Recheck, because block boundary may have been reset based on the
       extended length. */
      if(offset + size > block_boundary)
        {
          int i;
          for(i = block_boundary; i < offset + size; i+= BLOCK_SECTOR_SIZE)
            {
              if(!allocate_new_block(&disk, i))
                {
                  int j;
                  for(j = block_boundary; j < i; j += BLOCK_SECTOR_SIZE)
                    {
                      free_map_release(byte_to_sector(&disk, j), 1);
                    }
                  inode->extended_length = 0;
                  lock_release(&inode->extend_lock);
                  return 0;
                }
            }
          inode->extended_length = offset + size;
          cache_write(inode->sector, &disk);
          disk.length = offset + size;
          lock_release(&inode->extend_lock);
        }
    }
  else if(offset + size > disk.length)
    {
      disk.length = offset + size;
    }
  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (&disk, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = sector_left;
      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector to cache. */
          cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
           void* sector_data;
          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            {
              cache_write_at(sector_idx, buffer + bytes_written, chunk_size, sector_ofs);
            }
          else
            {
              sector_data = calloc (BLOCK_SECTOR_SIZE, 1);
              memcpy (sector_data + sector_ofs, buffer + bytes_written, chunk_size);
              cache_write (sector_idx, sector_data);
              free(sector_data);
            }

        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  /* Write to disk only after everything is done. */
  if(original_offset + bytes_written > inode->length)
    {
      lock_acquire(&inode->modify_lock);
      inode->length = original_offset + bytes_written;
      disk.length = original_offset + bytes_written;
      lock_release(&inode->modify_lock);
      cache_write(inode->sector, &disk);
    }
  lock_acquire(&inode->modify_lock);
  inode->extended_length = 0;
  lock_release(&inode->modify_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
	lock_acquire(&inode->modify_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->modify_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
	lock_acquire(&inode->modify_lock);
	ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->modify_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->length;
}
