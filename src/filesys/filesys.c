#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
static struct dir *initialize_directory(struct dir* directory);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
  cache_flush();
}

/* Initializes directory for filesys calls. */
static struct dir *initialize_directory(struct dir* directory)
{
  if(directory == NULL)
    {
      return dir_open_root();
    }
  else
    {
      return dir_reopen(directory);
    }
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char *name, off_t initial_size, bool is_dir, struct dir* directory)
{
  block_sector_t inode_sector = 0;
  directory = initialize_directory(directory);
  bool success =  (free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (directory, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (directory);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name, struct dir* directory)
{
  directory = initialize_directory(directory);
  struct inode *inode = NULL;
  dir_lookup (directory, name, &inode);
  dir_close (directory);
  struct file * f=file_open (inode);
  return f;
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name, struct dir* directory)
{
  directory = initialize_directory(directory);
  bool success = dir_remove (directory, name);
  dir_close (directory);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_root_create ())
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
