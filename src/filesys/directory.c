#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Creates the root directory. */
bool
dir_root_create ()
{
  if(inode_create (ROOT_DIR_SECTOR, 0, true))
    {
      struct dir* root = dir_open_root();
      dir_add(root, ".", ROOT_DIR_SECTOR);
      dir_add(root, "..", ROOT_DIR_SECTOR);
      dir_close(root);
      return true;
    }
  return false;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Returns the directory referred to by path. Will cut off
 after going through cutoff number of directories. */
struct dir *dir_find(const char* path, int cutoff)
{
  struct dir* dir;
  if(*path == '/' || thread_current()->current_directory == NULL)
    {
      dir = dir_open_root();
    }
  else
    {
      dir = dir_reopen(thread_current()->current_directory);
    }
  char *token;
  char *save_ptr;
  char local_path[strlen(path) + 1];
  strlcpy(local_path, path, strlen(path) + 1);
  int num_dirs_passed = 0;
  for (token = strtok_r (local_path, "/", &save_ptr); token != NULL; token =
         strtok_r (NULL, "/", &save_ptr))
    {
      if(cutoff == num_dirs_passed)
        {
          return dir;
        }
      int token_length = strnlen(token, NAME_MAX + 1);
      if(token_length == NAME_MAX + 1)
        {
          /* Name too long. */
          dir_close(dir);
          return NULL;
        }
      else
        {
          struct inode* next_inode;
          if(!dir_lookup(dir, token, &next_inode))
            {
              dir_close(dir);
              return NULL;
            }
          if(next_inode->is_dir == false)
            {
              dir_close(dir);
              inode_close(next_inode);
              return NULL;
            }
          dir_close(dir);
          dir = dir_open(next_inode);
        }
      num_dirs_passed++;
    }
  return dir;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name, bool marked_as_directory)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    {
      goto done;
    }

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    {
      goto done;
    }

   if (inode->is_dir)
    {
      /* Cannot remove directories in use by a process. */
      if(inode->open_cnt > 1)
        {
          goto done;
        }
      /* Check that the directory is empty. */
      struct dir* deletion_directory = dir_open(inode);
      char name[NAME_MAX + 1];
      /* Read the first two entries in dir, which are "." and "..". */
      dir_readdir(deletion_directory, name);
      dir_readdir(deletion_directory, name);
      if(dir_readdir(deletion_directory, name))
        {
          /* Entry other than "." or ".." still in directory. */
          dir_close(deletion_directory);
          return false;
        }
      dir_close(deletion_directory);
      inode = inode_open(e.inode_sector);
    }
   else
     {
       /* Cannot remove a filename if user inputted it with a slash. */
       if(marked_as_directory)
         {
           goto done;
         }
     }

  /* Erase directory entry. */

  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    {
      goto done;
    }

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          return true;
        } 
    }
  return false;
}
