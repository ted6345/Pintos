#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/buffer_cache.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

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

  /*set thread's current working directory to root directory */
  thread_current()->cur_dir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  /* parse name and open current dir*/
  if(strlen(name) > NAME_MAX)
	return false;
  char cp_name[strlen(name) + 1];
  char file_name[NAME_MAX + 1];
  strlcpy(cp_name, name, strlen(name) + 1);
  struct dir *dir = parse_path(cp_name, file_name);
  block_sector_t inode_sector = 0;

  if(dir == NULL)
	return false; 
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, 0)
                  && dir_add (dir, file_name, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);

  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  /* parse name and open current dir*/
  if(strlen(name) > NAME_MAX)
	return false;

  char cp_name[strlen(name) + 1];
  char file_name[NAME_MAX + 1];
  strlcpy(cp_name, name, strlen(name) + 1);
  struct dir *dir = parse_path(cp_name, file_name);
  struct inode *inode = NULL;

  if(strlen(name)==1&&name[0]=='/'){
	  return file_open(dir_get_inode(dir));
  }

  if (dir != NULL)
    dir_lookup (dir, file_name, &inode);
  dir_close (dir);

  if(inode==NULL)
	  return NULL;

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  /* parse name and open current dir*/
  if(strlen(name) > NAME_MAX)
	return false;
  char cp_name[strlen(name) + 1];
  char file_name[NAME_MAX + 1];
  strlcpy(cp_name, name, strlen(name) + 1);
  struct dir *dir = parse_path(cp_name, file_name);

  struct inode* rm_inode;
  dir_lookup(dir, file_name, &rm_inode);
  /* check if inode is directory */
  if(inode_is_dir(rm_inode)){
	struct inode* anc_inode;
	struct dir* temp_dir = dir_reopen(thread_current()->cur_dir);
	struct dir* root = dir_open_root();
	/* find cur_dir's ancestors from cwd to root */
	while(dir_lookup(temp_dir, "..", &anc_inode)){
		dir_close(temp_dir);
		temp_dir = dir_open(anc_inode);
		if(anc_inode == dir_get_inode(root)){
			dir_close(temp_dir);
			break; //anc_inode is root
		}
		/*if we find rm_inode in ancestor directory*/
		if(rm_inode == anc_inode){
			dir_close(temp_dir);
			dir_close(root);
			return false;
		}
	}
	dir_close(root);
  }

  bool success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir); 

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  struct dir* dir = dir_open_root();
  /*add current path and parent path entry in root*/
  dir_add(dir, ".", ROOT_DIR_SECTOR);
  dir_add(dir, "..", ROOT_DIR_SECTOR);
  dir_close(dir);
  free_map_close ();
  printf ("done.\n");
}

/* Return working current directory and file name by parsing path */
struct dir* parse_path(char *path_name, char *file_name){

	struct dir* dir;
	struct inode* inode;
	if(path_name == NULL || file_name == NULL)
		goto fail;
	/* check if path_name is "" */
	if(strlen(path_name) == 0)
		goto fail;

	/* determine if path is absolute or relative */
	if(path_name[0] == '/')
		dir = dir_open_root(); //absolute path
	else
		dir = dir_reopen(thread_current()->cur_dir); //relative path

	/* parse the path_name*/
	char *token, *nextToken, *savePtr;
	token = strtok_r(path_name, "/", &savePtr);
	nextToken = strtok_r(NULL, "/", &savePtr);

	while( token != NULL && nextToken != NULL){
		/* find the entry in dir which name is token */
		if(!dir_lookup(dir, token, &inode)){
			return NULL;
		}
		/* check if entry is directory */
		if(!inode_is_dir(inode)){
			return NULL;
		}
		/* set new current working directory */
		dir_close(dir);
		dir = dir_open(inode);
		token = nextToken;
		nextToken = strtok_r(NULL, "/", &savePtr);
	}
	/* after parsing path_name, token would be file_name */
	if(token != NULL)
		strlcpy(file_name, token, NAME_MAX + 1);
	else{
		file_name = NULL;
	}
	if(is_inode_removed(dir_get_inode(dir))){
		dir_close(dir);
		return NULL;
	}


	/* return current working dir*/
	return dir;	

	fail:
	return NULL;

}

/* Create directory in name(directory)*/
bool filesys_create_dir(const char* name){
 	/* parse name and open current dir*/
	if(strlen(name) > NAME_MAX)
		return false;
	char cp_name[strlen(name) + 1];
	char file_name[NAME_MAX + 1];
	strlcpy(cp_name, name, strlen(name) + 1);
	struct dir* dir = parse_path(name, file_name);
	if(dir == NULL)
		return false;
	/* allocate inode space */
	block_sector_t inode_sector = 0;
	if(!free_map_allocate(1,&inode_sector))
		return false;
	/* create directory inode */
	if(!dir_create(inode_sector, 16))
		return false;
	/* add entry to current dir*/
	if(!dir_add(dir, file_name, inode_sector))
		return false;

	/* newly created directory includes current path and parent path*/
	struct dir* new_dir = dir_open(inode_open(inode_sector));
	if(new_dir){
		/*add current path to new directory*/
		if(!dir_add(new_dir, ".", inode_sector))
			return false;
		/*add parent path to new directory*/
		if(!dir_add(new_dir, "..", inode_get_inumber(dir_get_inode(dir))))
			return false;
		dir_close(new_dir);
	} else
		return false;
	dir_close(dir);

	return true;
}

