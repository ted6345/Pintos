#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H
#define SECTOR_ERROR -1  //sector_unknown
#define BC_ENTRY_NB 64   //buffer_cache_entry

#include <stdbool.h>
#include <stdint.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"

//buffer_cache data structure
struct buffer_head{

	bool dirty; //dirty bit
	bool used;  //used bit
	bool clock; //clock bit
	block_sector_t sector; //sector num
	struct lock lock; // lock.
	uint8_t* data;  // data section

};


bool bc_read(block_sector_t sector_idx,void* buffer,off_t bytes_read,int chunk_size,int sector_ofs);
bool bc_write(block_sector_t sector_idx,void* buffer,off_t bytes_written,int chunk_size,int sector_ofs);
void bc_init(void);
void bc_term(void);
struct buffer_head* bc_select_victim(void);
struct buffer_head* bc_lookup(block_sector_t sector);
void bc_flush_entry(struct buffer_head *p_flush_entry);
void bc_flush_all_entries(void);


#endif
