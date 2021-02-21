#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "filesys/buffer_cache.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "devices/block.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define INDIRECT_BLOCK_ENTRIES 128
#define DIRECT_BLOCK_ENTRIES 123

// the ways inode points disk_block
enum inode_number_type {
	NORMAL_DIRECT, INDIRECT, DOUBLE_INDIRECT, OUT_LIMIT
};

// structure for block access type& block_offset
struct sector_location {
	int directness;
	off_t index1;
	off_t index2;
};

/* On-disk inode.
 Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
	off_t length; /* File size in bytes. */
	unsigned magic; /* Magic number. */
	int is_dir; //0 : file & 1 : directory
	block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];  //direct_map_table
	block_sector_t indirect_block_sector;  //indirect_table
	block_sector_t double_indirect_block_sector; //double_indirect_table
};

/* In-memory inode. */
struct inode {
	struct list_elem elem; /* Element in inode list. */
	block_sector_t sector; /* Sector number of disk location. */
	int open_cnt; /* Number of openers. */
	bool removed; /* True if deleted, false otherwise. */
	int deny_write_cnt; /* 0: writes ok, >0: deny writes. */
	struct lock extend_lock; // lock for inode
};


static block_sector_t byte_to_sector(const struct inode_disk* inode_disk, off_t pos);
bool inode_update_file_length(struct inode_disk* inode_disk, off_t start_pos, off_t end_pos);
static void free_inode_sectors (struct inode_disk* inode_disk);
static bool register_sector (struct inode_disk* inode_disk,block_sector_t new_sector, struct sector_location sec_loc);
bool get_disk_inode(const struct inode* inode,struct inode_disk* inode_disk);
static void locate_byte(off_t pos, struct sector_location *sec_loc);
bool is_inode_removed(const struct inode* inode);

/* Returns the number of sectors to allocate for an inode SIZE
 bytes long. */
static inline size_t bytes_to_sectors(off_t size) {
	return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}


/* List of open inodes, so that opening a single inode twice
 returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
	list_init(&open_inodes);

}

bool is_inode_removed(const struct inode* inode){
	return inode->removed;
}

/* Initializes an inode with LENGTH bytes of data and
 writes the new inode to sector SECTOR on the file system
 device.
 Returns true if successful.
 Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, uint32_t is_dir) {

	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT(length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 one sector in size, and you should fix that. */
	ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);
	disk_inode = calloc(1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
		disk_inode->is_dir = is_dir;

		//inode_update_file_length함수를 이용하여 디스크블락을 할당해준다.
		//disk_inode를 bc_write를 이용해 최신화.
		if(length > 0)	inode_update_file_length(disk_inode, 0, (length-1));
		success = bc_write(sector, (void*)disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
		free(disk_inode);
	}

	return success;
}

/* Reads an inode from SECTOR
 and returns a `struct inode' that contains it.
 Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector) {

	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e =
			list_next(e)) {
		inode = list_entry(e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen(inode);
			return inode;
		}
	}

	/* Allocate memory. */
	inode = malloc(sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front(&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	lock_init(&inode->extend_lock);

	return inode;
}


/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode) {

	if (inode != NULL)
		inode->open_cnt++;
	return inode;

}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 If this was the last reference to INODE, frees its memory.
 If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove(&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
			// get_disk_inode
			struct inode_disk *disk_inode = (struct inode_disk*) malloc(BLOCK_SECTOR_SIZE);
			get_disk_inode(inode, disk_inode);

			//free disk_inode
			free_inode_sectors (disk_inode);
			struct buffer_head* tmp_cache = bc_lookup(inode->sector);
			if(tmp_cache != NULL)		bc_flush_entry(tmp_cache);
			free_map_release(inode->sector,1);
			free(disk_inode);
		}

		free(inode);
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 has it open. */
void inode_remove(struct inode *inode) {
	ASSERT(inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 Returns the number of bytes actually read, which may be less
 than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset) {

	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	off_t length;
	static bool sec_0 = true;

	//disk_inode를 할당받고 length를 구한다.
	lock_acquire(&inode->extend_lock);
	struct inode_disk *disk_inode = (struct inode_disk*) malloc(BLOCK_SECTOR_SIZE);
	get_disk_inode(inode,disk_inode);
	length = disk_inode->length;
	lock_release(&inode->extend_lock);

	while (size > 0) {
		/* Disk sector to read, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector(disk_inode, offset);

		//야매코드.
		//버퍼를 0으로 채워서 반환.
		if(sector_idx == 0 && sec_0){
			void* zero = malloc(BLOCK_SECTOR_SIZE);
			memset(zero,0,BLOCK_SECTOR_SIZE);
			bc_write(sector_idx,zero,0,BLOCK_SECTOR_SIZE,0);
			free(zero);
			sec_0 = false;
		}

		int sector_ofs = offset % BLOCK_SECTOR_SIZE;
		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = length - offset;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;
		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		// Buffer_cache Read.
		lock_acquire(&inode->extend_lock);
		bc_read(sector_idx, (void*) buffer, bytes_read, chunk_size, sector_ofs);
		lock_release(&inode->extend_lock);

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}

	free(disk_inode);
	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 Returns the number of bytes actually written, which may be
 less than SIZE if end of file is reached or an error occurs.
 (Normally a write at end of file would extend the inode, but
 growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
		off_t offset) {

	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;

	if (inode->deny_write_cnt)
		return 0;

	//disk_inode 동적할당뒤 bc_read.
	lock_acquire(&inode->extend_lock);
	struct inode_disk *disk_inode = (struct inode_disk*) malloc(BLOCK_SECTOR_SIZE);
	if(disk_inode == NULL) return -1;
	get_disk_inode(inode, disk_inode);

	int length = disk_inode->length;
	int write_end = offset + size - 1;

	//파일 길이가 증가하였을 경우, disk_inode update.
	if( write_end > length - 1 )
		{
		inode_update_file_length(disk_inode, offset, write_end);
		bc_write(inode->sector,(void*)disk_inode,0,BLOCK_SECTOR_SIZE,0);
		length = disk_inode->length;
		}

	lock_release(&inode->extend_lock);


	while (size > 0) {

		/* Sector to write, starting byte offset within sector. */
		block_sector_t sector_idx = byte_to_sector(disk_inode, offset);
		int sector_ofs = offset % BLOCK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = length - offset;
		int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;

		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;
		//bc_write
		lock_acquire(&inode->extend_lock);
		bc_write(sector_idx, (void*) buffer, bytes_written, chunk_size, sector_ofs);
		lock_release(&inode->extend_lock);
		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}


	free(disk_inode);

	return bytes_written;
}

/* Disables writes to INODE.
 May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode) {
	inode->deny_write_cnt++;
	ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 Must be called once by each inode opener who has called
 inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode) {
	ASSERT(inode->deny_write_cnt > 0);
	ASSERT(inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (struct inode *inode)
{
//	lock_acquire(&inode->extend_lock);

	//get_disk_inode
	struct inode_disk *disk_inode = (struct inode_disk*) malloc(BLOCK_SECTOR_SIZE);
	get_disk_inode(inode, disk_inode);

	//get_disk_inode length
	off_t length = disk_inode->length;
	free(disk_inode);

//	lock_release(&inode->extend_lock);
	return length;
}

// read inode from buffer-cache
bool get_disk_inode(const struct inode* inode, struct inode_disk* inode_disk) {

	if(inode != NULL)
		return bc_read(inode->sector, (void*) inode_disk, 0, BLOCK_SECTOR_SIZE, 0);
	else
		return false;
}

// calculate sec_loc values.
static void locate_byte(off_t pos, struct sector_location *sec_loc) {

	off_t pos_sector = pos / BLOCK_SECTOR_SIZE;

	//Direct 접근방식
	if(pos_sector < (off_t) DIRECT_BLOCK_ENTRIES) {
		sec_loc->directness = NORMAL_DIRECT;
		sec_loc->index1 = pos_sector ;
	}
	//Indirect 접근방식
	else if (pos_sector < (off_t) (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES)) {
		sec_loc->directness = INDIRECT;
		sec_loc->index1 = pos_sector - (off_t) DIRECT_BLOCK_ENTRIES;
	}
	//Double_Indirect 접근방식
	else if (pos_sector < (off_t) (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * (INDIRECT_BLOCK_ENTRIES + 1)) ) {
		sec_loc->directness = DOUBLE_INDIRECT;
		sec_loc->index1 = (pos_sector - (off_t) (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES)) / INDIRECT_BLOCK_ENTRIES ;
		sec_loc->index2 = (pos_sector - (off_t) (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES)) % INDIRECT_BLOCK_ENTRIES ;
	}
	else
		sec_loc->directness = OUT_LIMIT;

}

//새로 할당받은 디스크 블록의 번호를 inode_disk에 update.
static bool register_sector (struct inode_disk* inode_disk, block_sector_t new_sector, struct sector_location sec_loc)
{

	block_sector_t sector_idx;
	//indirect_block_sector에 write할 buffer를 할당해준다.
	block_sector_t* new_block =(block_sector_t*) malloc (BLOCK_SECTOR_SIZE);
	if(new_block == NULL)		goto error;

	switch(sec_loc.directness)
	{
		//Driect 접근방식일때,
		case NORMAL_DIRECT:
			//inode_disk의 direct_map에 직접 참조한다.
			inode_disk->direct_map_table[sec_loc.index1] = new_sector;
			break;

		//Indirect 접근방식일때,
		case INDIRECT:
			//Indirect 접근방식이 처믐일때는 indirect_block_sector를 할당해준다.
			if(sec_loc.index1 == 0)
			{
				if(free_map_allocate(1,&sector_idx))
					inode_disk->indirect_block_sector = sector_idx;
				else goto error;
			}
			//Indirect map의 index번째에 new_sector를 집어넣어주고
			//bc_write을 통해 inode_disk의 indirect_block_sector를 최신화해준다.
			new_block[sec_loc.index1] = new_sector;
			bc_write(inode_disk->indirect_block_sector, (void*) new_block, (sec_loc.index1 * 4), 4 ,(sec_loc.index1 * 4));

			break;
		//Double_Indirect 접근방식일때
		case DOUBLE_INDIRECT:
			//Double Indirect 접근방식이 처믐일때는 Double indirect_block_sector를 할당해준다.
			if(sec_loc.index1 == 0 && sec_loc.index2 == 0)
			{
				if(free_map_allocate(1,&sector_idx))
					inode_disk->double_indirect_block_sector = sector_idx;
				else goto error;
			}
			//Double_indriect의 각 index에 대해서 처음접근할때는 또 double_indirect_map의 index_sector를 할당해준다.
			if(sec_loc.index2 == 0){
				if(free_map_allocate(1,&sector_idx)){
					new_block[sec_loc.index1] = sector_idx;
					bc_write(inode_disk->double_indirect_block_sector, (void*) new_block, (sec_loc.index1*4), 4 ,(sec_loc.index1*4));
				}
				else goto error;
			}

			//Double_indirect의 첫번째 map에서 참조해야할 sector번호를 얻는다.
			bc_read(inode_disk->double_indirect_block_sector, (void*) new_block, 0, BLOCK_SECTOR_SIZE, 0);
			sector_idx = new_block[sec_loc.index1];

			//얻은 sector에 new_sector 값을 write해준다.
			new_block[sec_loc.index2] = new_sector;
			bc_write(sector_idx, (void*) new_block, (sec_loc.index2*4), 4, (sec_loc.index2*4));
			break;

		default:
			return false;
	}

	//할당해제
	free(new_block);
	return true;

	//error handling.
	error:  free(new_block);
			printf("reg sector error\n");
			return false;

}


// search block_sector by file's offset.
static block_sector_t byte_to_sector(const struct inode_disk* inode_disk, off_t pos){

	struct sector_location sec_loc;   // block_sector가 저장된 위치를 저장.
	block_sector_t result_sec = -1;   // 반환할 디스크 블록 번호
	block_sector_t* block_map = (block_sector_t*) malloc (BLOCK_SECTOR_SIZE); //indirect방식일때 자료를 얻기위해.

	if( pos < inode_disk->length) //inode_length보다 작을때
	{
		locate_byte(pos,&sec_loc); // block_sector가 저장된 위치를 계산.
		switch(sec_loc.directness) // 접근방식에따라
		{
			case NORMAL_DIRECT:
				//직접접근시 direct_map_table[index1]
				result_sec = inode_disk->direct_map_table[sec_loc.index1];
				break;

			case INDIRECT:
				//indirect시 block_sector를 block_map에 가져온뒤 indirect_block_map에서
				//result_sec을 읽음.
				bc_read(inode_disk->indirect_block_sector, (void*) block_map, 0,BLOCK_SECTOR_SIZE, 0);
				result_sec = block_map[sec_loc.index1];
				break;

			case DOUBLE_INDIRECT:
				//double_indirect시 첫번째 map에서 참조해야할 block sector_num을 읽어옴
				bc_read(inode_disk->double_indirect_block_sector, (void*) block_map, 0,BLOCK_SECTOR_SIZE, 0);
				block_sector_t sector_index = block_map[sec_loc.index1];
				//얻은 sector_index로부터 block_map을 읽고
				//index2를 이용하여 result_sec을 참조.
				bc_read(sector_index, (void*) block_map, 0,BLOCK_SECTOR_SIZE, 0);
				result_sec = block_map[sec_loc.index2];
				break;

			default:
				return false;
		}
	}
	free(block_map);
	return result_sec;
}


// 파일의 크기가 증가하면, new_disk_block_sector를 할당하고 disk_inode에 기록한다.
bool inode_update_file_length(struct inode_disk* inode_disk, off_t start_pos, off_t end_pos)
{
	//각종 변수 선언
	off_t size = end_pos - start_pos + 1;
	off_t offset = start_pos;
	block_sector_t sector_idx;
	inode_disk->length = end_pos+1;
	unsigned chunk_size;

	struct sector_location sec_loc;
	//새로 할당 받은 disk_block을 0으로 초기화해주기 위한 block
	void* zeroes = malloc(BLOCK_SECTOR_SIZE);
	memset (zeroes, 0, BLOCK_SECTOR_SIZE);

	//모든 디스크블락을 할당할때까지 순회한다.
	while(size > 0)
	{
		//sector_ofs과 chunk_size 계산
		off_t sector_ofs = offset % BLOCK_SECTOR_SIZE;
		chunk_size = BLOCK_SECTOR_SIZE - sector_ofs;
		if(size <BLOCK_SECTOR_SIZE)
			if(sector_ofs + size <= BLOCK_SECTOR_SIZE)
				chunk_size = size;

		// sector_ofs > 0 은 해당 sector가 존재한다는 의미.
		if(sector_ofs > 0){
			sector_idx = byte_to_sector(inode_disk, offset);

			// sector_idx == 0 이면 이 offset에서 최초로 block_sector가 접근했다는
			// 의미이므로 새로 disk_block을 할당해주어야한다.
			if(sector_idx == 0){
				if(free_map_allocate(1,&sector_idx)){
					locate_byte(offset , &sec_loc);
					register_sector (inode_disk,sector_idx, sec_loc);
					bc_write(sector_idx,zeroes,0,BLOCK_SECTOR_SIZE,0);
				}
				else goto error;
			}
		}
		// sector_ofs == 0 이면 최초로 접근하는 sector이므로 block_sector를 할당해주고
		// 해당 block을 0으로 초기화한다.
		else{
			// add new_sector on inode_disk.
			if(free_map_allocate(1,&sector_idx)){
				locate_byte(offset , &sec_loc);
				register_sector (inode_disk,sector_idx, sec_loc);
				bc_write(sector_idx,zeroes,0,BLOCK_SECTOR_SIZE,0);
			}
			else goto error;
		}
		size -= chunk_size;
		offset += chunk_size;
	}

	free(zeroes);
	return true;

	error:
		printf("extend length error\n");
	    free(zeroes);
		return false;

}

//inode를 해지해주면서 inode가 할당받았던 block_sector에 대하여
//반환해주는 함수.
static void free_inode_sectors (struct inode_disk* inode_disk){

	int i,j;
	block_sector_t* block_map1 = (block_sector_t*) malloc (BLOCK_SECTOR_SIZE);
	block_sector_t* block_map2 = (block_sector_t*) malloc (BLOCK_SECTOR_SIZE);

	// double indirect 방식으로 할당된 block 해지
	if(inode_disk->double_indirect_block_sector > 0){

		// 1차 블록맵을 buffer_cache로 부터 읽음.
		bc_read(inode_disk->double_indirect_block_sector, (void*) block_map1, 0,BLOCK_SECTOR_SIZE, 0);
		i=0;
		// 1차 블록과 2차 블록을 순회하며 할당받았던 block_sector를 해지해준다.
		while(block_map1[i] > 0) //block_map1[i] != 0 이면 해당 블록 존재..
		{
			bc_read(block_map1[i], (void*) block_map2, 0,BLOCK_SECTOR_SIZE, 0);

			j=0;
			while(block_map2[j]>0)  //block_map1[i] != 0 이면 해당 블록 존재..
			{
				//버퍼캐시가 나중에 플러시되어 dangling point가 생길것을
				//방지하기 위해..
				struct buffer_head* tmp_cache = bc_lookup(block_map2[j]);
				if(tmp_cache != SECTOR_ERROR)		   bc_flush_entry(tmp_cache);
				free_map_release (block_map2[j],1);
				j++;
			}
			// 1차 index_block들도 해지해준다.
			struct buffer_head* tmp_cache = bc_lookup(block_map1[i]);
			if(tmp_cache != SECTOR_ERROR)		   bc_flush_entry(tmp_cache);
			free_map_release(block_map1[i],1);
			i++;
		}
		// double_indirect_block_sector도 해지해준다.
		struct buffer_head* tmp_cache = bc_lookup(inode_disk->double_indirect_block_sector);
		if(tmp_cache != NULL)		bc_flush_entry(tmp_cache);
		free_map_release(inode_disk->double_indirect_block_sector,1);
		free(block_map2);
	}

	// indriect 방식으로 할당된 block 해지
	if(inode_disk->indirect_block_sector > 0){

		bc_read(inode_disk->indirect_block_sector, (void*) block_map1, 0, BLOCK_SECTOR_SIZE, 0);
		i = 0;
		while (block_map1[i] > 0) //block_map1[i] != 0 이면 해당 블록 존재..
		{
			struct buffer_head* tmp_cache = bc_lookup(block_map1[i]);
			if(tmp_cache != SECTOR_ERROR)		   bc_flush_entry(tmp_cache);
			free_map_release(block_map1[i], 1);
			i++;
		}
		struct buffer_head* tmp_cache = bc_lookup(inode_disk->indirect_block_sector);
		if(tmp_cache != SECTOR_ERROR)		bc_flush_entry(tmp_cache);
		free_map_release(inode_disk->indirect_block_sector,1);
		free(block_map1);
	}

	//direct_방식의 sector들을 해지해준다.
	i=0;
	while(inode_disk->direct_map_table[i]>0){ //block_map1[i] != 0 이면 해당 블록 존재..
		struct buffer_head* tmp_cache = bc_lookup(inode_disk->direct_map_table[i]);
		if(tmp_cache != SECTOR_ERROR)		   bc_flush_entry(tmp_cache);
		free_map_release(inode_disk->direct_map_table[i],1);
		i++;
	}

}

/* Return true if inode is directory */
bool inode_is_dir(struct inode* inode){

	bool result;
	/*get on-disk inode first*/
	struct inode_disk* disk_inode = (struct inode_disk*) malloc(BLOCK_SECTOR_SIZE);
	get_disk_inode(inode, disk_inode);
	/*check if inode is directory*/
	if(disk_inode->is_dir == 1)
		result = true;
	else
		result = false;

	return result;
}

