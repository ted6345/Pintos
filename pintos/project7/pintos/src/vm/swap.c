#include "vm/swap.h"
#include "threads/vaddr.h"

#define SWAP_FREE 0
#define SWAP_USED 1
#define SECTOR_PER_PAGE ((PGSIZE)/(BLOCK_SECTOR_SIZE))

static struct lock swap_lock;
static struct bitmap* swap_map;
static struct block* swap_block;

/*Initialize Swap space*/
void swap_init(void){
	swap_block = block_get_role(BLOCK_SWAP);
	swap_map = bitmap_create(block_size(swap_block)/SECTOR_PER_PAGE);
	bitmap_set_all(swap_map, false); //make it 0 first
	lock_init(&swap_lock);	
}

/*Swap in : from Disk to Memory*/
void swap_in(size_t used_index, void* kaddr){
	int i;
	lock_acquire(&swap_lock);
	/*Check if bitmap is available*/
	if(bitmap_test(swap_map, used_index) != SWAP_USED)
		exit(-1);
	/*Read from Disk to physical memory*/
	for(i=0; i < SECTOR_PER_PAGE; i++){
		block_read(swap_block,
		used_index * SECTOR_PER_PAGE + i,
		kaddr + BLOCK_SECTOR_SIZE * i);
	}
	/*Make swap slot to 0(SWAP_FREE)*/
	bitmap_flip(swap_map, used_index); 
	lock_release(&swap_lock);
}

/*Swap out : from Momory to Disk*/
size_t swap_out(void *kaddr){
	int i;
	lock_acquire(&swap_lock);
	/*Find first SWAP_FREE bitmap index*/
	size_t free_index = bitmap_scan(swap_map,0,1,SWAP_FREE);
	/*Write from physical memory to Disk*/
	for(i=0; i < SECTOR_PER_PAGE; i++){
		block_write(swap_block,
		free_index * SECTOR_PER_PAGE + i,
		kaddr + i * BLOCK_SECTOR_SIZE);
	}
	/*Make swap slot to 1(SWAP_USED)*/
	bitmap_flip(swap_map, free_index);
	lock_release(&swap_lock);

	return free_index;
}
