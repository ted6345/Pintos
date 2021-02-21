#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <list.h>
#include <stdio.h>
#include <debug.h>
#define STACK_HEURISTIC 32

enum vm_entry_type{
	VM_BIN, //load data from binary file
	VM_FILE, //load data from mapped file
	VM_ANON //load data from swap space
};

/* Represent virtual memory entry, matching each page.
   Only be filled and loaded when system demands paging */
struct vm_entry{
	uint8_t type; //3 types : VM_BIN, VM_FILE, VM_ANON
	void *vaddr; //virtual address
	bool writable; //if writable at this page
	bool is_loaded; //whether physical frame is loaded
	bool pinned; //prevent for swapping
	
	struct file* file; //indicate mapped file
	struct list_elem mmap_elem; //for VM_FILE
	size_t offset; //offset of file
	size_t read_bytes; //readed(used) bytes of page
	size_t zero_bytes; //initialize 0 the rest of page

	size_t swap_slot; //for VM_ANON(later)

	struct hash_elem elem; //element of hash table
};

/* Represent memory-mapping file data */
struct mmap_file{
	int mapid; //map id for thread mapping file
	struct file* file;
	struct list_elem elem;
	struct list vme_list;
};

/* Represent a page(frame) of physical memory */
struct page{
	void *kaddr; //physical address
	struct vm_entry* vme; //indicating this frame
	struct thread* thread; //for access to pagedir
	struct list_elem lru; //element of lru_list
};

void vm_init(struct hash* vm);
void vm_destroy(struct hash* vm);
struct vm_entry* find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry* vme);
bool delete_vme(struct hash *vm, struct vm_entry* vme);
bool load_file(void *kaddr, struct vm_entry *vme);

#endif
