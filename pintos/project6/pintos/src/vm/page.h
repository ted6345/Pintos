#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdio.h>
#include <debug.h>
#include <stdbool.h>
#include <string.h>

void vm_init(struct hash* vm);
void vm_destroy(struct hash* vm);
struct vm_entry* find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry* vme);
bool delete_vme(struct hash *vm, struct vm_entry* vme);
bool load_file(void* kaddr,struct vm_entry *vme);
bool handle_mm_fault(struct vm_entry *vme);


//define vm_entry_type
enum vm_entry_type{
	VM_BIN,
	VM_FILE,
	VM_ANON
};

//Structure for vm_entry
struct vm_entry{
	uint8_t type;  //VM_BIN,VM_FILE,VM_ANON
	void *vaddr;   //Virtual_address
	bool writable; //Write_access permission
	bool is_loaded;//is_loaded.
	bool pinned;   //prevent for swapping
	struct file* file; //file that mapping with vm_entry
	unsigned int read_bytes; // read_bytes
	unsigned int zero_bytes; // bytes that unused
	unsigned int swap_slot;
	unsigned int offset;     // offset
	struct list_elem mmap_elem; //mmap_elem
	struct hash_elem elem;      //hash_elem
};

//Structure for mmap_file
struct mmap_file{
	int map_id;
	struct file* file;
	struct list_elem elem; //elem for thread's mmap_list.
	struct list vme_list;
};

#endif
