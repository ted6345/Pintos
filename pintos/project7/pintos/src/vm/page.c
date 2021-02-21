#include "vm/page.h"
#include <stdbool.h>
#include <string.h>
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

extern struct lock LOCK;

static unsigned vm_hash_func(const struct hash_elem *e, void* aux UNUSED);
static bool vm_less_func(const struct hash_elem *a,	const struct hash_elem *b, void* aux UNUSED);
static void vm_destroy_func(struct hash_elem *e, void* aux UNUSED);

/*Initialize vm hash table*/
void vm_init(struct hash *vm){

	hash_init(vm, vm_hash_func, vm_less_func, (void *)NULL);
}

/*Eliminate vm hash table*/
void vm_destroy(struct hash *vm){
	
	hash_destroy(vm, vm_destroy_func);
}

/*Using vm_entry's vaddr value to key of hash function*/
static unsigned vm_hash_func(const struct hash_elem *e,
	   	void *aux UNUSED){	
	
	struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
	return hash_int((int)vme->vaddr);
}

/*Compare two vm_entries' vaddr value*/
static bool vm_less_func(const struct hash_elem *a,
	   	const struct hash_elem *b, void *aux UNUSED){
	
	struct vm_entry *vme_a = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *vme_b = hash_entry(b, struct vm_entry, elem);
	if(vme_a->vaddr < vme_b->vaddr)
		return true;
	else
		return false;
}

/*Remove vm_entry and what it indicates*/
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED){
	struct thread * cur = thread_current();
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	
	if(vme != NULL){
		if(vme->is_loaded == true){
			/*free physical frame and page table entry*/
			palloc_free_page(pagedir_get_page(cur->pagedir, vme->vaddr));
			pagedir_clear_page(cur->pagedir, vme->vaddr);
		}
		/*free vm_entry*/
		free(vme);
	}
}

/*Find vm_entry that has the page including vaddr value
 if there isn't those vm_entry ,return NULL*/
struct vm_entry* find_vme(void *vaddr){
	
	void *page = pg_round_down(vaddr);
	struct vm_entry temp;
	temp.vaddr = page;
	struct hash_elem* e;
	e = hash_find(&thread_current()->vm, &temp.elem);

	if(e == NULL)
		return NULL;
	else
		return hash_entry(e, struct vm_entry, elem);
}

/*Insert vm_entry to hash table,
  return false if hash table already has that vm_entry*/
bool insert_vme(struct hash *vm, struct vm_entry* vme){

	//hash_insert returns NULL if new element is inserted
	if(hash_insert(vm, &vme->elem) == NULL)
		return true;
	else
		return false;
	
}

/*Delete vm_entry from hash table
  return false if hash table doesn't have that vm_entry*/
bool delete_vme(struct hash *vm, struct vm_entry* vme){

	//hash_delete returns NULL if no element existed
	struct hash_elem* e = hash_delete(vm, &vme->elem);
	if(e != NULL)
		return true;
	else
		return false;
}

/* load 1 page from vme->file, vme->offset 
 and install page to kaddr */
bool load_file(void *kaddr, struct vm_entry *vme){

	/* set up lock when accessing shared file */
	lock_acquire(&LOCK);
	if(file_read_at(vme->file, kaddr, vme->read_bytes ,vme->offset) 
			!= (int)vme->read_bytes){
		lock_release(&LOCK);
		free_page(kaddr); //change
		return false;
	}
	lock_release(&LOCK);
	/* Fill in rest of memory of page by zero*/
	memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);

	return true;
}

