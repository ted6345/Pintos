#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

/* lru_list : list of struct page that manages physical frame
 because lru_list is shared global variable,
 mutual exclusion is necessary.
 lru_list_lock is acquired and released when accessing lru_list
 lru_clock indicates one of element in lru_list
 and it is used as the clock of lru algorithm*/
static struct list lru_list;
static struct lock lru_list_lock;
static struct list_elem* lru_clock;
extern struct lock LOCK;
static struct list_elem* get_next_lru_clock(void);

/* Initialize lru_list(called at init_thread)*/
void lru_list_init(void){
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL; //set NULL at first
}

/* Push back list_elem(lru) to lru_list */
void add_page_to_lru_list(struct page* page){
	lock_acquire(&lru_list_lock);
	list_push_back(&lru_list, &page->lru);
	lock_release(&lru_list_lock);
}

/* Remove list_elem(lru) from lru_list */
void del_page_from_lru_list(struct page* page){

	if(lru_clock == &page->lru) 
		//lru_clock should indicate next elem
		lru_clock = list_remove(&page->lru);
	else
		list_remove(&page->lru);
}

/* Allocate physical frame.
  Set struct page field properly*/
struct page* alloc_page(enum palloc_flags flags){

	/*Allocate physical frame*/
	void* kaddr = palloc_get_page(flags);

	/*If physical memory is allocated full*/
	while(kaddr == NULL){
		/*swapping occurs*/
		kaddr = try_to_free_pages(flags);
	}

	/*Create page and initialize*/
	struct page* page = (struct page*)malloc(sizeof(struct page));
	if(page == NULL){
		palloc_free_page(kaddr);
		return NULL;
	}
	page->kaddr = kaddr;
	page->thread = thread_current();

	/*Insert to lru_list*/
	add_page_to_lru_list(page);

	return page;
}

/* Search page from lru_list which has kaddr field
  and free page if found*/
void free_page(void *kaddr){
	lock_acquire(&lru_list_lock);
	struct list_elem* ptr = list_begin(&lru_list);
	while(ptr != list_end(&lru_list)){
		struct page* page = list_entry(ptr, struct page, lru);
		if(page->kaddr == kaddr){
			/*If page has kaddr field*/
			__free_page(page);
			break ;
		}
		ptr = list_next(ptr);
	}
	lock_release(&lru_list_lock);
}

/* Actual free page occurs here*/
void __free_page(struct page* page){

	/*Remove from lru_list(lock is already held)*/
	del_page_from_lru_list(page);
	/*Free physical frame and its page*/
	palloc_free_page(page->kaddr);
	/*Free struct page*/
	free(page);
}

/* In general, return next lru_clock.
 If next lru_clock is end of lru_list, return NULL*/
static struct list_elem* get_next_lru_clock(void){

	if(list_next(lru_clock) == list_end(&lru_list)){
		return NULL;
	}
	else{
		return list_next(lru_clock);
	}
}

/* When physical memory is full and process needs more memory*/
void* try_to_free_pages(enum palloc_flags flags){

	lock_acquire(&lru_list_lock);

	/*Error check*/
	if(list_empty(&lru_list)){
		exit(-1);
	}

	/*If lru_clock is NULL(not setted or end of list)*/
	if(lru_clock == NULL){
		lru_clock = list_begin(&lru_list);
	}

	while(lru_clock) {
		struct page* page = list_entry(lru_clock, struct page, lru);
		struct thread* t = page->thread;
		if(page->vme->pinned != true){ //Do not swap out if pinned is true
			/*Get accessed bit from pagedir*/
			if(pagedir_is_accessed(t->pagedir, page->vme->vaddr)){
				/*If accessed bit is 1, reset to 0*/
				pagedir_set_accessed(t->pagedir, page->vme->vaddr,false);
			}
			else {  /*If accessed bit is 0, victim!*/
				if(pagedir_is_dirty(t->pagedir, page->vme->vaddr)
				 || page->vme->type == VM_ANON){ 
					if(page->vme->type == VM_FILE){
						/*Dirty bit is 1(Used)
						save file to disk that is dirty*/
						lock_acquire(&LOCK);
						file_write_at(page->vme->file,
							page->kaddr,
							page->vme->read_bytes,
							page->vme->offset);
						lock_release(&LOCK);
					} else {
						/*VM_BIN : change type to VM_ANON*/
						page->vme->type = VM_ANON;
						/* swap slot will be used for swap in*/
						page->vme->swap_slot = swap_out(page->kaddr);
					}
				}
				/*Free data (physical frame is swapped out)*/
				page->vme->is_loaded = false;
				pagedir_clear_page(t->pagedir, page->vme->vaddr); //clear pagedir
				__free_page(page);
				break;
			}
		}
		lru_clock = get_next_lru_clock();
	}
	lock_release(&lru_list_lock);

	/*return physical address that is allocated after swap out*/
	return palloc_get_page(flags);
}
