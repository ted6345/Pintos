#include "vm/page.h"
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "userprog/syscall.h"


extern struct lock LOCK;
static unsigned vm_hash_func(const struct hash_elem *e, void *aux);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b,
		void *aux);
static void vm_destroy_func(struct hash_elem *e, void *aux);

//initialize hash-table
//thread의 hash table을 초기화를 하기 위해 hash_init 라이브러리를 사용함.
void vm_init(struct hash* vm) {

	hash_init(vm, &vm_hash_func, &vm_less_func, (void*) NULL);

}
//hash_init을 통해 hash를 초기화하기 위해서는 hash_func와 vm_less_func 두 함수가 필요한데
//hash_func은 hash_elem이 가르치는 vm_entry를 hash_int 함수를 통해서 반환시키는 함수.
//vm_less_func은 두개의 hash_elem을 받아 hash_elem을 갖고잇는 2개의 vm_entry의 논리 주소를 비교하여
//첫번째 vm_entry의 논리주소가 작으면 true 아니면 false를 반환하는 함수이다.

//hash_func for hash-table
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED) {

	//hash_entry를 통해 vm_entry를 불러옴.
	//vm_entry의 vaddr을 인자로 hash_int를 호출화 반환값을 반환해준다.
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	return hash_int((int) vme->vaddr);

}

//less_func for hash-table
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b,
		void *aux UNUSED) {

	// 2개의 vm_entry를 각각 불러낸후 vaddr 값을 비교 후 반환한다.
	struct vm_entry *vme_a = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *vme_b = hash_entry(b, struct vm_entry, elem);

	if (vme_a->vaddr < vme_b->vaddr)
		return true;
	else
		return false;

}

//destroy hash-table
void vm_destroy(struct hash* vm) {

	hash_destroy(vm, &vm_destroy_func);
	//hash_destrory라는 라이브러리를 사용. vm_destroy_func이 필요한데 아래에 정의.
}

//destroy_func for hash_destroy
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED) {

	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	//hash_elem을 이용해 vm_entry를 불러온 후, vme를 성공적으로 호출이 성공했다면
	//vm_entry가 physical memory에 올라와있다면, 올라온 해당페이지를
	//pagedir_get_page함수와 vaddr를 이용해 검색한후 page공간과 pagedir를 정리해준다.
	if (vme != NULL) { 								// handling exception
		if (vme->is_loaded == true) {	// if it allocated in Physical Memory,
			palloc_free_page(
					pagedir_get_page(thread_current()->pagedir, vme->vaddr));
			pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
		}
		//physcial memory에 올라온 것과 상관없이 vm_entry의 할당된 메모리를 해제해준다.
		free(vme);
	}
}

//find_vme based on vaddr
struct vm_entry* find_vme(void *vaddr) {

	void *pgnum = pg_round_down(vaddr);
	struct hash_elem* e;
	struct vm_entry temp;
	temp.vaddr = pgnum;
	//e = temp 라는 vm_entry 를 바탕으로 hash_elem을 찾는다.
	e = hash_find(&thread_current()->vm, &temp.elem);
	//hash_entry 라이브러리를 사용ㅎ여 vm_entry를 반환한다.
	return hash_entry(e, struct vm_entry, elem);
}

//insert vme to hash-table
bool insert_vme(struct hash *vm, struct vm_entry* vme) {

	//has_insert 라이브러리를 사용해 vm_entry 삽입.
	if (hash_insert(vm, &vme->elem) == NULL)
		return true;
	else
		return false;
}

//delete vme from hash_table
bool delete_vme(struct hash *vm, struct vm_entry* vme) {

	//hash_delete 라이브러리를 사용하여 vm_entry 삭제.
	struct hash_elem* e = hash_delete(vm, &vme->elem);
	if (e != NULL)
		return true;
	else
		return false;
}

//load file from disk to physical memory.
bool load_file(void* kaddr, struct vm_entry *vme) {

	//file_read_at을 이용해 디스크로부터 physcial memory에 memory를 올린다.
	int read_byte = file_read_at(vme->file, kaddr, vme->read_bytes,
			vme->offset);

	if (read_byte != (int) vme->read_bytes) {
		return false;
	}
	memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);

	return true;

}
