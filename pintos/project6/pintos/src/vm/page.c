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
//thread�� hash table�� �ʱ�ȭ�� �ϱ� ���� hash_init ���̺귯���� �����.
void vm_init(struct hash* vm) {

	hash_init(vm, &vm_hash_func, &vm_less_func, (void*) NULL);

}
//hash_init�� ���� hash�� �ʱ�ȭ�ϱ� ���ؼ��� hash_func�� vm_less_func �� �Լ��� �ʿ��ѵ�
//hash_func�� hash_elem�� ����ġ�� vm_entry�� hash_int �Լ��� ���ؼ� ��ȯ��Ű�� �Լ�.
//vm_less_func�� �ΰ��� hash_elem�� �޾� hash_elem�� �����մ� 2���� vm_entry�� �� �ּҸ� ���Ͽ�
//ù��° vm_entry�� ���ּҰ� ������ true �ƴϸ� false�� ��ȯ�ϴ� �Լ��̴�.

//hash_func for hash-table
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED) {

	//hash_entry�� ���� vm_entry�� �ҷ���.
	//vm_entry�� vaddr�� ���ڷ� hash_int�� ȣ��ȭ ��ȯ���� ��ȯ���ش�.
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	return hash_int((int) vme->vaddr);

}

//less_func for hash-table
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b,
		void *aux UNUSED) {

	// 2���� vm_entry�� ���� �ҷ����� vaddr ���� �� �� ��ȯ�Ѵ�.
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
	//hash_destrory��� ���̺귯���� ���. vm_destroy_func�� �ʿ��ѵ� �Ʒ��� ����.
}

//destroy_func for hash_destroy
static void vm_destroy_func(struct hash_elem *e, void *aux UNUSED) {

	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
	//hash_elem�� �̿��� vm_entry�� �ҷ��� ��, vme�� ���������� ȣ���� �����ߴٸ�
	//vm_entry�� physical memory�� �ö���ִٸ�, �ö�� �ش���������
	//pagedir_get_page�Լ��� vaddr�� �̿��� �˻����� page������ pagedir�� �������ش�.
	if (vme != NULL) { 								// handling exception
		if (vme->is_loaded == true) {	// if it allocated in Physical Memory,
			palloc_free_page(
					pagedir_get_page(thread_current()->pagedir, vme->vaddr));
			pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
		}
		//physcial memory�� �ö�� �Ͱ� ������� vm_entry�� �Ҵ�� �޸𸮸� �������ش�.
		free(vme);
	}
}

//find_vme based on vaddr
struct vm_entry* find_vme(void *vaddr) {

	void *pgnum = pg_round_down(vaddr);
	struct hash_elem* e;
	struct vm_entry temp;
	temp.vaddr = pgnum;
	//e = temp ��� vm_entry �� �������� hash_elem�� ã�´�.
	e = hash_find(&thread_current()->vm, &temp.elem);
	//hash_entry ���̺귯���� ��뤾�� vm_entry�� ��ȯ�Ѵ�.
	return hash_entry(e, struct vm_entry, elem);
}

//insert vme to hash-table
bool insert_vme(struct hash *vm, struct vm_entry* vme) {

	//has_insert ���̺귯���� ����� vm_entry ����.
	if (hash_insert(vm, &vme->elem) == NULL)
		return true;
	else
		return false;
}

//delete vme from hash_table
bool delete_vme(struct hash *vm, struct vm_entry* vme) {

	//hash_delete ���̺귯���� ����Ͽ� vm_entry ����.
	struct hash_elem* e = hash_delete(vm, &vme->elem);
	if (e != NULL)
		return true;
	else
		return false;
}

//load file from disk to physical memory.
bool load_file(void* kaddr, struct vm_entry *vme) {

	//file_read_at�� �̿��� ��ũ�κ��� physcial memory�� memory�� �ø���.
	int read_byte = file_read_at(vme->file, kaddr, vme->read_bytes,
			vme->offset);

	if (read_byte != (int) vme->read_bytes) {
		return false;
	}
	memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);

	return true;

}
