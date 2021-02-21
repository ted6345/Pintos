#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"     //void thread_exit(void)
/*added header*/
#include <devices/shutdown.h>   //void shutdown_power_off(void)
#include <filesys/filesys.h>    //bool filesys_create(), filesys_remove()
#include <filesys/file.h>
#include "userprog/process.h"
#include <devices/input.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "filesys/inode.h"
#include "vm/page.h"

extern struct lock LOCK;

static void syscall_handler(struct intr_frame *);

void syscall_init(void) {
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
	int syscall_num = *(int *) f->esp;
	int arg[3]; //max arg of syscall : 3

	/*check if stack pointer is in User Space*/
	check_address(f->esp, f->esp);
	/*Matching system calls by syscall_num*/
	switch (syscall_num) {
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		get_argument(f->esp, arg, 1);
		exit((int) arg[0]);
		break;

	case SYS_EXEC:
		get_argument(f->esp, arg, 1);
		check_valid_string((void *) arg[0], f->esp);
		f->eax = exec((const char *) arg[0]);
		break;

	case SYS_WAIT:
		get_argument(f->esp, arg, 1);
		f->eax = wait((tid_t) arg[0]);
		break;

	case SYS_CREATE:
		get_argument(f->esp, arg, 2);
		check_valid_string((void *) arg[0], f->esp);
		f->eax = create((const char *) arg[0], (unsigned) arg[1]);
		break;

	case SYS_REMOVE:
		get_argument(f->esp, arg, 1);
		check_valid_string((void *) arg[0], f->esp);
		f->eax = remove((const char *) arg[0]);
		break;

	case SYS_OPEN:
		get_argument(f->esp, arg, 1);
		check_valid_string((void *) arg[0], f->esp);
		f->eax = open((const char *) arg[0]);
		break;

	case SYS_FILESIZE:
		get_argument(f->esp, arg, 1);
		f->eax = filesize((int) arg[0]);
		break;

	case SYS_READ:
		get_argument(f->esp, arg, 3);
		check_valid_buffer((void *) arg[1], (unsigned) arg[2], f->esp, false);
		f->eax = read((int) arg[0], (void *) arg[1], (unsigned) arg[2]);
		break;

	case SYS_WRITE:
		get_argument(f->esp, arg, 3);
		check_valid_buffer((void *) arg[1], (unsigned) arg[2], f->esp, true);
		f->eax = write((int) arg[0], (void *) arg[1], (unsigned) arg[2]);
		break;

	case SYS_SEEK:
		get_argument(f->esp, arg, 2);
		seek((int) arg[0], (unsigned) arg[1]);
		break;

	case SYS_TELL:
		get_argument(f->esp, arg, 1);
		f->eax = tell((int) arg[0]);
		break;

	case SYS_CLOSE:
		get_argument(f->esp, arg, 1);
		close((int) arg[0]);
		break;

	case SYS_MMAP: /* Map a file into memory. */
		get_argument(f->esp, arg, 2);
		f->eax = mmap((int) arg[0], (void*) arg[1]);
		break;

	case SYS_MUNMAP: /* Remove a memory mapping. */
		get_argument(f->esp, arg, 1);
		munmap((int) arg[0]);
		break;

	}
}

//check if is there vme , handle_mm_fault..
//if not, error : exit(-1)
struct vm_entry* check_address(void *addr,UNUSED void* esp) {

	/*User Space : 0xc0000000 ~ 0x8048000*/
	if (addr < (void *) 0x08048000 || addr >= (void *) 0xc0000000)
		exit(-1);
	struct vm_entry* vme = find_vme(addr);
	if (vme) {
		//if vme->is_loaded==false , then handle_mm_fault.
		if (vme->is_loaded != true){
			if (!handle_mm_fault(vme)) {
				exit(-1);
			}
		}
		return vme;
	}
	// if vme isn't existed, then it's error.
	else
		exit(-1);
}

// check if buffer is valid.
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write) {

	unsigned i = 0;
	struct vm_entry* vme;
	while (1) {
		//check_address of buffer.
		vme = check_address((void*) (buffer + i), esp);

		//check_if_write access is Ok.
		if (to_write == true && vme->writable == false)
		{
			return -1;
		}
		//check_buffer iterate on PGSIZE.
		//if left_size of buffer < PGSIZE then break.
		if (size > PGSIZE) {
			i += PGSIZE;
			size -= PGSIZE;
		} else
			break;
	}
}

// check if string is valid.
void check_valid_string(const void* str, void* esp) {

	check_address((void *) str, esp);
	//str값을 1씩 올리면서 check_address를 해준다.
	while (*(char*) str != 0) {
		str++;
		check_address((void *) str, esp);
	}
}
/*save arguments to Kernel from User Stack*/
void get_argument(void *esp, int *arg, int count) {
	int i;
	esp = esp + 4;
	for (i = 0; i < count; i++) {
		if (check_address(esp, esp) == NULL)
			exit(-1);
		arg[i] = *(int *) esp;
		esp = esp + 4;
	}
}

/*Quit Pintos*/
void halt(void) {
	shutdown_power_off();
}

/*Exit running Process*/
void exit(int status) {
	struct thread *t = thread_current();
	t->exit_status = status;  //save current exit_status
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

/*Create file*/
bool create(const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

/*Remove file*/
bool remove(const char *file) {
	return filesys_remove(file);
}

/*Create child process and Execute it (program name : cmd_line)
 if it is created and loaded successfully,
 return child process's pid*/
tid_t exec(const char *cmd_line) {

	tid_t child_pid = process_execute(cmd_line); //create child process and execute
	struct thread *t = get_child_process(child_pid);

	//for filesys-base-syn-write/read.
	thread_sleep(1);
	sema_down(&t->load_sema); //wait for child process(load)

	if (!t->is_load || t == NULL) {
		return -1; //load fail
	}
	return child_pid; //load success

}

/*Wait(sleep state) until child process exits */
int wait(tid_t tid) {
	//for filesys-base-syn-write/read.
	thread_sleep(1);
	return process_wait(tid);
}

/*Open the file with filename and reset process's file descriptor,
 if there's no such file, return -1(Error) */
int open(const char *file_path) {
	struct file * file;
	file = filesys_open(file_path);
	if (file == NULL)
		return -1;
	else
		return process_add_file(file);
}

/*Return opend file(fd)'s size,
 if there's no such file opend return -1*/
int filesize(int fd) {
	struct file * file;
	file = process_get_file(fd);
	if (file == NULL)
		return -1;
	else
		return (int) file_length(file);
}

/*Read data(buffer) from opend file that has file descriptor value fd*/
int read(int fd, void* buffer, unsigned size) {
	int read_size;
	lock_acquire(&LOCK); //Protect concurrent access to file

	struct file *f = process_get_file(fd);
	if (fd == 0) { //STDIN
		unsigned int i = 0;
		for (i = 0; i < size; i++)
			((char *) buffer)[i] = input_getc();
		read_size = i;
	} else
		read_size = file_read(f, buffer, (off_t) size);
	lock_release(&LOCK);
	return read_size;
}

/*Write data(buffer) to opend file that has file descriptor value fd*/
int write(int fd, void *buffer, unsigned size) {
	int write_size;
	lock_acquire(&LOCK); //Protect concurrent access to file

	struct file *f = process_get_file(fd);

	if (fd == 1) { //STDOUT
		putbuf((const char *) buffer, (size_t) size);
		write_size = size;
	} else
		write_size = file_write(f, buffer, (off_t) size);

	lock_release(&LOCK);
	return write_size;
}

/*Move offset of opend file that has file descriptor value fd*/
void seek(int fd, unsigned position) {
	struct file *f = process_get_file(fd);
	if (f != NULL)
		file_seek(f, position);
}

/*Return offset of opend file that has file descriptor value fd*/
unsigned tell(int fd) {
	struct file *f = process_get_file(fd);
	return file_tell(f);
}

/*Close opend file that has file descriptor value fd*/
void close(int fd) {
	process_close_file(fd);
}

/* Map a file into memory. */
int mmap(int fd, void* addr) {

	/*User Space : 0xc0000000 ~ 0x8048000*/
	if (addr < (void *) 0x08048000 || addr >= (void *) 0xc0000000)
		return -1;

	//execption for addr misalign
	if ((int) addr % PGSIZE != 0)
		return -1;

	struct thread* t = thread_current();
	struct list_elem* e;
	struct file* tmp_file = process_get_file(fd);

	if (tmp_file == NULL) //execption handling
		return -1;

	struct mmap_file * mmap_file = (struct mmap_file*) malloc(
			sizeof(struct mmap_file));
	struct file *fp = file_reopen(tmp_file); //reopen tmp_file.

	if (fp == NULL) //execption handling
		return -1;

	//mmap_file의 필드 초기화.
	mmap_file->map_id = t->map_id; // thread에서 map id를 할당받은후 thread의 map id 최신화.
	t->map_id++;
	list_init(&mmap_file->vme_list); // mmap_file의 vme_list 초기화.
	int32_t ofs = 0;				// ofs =0;
	uint32_t read_bytes = file_length(fp);

	//mmap_file의 vm_entry를 생성.
	while (read_bytes > 0) {

		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;
		struct vm_entry* vme = (struct vm_entry*) malloc(
				sizeof(struct vm_entry));

		//vm_entry 필드 초기화.
		vme->type = VM_FILE;
		vme->vaddr = pg_round_down(addr);
		vme->is_loaded = false;   //is_loaded.
		vme->writable = true; //Write_access permission
		vme->file = fp;
		vme->read_bytes = page_read_bytes;
		vme->zero_bytes = page_zero_bytes;
		vme->offset = ofs;

		//process의 hash-table에 vm_entry 삽입
		if (!insert_vme(&t->vm, vme)) {
			free(vme);
			return -1;
		}
		//mmap_file의 vme-list에 mmap_file 삽입.
		list_push_back(&mmap_file->vme_list, &vme->mmap_elem);

		read_bytes -= page_read_bytes;
		ofs += page_read_bytes;
		addr += PGSIZE;
	}

	//process의 mmap_list에 mmap_file 추가.
	list_push_back(&t->mmap_list, &mmap_file->elem);

	//mmap_file의 id 반환.
	return mmap_file->map_id;
}

/* Remove a memory mapping. */
void munmap(int mapid) {

	struct list_elem *e;
	struct thread* t = thread_current();

	//process의 mmap_list를 순회하며.
	for (e = list_begin(&t->mmap_list); e != list_end(&t->mmap_list); e =
			list_next(e)) {

		//mmap_file을 mmap_elem을 통해 호출한후.
		struct mmap_file *m = list_entry(e, struct mmap_file, elem);

		//mmap_file이 지우기로 한 mapid이거나 mapid가 CLOSE_ALL인 경우
		if (m->map_id == mapid || mapid == CLOSE_ALL) {

			//mmap_file을 삭제 해주는 do_munmap함수를 호출한다.
			do_munmap(m);
			e = list_remove(e);
			e = list_prev(e);
			//mmap_file 메모리 해체.
			free(m);
		}


	}

}

// remove all vm_enties of mmap
void do_munmap(struct mmap_file* mmap_file) {

	struct list_elem *e = list_begin(&mmap_file->vme_list);
	while (e != list_end(&mmap_file->vme_list)) { //mmap_file의 vme_list에 있는 모든 vm_entry를 순회.

		struct vm_entry *vme = list_entry(e, struct vm_entry, mmap_elem);

		if (vme->is_loaded) { // vme physical memory에 올라와있다면..

			//vme->vaddr의 page가 수정되었다면.. file_write_at함수로
			//디스크에 최신화를 해주어야한다.
			if (pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)) {
				file_write_at(vme->file, vme->vaddr, vme->read_bytes,
						vme->offset);
			}
			//physcial memory에 올라와 있는 page를 해제해준다. pagdir를 clear해준다.
			palloc_free_page(
					pagedir_get_page(thread_current()->pagedir, vme->vaddr));
			pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
		}

		//list_remove의 return 값은 list_next(e)이기 때문에 따로 list_next를 해줄 필요는 없다.
		e = list_remove(e);

		//현재 프로세스의 hash-table에서 vm_entry를 삭제해주고 vm_entry의 동적할당된 메모리를 해제해준다.
		delete_vme(&thread_current()->vm, vme);
		free(vme);
	}

}
