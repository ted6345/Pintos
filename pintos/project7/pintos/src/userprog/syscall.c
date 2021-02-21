#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"     //void thread_exit(void)
#include <devices/shutdown.h>   //void shutdown_power_off(void)
#include <filesys/filesys.h>    //bool filesys_create(), filesys_remove()
#include <filesys/file.h>
#include "userprog/process.h"
#include <devices/input.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/page.h"

extern struct lock LOCK;

static void syscall_handler (struct intr_frame *);
struct vm_entry* check_address(void *addr, void *esp UNUSED);
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write);
void check_valid_string(const void* str, void* esp);
void unpin_ptr(void *vaddr);
void unpin_string(void *str);
void unpin_buffer(void *buffer, unsigned size);
void get_argument(void *esp, int *arg, int count);
void do_munmap(struct mmap_file* mmap_file);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{

	int syscall_num = *(int *)f->esp;
	int arg[3]; //max arg of syscall : 3

	/*check if stack pointer is in User Space*/
	check_address(f->esp, f->esp);

	/*Matching system calls by syscall_num*/
	switch(syscall_num){
		case SYS_HALT:
			halt();
			break;

		case SYS_EXIT:
			get_argument(f->esp, arg, 1);
			exit((int)arg[0]);
			break;

		case SYS_EXEC:
			get_argument(f->esp, arg, 1);
			check_valid_string((void *)arg[0], f->esp);
			f->eax = exec((const char *)arg[0]);
			unpin_string((void *)arg[0]);
			break;

		case SYS_WAIT:
			get_argument(f->esp, arg, 1);
			f->eax = wait((tid_t)arg[0]);
			break;

		case SYS_CREATE:
			get_argument(f->esp, arg, 2);
			check_valid_string((void *)arg[0], f->esp);
			f->eax = create((const char *)arg[0], (unsigned)arg[1]);
			unpin_string((void *)arg[0]);
			break;

		case SYS_REMOVE:
			get_argument(f->esp, arg, 1);
			check_valid_string((void *)arg[0], f->esp);
			f->eax = remove((const char *)arg[0]);
			unpin_string((void *)arg[0]);
			break;

		case SYS_OPEN:
			get_argument(f->esp, arg, 1);
			check_valid_string((void *)arg[0], f->esp);
			f->eax = open((const char *)arg[0]);
			unpin_string((void *)arg[0]);
			break;

		case SYS_FILESIZE:
			get_argument(f->esp, arg, 1);
			f->eax = filesize((int)arg[0]);
			break;

		case SYS_READ:
			get_argument(f->esp, arg, 3);
			check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, true);
			f->eax = read((int)arg[0], (void *)arg[1], (unsigned)arg[2]);
			unpin_buffer((void *)arg[1], (unsigned)arg[2]);
			break;

		case SYS_WRITE:
			get_argument(f->esp, arg, 3);
			check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, false);
			f->eax = write((int)arg[0], (void *)arg[1], (unsigned)arg[2]);
			unpin_buffer((void *)arg[1], (unsigned)arg[2]);
			break;

		case SYS_SEEK:
			get_argument(f->esp, arg, 2);
			seek((int)arg[0],(unsigned)arg[1]);
			break;
		
		case SYS_TELL:
			get_argument(f->esp, arg, 1);
			f->eax = tell((int)arg[0]);
			break;

		case SYS_CLOSE:
			get_argument(f->esp, arg, 1);
			close((int)arg[0]);
			break;
		
		case SYS_MMAP:
			get_argument(f->esp, arg, 2);
			f->eax = mmap((int)arg[0], (void *)arg[1]);
			break;
		
		case SYS_MUNMAP:
			get_argument(f->esp, arg, 1);
			munmap(arg[0]);
			break;
	}

	unpin_ptr(f->esp);	
}

/* First, check if addr locates in User Space
   Second, search vm_entry including addr space
   and call handle_mm_fault to implement paging
   between virtual page and physical frame
 */
struct vm_entry* check_address(void *addr, void* esp UNUSED)
{
	/*User Space : 0xc0000000 ~ 0x8048000*/
	if(addr < (void *)0x08048000 || addr >= (void *)0xc0000000){
		exit(-1);
	}
	/*Check if addr is valid virtual address*/
	struct vm_entry* vme = find_vme(addr);
	if(vme != NULL){
		if(vme->is_loaded != true)
			if(!handle_mm_fault(vme)){
				exit(-1);
			}
		return vme;
	}
	/*Check if addr is in valid Stack space*/
	else if(addr >= esp - STACK_HEURISTIC){
		if(!expand_stack(addr)){
			exit(-1);
		}
		return find_vme(addr);
	}
}

/*save arguments to Kernel from User Stack*/
void get_argument(void *esp, int *arg, int count){
	int i;
	esp = esp + 4;
	for(i=0; i<count; i++){
		check_address(esp, esp);
		arg[i] = *(int *)esp;
		esp = esp + 4;
	}
}

/*Quit Pintos*/
void halt(void){
	shutdown_power_off();
}

/*Exit running Process*/
void exit(int status){
	struct thread *t = thread_current();
	t->exit_status = status;  //save current exit_status
	printf("%s: exit(%d)\n",t->name, status);
	thread_exit();
}

/*Create file*/
bool create(const char *file, unsigned initial_size){
	lock_acquire(&LOCK);
	bool success = filesys_create(file, initial_size);
	lock_release(&LOCK);
	return success;
}

/*Remove file*/
bool remove(const char *file){
	lock_acquire(&LOCK);
	bool success = filesys_remove(file);
	lock_release(&LOCK);
	return success;
}

/*Create child process and Execute it (program name : cmd_line)
 if it is created and loaded successfully,
 return child process's pid*/
tid_t exec(const char *cmd_line){
	tid_t child_pid;
	struct thread *t;
	child_pid = process_execute(cmd_line); //create child process and execute
	t = get_child_process(child_pid);
	sema_down(&t->load_sema); //wait for child process(load)
	if(!t->is_load){
		return -1; //load fail
	}
	else {
		return child_pid; //load success
	}
}

/*Wait(sleep state) until child process exits */
int wait(tid_t tid){
	return process_wait(tid);
}

/*Open the file with filename and reset process's file descriptor,
  if there's no such file, return -1(Error) */
int open(const char *file_path){
	struct file * file;
	lock_acquire(&LOCK);
	file = filesys_open(file_path);
	if(file  == NULL){
		lock_release(&LOCK);
		return -1;
	}
	else{
		int fd = process_add_file(file);
		lock_release(&LOCK);
		return fd;
	}
}

/*Return opend file(fd)'s size,
 if there's no such file opend return -1*/
int filesize(int fd){
	struct file * file;
	lock_acquire(&LOCK);
	file = process_get_file(fd);
	if(file == NULL){
		lock_release(&LOCK);
		return -1;
	}
	else{
		int size = (int)file_length(file);
		lock_release(&LOCK);
		return size;
	}
}

/*Read data(buffer) from opend file that has file descriptor value fd*/
int read (int fd, void *buffer, unsigned size){
	
	int read_size;
	lock_acquire(&LOCK); //Protect concurrent access to file

	struct file *f = process_get_file(fd);

	if(fd == 0){ //STDIN
		unsigned int i=0;
		for(i=0; i<size; i++)
			((char *)buffer)[i] = input_getc();
		read_size = i;
	}
	else
		read_size = file_read(f, buffer, (off_t)size);

	lock_release(&LOCK);
	return read_size;
}

/*Write data(buffer) to opend file that has file descriptor value fd*/
int write(int fd, const void *buffer, unsigned size){
	int write_size;
	lock_acquire(&LOCK); //Protect concurrent access to file

	struct file *f = process_get_file(fd);
	
   	if(fd == 1){ //STDOUT
		putbuf((const char *)buffer, (size_t)size);
		write_size = size;
	}
	else
		write_size = file_write(f, buffer, (off_t)size);

	lock_release(&LOCK);
	
	return write_size;
}

/*Move offset of opend file that has file descriptor value fd*/
void seek(int fd, unsigned position){
	lock_acquire(&LOCK);
	struct file *f = process_get_file(fd);
	if(f != NULL){
		file_seek(f, position);
		lock_release(&LOCK);
	}
	else
		lock_release(&LOCK);
}

/*Return offset of opend file that has file descriptor value fd*/
unsigned tell (int fd){
	lock_acquire(&LOCK);
	struct file *f = process_get_file(fd);
	if(f != NULL){
		lock_release(&LOCK);
		return -1;
	}
	unsigned offset = file_tell(f);
	lock_release(&LOCK);
	return offset;
}

/*Close opend file that has file descriptor value fd*/
void close(int fd){
	lock_acquire(&LOCK);
	process_close_file(fd);
	lock_release(&LOCK);
}

/*check if buffer is valid*/
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write){

	unsigned i = 0;
	struct vm_entry* vme;
	/*check elements of buffer*/
	while(i < size){
		vme = check_address((void *)(buffer + i), esp);
		/*if loaded segment is read-only and
		  something tries to write on this segment(like write system call)*/
		if(vme != NULL && to_write == true && vme->writable == false)
			exit(-1);
		i++;
	}
}

/*check if string is valid*/
void check_valid_string(const void* str, void* esp){
	
	check_address((void *)str, esp);
	/*check all elements of string*/
	while( *(char *)str != 0){
		str++;
		check_address((void *)str, esp);
	}
}
/* Unpin if there exist vm_entry which has vaddr */
void unpin_ptr(void *vaddr){

	struct vm_entry* vme = find_vme(vaddr);
	if(vme != NULL && vme->pinned == true)
		vme->pinned = false;
}

/* Unpin vm_entry of string elements */
void unpin_string(void *str){
	unpin_ptr(str);
	while( *(char *)str != 0){
		str++;
		unpin_ptr((void *)str);
	}
}

/* Unpin vm_entry of buffer */
void unpin_buffer(void *buffer, unsigned size){
	unsigned i = 0;
	while(1){
		unpin_ptr((void *)(buffer + i));
		/*Unpin each page*/
		if(size > PGSIZE){
			i += PGSIZE;
			size -= PGSIZE;
		} else
			break;
//		i++;
	}
}

/*Implement Memory mapping between file and virtual address
 return mapid if success, or return -1 if failed*/
int mmap(int fd, void *addr){

	struct thread *cur = thread_current();
	struct mmap_file* mmap_file;	
	
	
	/* check if valid address */
	if(addr > (void *)0xc0000000 || addr < (void *)0x08048000)
		return -1;
	/* check if address is indicating page*/
	if((uint32_t)addr % PGSIZE != 0)
		return -1;

	/* get file from file descriptor*/	
	struct file *fp = process_get_file(fd);
	if(fp == NULL)
		return -1;
	
	/* file reopen to guarantee valid until process exits */
	struct file *rfp = file_reopen(fp);
	if(rfp == NULL)
		return -1;

	/* create and initialize  mmap_file */
	mmap_file = (struct mmap_file *)malloc(sizeof(struct mmap_file));
	if(mmap_file == NULL)
		return -1;
	else{
		mmap_file->file = rfp;
		mmap_file->mapid = ++cur->mapid;
		list_init(&mmap_file->vme_list);
	}

	off_t offset = 0;
	uint32_t read_bytes = file_length(rfp);

	while(read_bytes > 0){

		uint32_t page_read_bytes =
			 read_bytes < PGSIZE ? read_bytes : PGSIZE;
		uint32_t page_zero_bytes =
			 PGSIZE - page_read_bytes;

		/* Create vm_entry */
		struct vm_entry* vme =
			 (struct vm_entry *)malloc(sizeof(struct vm_entry));
		if(vme == NULL){
			free(mmap_file);
			return -1;
		}

		/* Initialize vm_entry */
		vme->type = VM_FILE; //for mmap file
		vme->vaddr = pg_round_down(addr);
		vme->is_loaded = false;
		vme->writable = true;
		vme->file = rfp;
		vme->read_bytes = page_read_bytes;
		vme->zero_bytes = page_zero_bytes;
		vme->offset = offset;

		/* insert vm_entry to mmap_file's vme_list */
		list_push_back(&mmap_file->vme_list, &vme->mmap_elem);
		/* insert vm_entry to hash table */
		if(!insert_vme(&cur->vm, vme)){
			free(mmap_file);
			free(vme);
			return -1;
		}

		/* Advance */
		read_bytes -= page_read_bytes;
		offset += page_read_bytes;
		addr += PGSIZE;
	}

	/* insert mmap_file to thread's mmap_list*/
	list_push_back(&cur->mmap_list, &mmap_file->elem);
	
	return cur->mapid;
}


/* Eliminate memory-mapped file from mmap_list
   CLOSE_ALL means eliminate all mmap_file from mmap_list*/
void munmap(int mapping){
	struct thread * cur = thread_current();
	struct list_elem* ptr;
	struct mmap_file* mmf;

	/* Tour mmap_list to find mmap_file
	 which has the mapid for parameter mapping*/
	ptr = list_begin(&cur->mmap_list);
	while(ptr != list_end(&cur->mmap_list)){
		
		mmf = list_entry(ptr, struct mmap_file, elem);
		/* find mmf which has mapid as mapping,
		   or mapping is CLOSE_ALL(0) */
		if(mmf->mapid == mapping || mapping == CLOSE_ALL){
			do_munmap(mmf);
			list_remove(ptr);
			ptr = list_prev(ptr);
			lock_acquire(&LOCK);
			file_close(mmf->file);
			lock_release(&LOCK);
			free(mmf);
		}
		ptr = list_next(ptr);
	}
}

/*Eliminate vm_entry from vme_list and hash table
  Also, eliminate physical frame loaded before
  But, overwrite disk if the memory is written(dirty) */
void do_munmap(struct mmap_file* mmap_file){

	struct list_elem *ptr;
	struct vm_entry *vme;

	/* Tour vme_list and eleminate vm_entry */
	ptr = list_begin(&mmap_file->vme_list);
	while(ptr != list_end(&mmap_file->vme_list)){
		
		vme = list_entry(ptr, struct vm_entry, mmap_elem);
		vme->pinned = true;
		if(vme->is_loaded == true){
			/*Before eleminating, check if content of memory is written*/
			if(pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)){
				/* If page is dirty,
				 write disk from changed content of memory*/
				lock_acquire(&LOCK);
				file_write_at(vme->file, vme->vaddr , vme->read_bytes, vme->offset);
				lock_release(&LOCK);
			}
			/* free physical frame */
			free_page(pagedir_get_page(thread_current()->pagedir, vme->vaddr));
			/* free page table entry */
			pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
		}
		list_remove(ptr);
		ptr = list_prev(ptr);
		/* eleminate vm_entry from hash table */
		delete_vme(&thread_current()->vm, vme);
		free(vme);
		ptr = list_next(ptr);
	}
}
