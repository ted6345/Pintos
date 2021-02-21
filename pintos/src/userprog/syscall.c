#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/*added header*/
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include "userprog/process.h"
#include <devices/input.h>
#include "threads/synch.h"
#include "threads/vaddr.h"

extern struct lock LOCK;

static void syscall_handler (struct intr_frame *);
int process_add_file (struct file *f);
void remove_child_process(struct thread *cp);
struct thread *get_child_process(int pid);
struct file *process_get_file(int fd);
void process_close_file(int fd);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
tid_t exec(const char *cmd_line);
int wait(tid_t tid);
int open(const char *file_path);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell (int fd);
void close(int fd);

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
	check_address(f->esp);

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
			check_address((void *)arg[0]);
			f->eax = exec((const char *)arg[0]);
			break;

		case SYS_WAIT:
			get_argument(f->esp, arg, 1);
			f->eax = wait((tid_t)arg[0]);
			break;

		case SYS_CREATE:
			get_argument(f->esp, arg, 2);
			check_address((void *)arg[0]);
			f->eax = create((const char *)arg[0], (unsigned)arg[1]);
			break;

		case SYS_REMOVE:
			get_argument(f->esp, arg, 1);
			check_address((void *)arg[0]);
			f->eax = remove((const char *)arg[0]);
			break;

		case SYS_OPEN:
			get_argument(f->esp, arg, 1);
			check_address((void *)arg[0]);
			f->eax = open((const char *)arg[0]);
			break;

		case SYS_FILESIZE:
			get_argument(f->esp, arg, 1);
			f->eax = filesize((int)arg[0]);
			break;

		case SYS_READ:
			get_argument(f->esp, arg, 3);
			check_address((void *)arg[1]);
			f->eax = read((int)arg[0], (void *)arg[1], (unsigned)arg[2]);
			break;

		case SYS_WRITE:
			get_argument(f->esp, arg, 3);
			check_address((void *)arg[1]);
			f->eax = write((int)arg[0], (void *)arg[1], (unsigned)arg[2]);
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
	}
}

/*check if addr locates in User Space*/
void check_address(void *addr)
{
	/*User Space : 0xc0000000 ~ 0x8048000*/
	if((uint32_t)addr < 0x08048000 || (uint32_t)addr >= 0xc0000000){
		exit(-1);
	}
}

/*save arguments to Kernel from User Stack*/
void get_argument(void *esp, int *arg, int count){
	int i;

	esp = esp + 4;
	for(i=0; i<count; i++){
		arg[i] = *(int *)esp;
		esp = esp + 4;
	}
}

void halt(void){
	shutdown_power_off();
}

void exit(int status){
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit(%d)\n",t->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size){
	return filesys_create(file, initial_size);
}

bool remove(const char *file){
	return filesys_remove(file);
}

tid_t exec(const char *cmd_line){
	tid_t child_pid;
	struct thread *t;
	child_pid = process_execute(cmd_line);
	t = get_child_process((int)child_pid);
	sema_down(&t->load_sema);
	if(t->is_load == false)
		return -1;
	else 
		return child_pid;
}

int wait(tid_t tid){
	return process_wait(tid);
}

int open(const char *file_path){
	//int fd;
	struct file * file;
	file = filesys_open(file_path);
	if(file  == NULL)
		return -1;
	else
	   return process_add_file(file);
}

int filesize(int fd){
	struct file * file;
	file = process_get_file(fd);
	if(file == NULL)
		return -1;
	else
		return file_length(file);
}

int read (int fd, void *buffer, unsigned size){
	
	int read_size;
	lock_acquire(&LOCK);
	struct file *f = process_get_file(fd);

	if(f == NULL)
		read_size = 0;
	else if(fd == 0){ //STDIN
		unsigned int i=0;
		for(i=0; i<size; i++)
			*(char *)buffer++ = input_getc();
		read_size = i;
	}
	else
		read_size = file_read(f, buffer, (off_t)size);

	lock_release(&LOCK);
	return read_size;
}

int write(int fd, void *buffer, unsigned size){
	int write_size;

	lock_acquire(&LOCK);
	struct file *f = process_get_file(fd);
	
	if(fd == 1){ //STDOUT
		putbuf((const char *)buffer, (size_t)size);
		write_size = size;
	}
	else if(f == NULL)
		write_size = -1;
	else
		write_size = file_write(f, buffer, (off_t)size);

	lock_release(&LOCK);
	return write_size;
}

void seek(int fd, unsigned position){
	struct file *f = process_get_file(fd);
	if(f != NULL)
		file_seek(f, position);
}
unsigned tell (int fd){
	struct file *f = process_get_file(fd);
	if(f != NULL)
		return file_tell(f);
	else
		return -1;
}
void close(int fd){
	process_close_file(fd);
}
