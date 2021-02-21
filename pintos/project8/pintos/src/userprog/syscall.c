#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"     //void thread_exit(void)
/*added header*/
#include <devices/shutdown.h>   //void shutdown_power_off(void)
#include "filesys/filesys.h"    //bool filesys_create(), filesys_remove()
#include "filesys/file.h"
#include "userprog/process.h"
#include <devices/input.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

extern struct lock LOCK;

static void syscall_handler (struct intr_frame *);
void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);
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
bool sys_isdir(int fd);
bool sys_chdir(const char*);
bool sys_mkdir(const char* dir);
bool sys_readdir(int fd, char* name);
int sys_inumber(int fd);

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

		case SYS_CHDIR:
			get_argument(f->esp, arg, 1);
			check_address((void *)arg[0]);
			f->eax = sys_chdir((const char*)arg[0]);
			break;

		case SYS_MKDIR:
			get_argument(f->esp, arg, 1);
			check_address((void *)arg[0]);
			f->eax = sys_mkdir((const char*)arg[0]);
			break;

		case SYS_READDIR:
			get_argument(f->esp, arg, 2);
			check_address((void *)arg[1]);
			f->eax = sys_readdir((int)arg[0],(char*)arg[1]);
			break;

		case SYS_INUMBER:
			get_argument(f->esp, arg, 1);
			f->eax = sys_inumber((int)arg[0]);
			break;
	}
}

/*check if addr locates in User Space
 if not, page fault : exit(-1)*/
void check_address(void *addr)
{
	/*User Space : 0xc0000000 ~ 0x8048000*/
	if(addr < (void *)0x08048000 || addr >= (void *)0xc0000000)
		exit(-1);
}

/*save arguments to Kernel from User Stack*/
void get_argument(void *esp, int *arg, int count){
	int i;
	esp = esp + 4;
	for(i=0; i<count; i++){
		check_address(esp);
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
	return filesys_create(file, initial_size);
}

/*Remove file*/
bool remove(const char *file){
	return filesys_remove(file);
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
	file = filesys_open(file_path);
	if(file  == NULL)
	{
		return -1;
	}
	else{
		int fd = process_add_file(file);
		return fd;
	}
}

/*Return opend file(fd)'s size,
 if there's no such file opend return -1*/
int filesize(int fd){
	struct file * file;
	file = process_get_file(fd);
	if(file == NULL)
		return -1;
	else
		return (int)file_length(file);
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
int write(int fd, void *buffer, unsigned size){
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
	struct file *f = process_get_file(fd);
	if(f != NULL)
		file_seek(f, position);
}

/*Return offset of opend file that has file descriptor value fd*/
unsigned tell (int fd){
	struct file *f = process_get_file(fd);
	return file_tell(f);
}

/*Close opend file that has file descriptor value fd*/
void close(int fd){
		process_close_file(fd);
}

/*Check if file is directory*/
bool sys_isdir(int fd){
	bool result = false;
	struct file* fp = process_get_file(fd);
	if(fp != NULL)
		result = inode_is_dir(file_get_inode(fp));
	return result;
}

/*Change current working directory*/
bool sys_chdir(const char* dir_name){
	/*get dir_name's inode*/
	struct file* file = filesys_open(dir_name);
	if(file == NULL)
		return false;
	struct inode* inode = file_get_inode(file);
	struct dir* dir;

	/*change current threads' cur_dir*/
	dir_close(thread_current()->cur_dir);
	dir = dir_open(inode);
	if(dir != NULL){
		thread_current()->cur_dir = dir;
		return true;
	} else
		return false;

}

/*Create directory in dir*/
bool sys_mkdir(const char* dir){
	return filesys_create_dir(dir);
}

/*Read directory and get name of directory's entry */
bool sys_readdir(int fd, char* name){
	/* get file (which would be directory)*/
	struct file* fp = process_get_file(fd);
	if(inode_is_dir(file_get_inode(fp))){
		/* find file name from directory excluding ".", ".." */
		struct dir* dir = dir_open(file_get_inode(fp));
		do{
			if(!dir_readdir(dir, name)){
				dir_close(dir);
				return false;
			}
		} while(strcmp(name, ".") || strcmp(name, ".."));
		dir_close(dir);
	} else
		return false;

	return true;
}

/* get inode number from file */
int sys_inumber(int fd){
	struct file* fp = process_get_file(fd);
	return inode_get_inumber(file_get_inode(fp));
}
