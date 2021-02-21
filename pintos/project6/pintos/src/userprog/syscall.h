#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"
#include "vm/page.h"

void syscall_init (void);

struct vm_entry* check_address(void *addr,void* esp);
void check_valid_buffer(void* buffer, unsigned size, void* esp,bool to_write);
void check_valid_string(const void* str, void* esp);

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
int mmap(int fd,void* addr);
void do_munmap(struct mmap_file* mmap_file);
void munmap(int mapid);

#endif /* userprog/syscall.h */
