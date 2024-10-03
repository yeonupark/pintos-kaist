#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"

#define FD_MAX 128

typedef uint32_t disk_sector_t;

struct file {
	struct inode *inode;        /* File's inode. */
	off_t pos;                  /* Current position. */
	bool deny_write;            /* Has file_deny_write() been called? */
};

struct inode_disk {
	disk_sector_t start;                /* First data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	uint32_t unused[125];               /* Not used. */
};

struct inode {
	struct list_elem elem;              /* Element in inode list. */
	disk_sector_t sector;               /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	struct inode_disk data;             /* Inode content. */
};

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void user_memory_valid(void *r);
struct file *get_file_by_descriptor(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf("\n------- syscall handler -------\n");
	uint64_t arg1 = f->R.rdi;
	uint64_t arg2 = f->R.rsi;
	uint64_t arg3 = f->R.rdx;
	uint64_t arg4 = f->R.r10;
	uint64_t arg5 = f->R.r8;
	uint64_t arg6 = f->R.r9;
	switch (f->R.rax)
	{
		case SYS_HALT:							//  0 운영체제 종료
			// RPL(Requested Privilege Level) : cs의 하위 2비트
			if ((f->cs & 0x3) != 0){}
				// 권한 없음
			// printf("SYS_HALT\n");
			halt();
		case SYS_EXIT:							//  1 프로세스 종료
			// printf("SYS_EXIT\n");
			exit(arg1);
			break;
		case SYS_FORK:							//  2 프로세스 복제
			// printf("SYS_FORK\n");
			f->R.rax=fork(arg1);
			break;
		case SYS_EXEC:							//  3 새로운 프로그램 실행
			// printf("SYS_EXEC\n");
			f->R.rax=exec(arg1);
			break;
		case SYS_WAIT:							//  4 자식 프로세스 대기
			// printf("SYS_WAIT\n");
			f->R.rax=wait(arg1);
			break;
		case SYS_CREATE:						//  5 파일 생성
			// printf("SYS_CREATE\n");
			user_memory_valid((void *)arg1);
			f->R.rax=create(arg1,arg2);
			break;
		case SYS_REMOVE:						//  6 파일 삭제
			// printf("SYS_REMOVE\n");
			user_memory_valid((void *)arg1);
			f->R.rax=remove(arg1);
			break;
		case SYS_OPEN:							//  7 파일 열기
			// printf("SYS_OPEN\n");
			user_memory_valid((void *)arg1);
			f->R.rax=open(arg1);
			break;
		case SYS_FILESIZE:						//  8 파일 크기 조회
			// printf("SYS_FILESIZE\n");
			f->R.rax=filesize(arg1);
			break;
		case SYS_READ:							//  9 파일에서 읽기
			// printf("SYS_READ\n");
			user_memory_valid((void *)arg2);
			f->R.rax=read(arg1,arg2,arg3);
			break;
		case SYS_WRITE:							//  10 파일에 쓰기
			// printf("SYS_WRITE\n");
			user_memory_valid((void *)arg2);
			f->R.rax=write((int)arg1,(void *)arg2,(unsigned)arg3);
			break;
		case SYS_SEEK:							//  11 파일 내 위치 변경
			// printf("SYS_SEEK\n");
			seek(arg1,arg2);
			break;
		case SYS_TELL:							//  12 파일의 현재 위치 반환
			// printf("SYS_TELL\n");
			f->R.rax=tell(arg1);
			break;
		case SYS_CLOSE:							//  13 파일 닫기
			// printf("SYS_CLOSE\n");
			close(arg1);
			break;
		default:
			// printf("default;\n");
			break;
	}
	// printf("-------------------------------\n\n");
}

void halt (void){
	power_off();
}

void exit (int status){
	struct thread *t = thread_current();
	// args-single: exit(0)
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

pid_t fork (const char *thread_name){
	tid_t tid = thread_create (thread_name, PRI_DEFAULT, __do_fork, thread_current ());
	
}

int exec (const char *cmd_line){
	
	palloc_get_page(PAL_USER);
	if (process_exec (cmd_line) < 0)
		return -1;
	NOT_REACHED ();
}

int wait (pid_t pid){

}

bool create (const char *file, unsigned initial_size){
	return filesys_create(file, initial_size);
}

bool remove (const char *file){
	return filesys_remove(file);
}

int open (const char *file){
	struct thread *t = thread_current();
	if (t->next_fd == FD_MAX) {
		return -1;
	}
	if((t->fd_table[t->next_fd] = filesys_open(file)) == NULL) {
		return -1;
	}
	int fd = t->next_fd;

	// next_fd 갱신
	for (int i=3; i<=FD_MAX; i++) {
		if (i==FD_MAX) {
			t->next_fd = i;
			break;
		}
		if (t->fd_table[i] == NULL) {
			t->next_fd = i;
			break;
		}
	}

	return fd;
}

int filesize (int fd){
	struct thread *t = thread_current();
	struct file *file = t->fd_table[fd];
	return file->inode->data.length;
}

int read (int fd, void *buffer, unsigned size){
	struct file *file = get_file_by_descriptor(fd);
	if (file == NULL) {
		return -1;
	}
	return file_read(file, buffer, size);
}

int write (int fd, const void *buffer, unsigned size){
	if (fd == 0){		// Standard Input
		return -1;
	}
	if (fd == 1){		// Standard Output
		putbuf(buffer, size);
		return size;
	}
	if (fd == 2){		// Standard Error
		putbuf(buffer, size);
		return size;
	}
	struct file *file = get_file_by_descriptor(fd);
	if (file == NULL){
		return -1;
	}
	int written = file_write(file, buffer, size);
	file->pos += written;
	return written;
}

void seek (int fd, unsigned position){
	file_seek(get_file_by_descriptor(fd), position);
}

unsigned tell (int fd){
	struct thread *t = thread_current();
	return t->fd_table[fd]->pos;
}

void close (int fd){
	struct thread *t = thread_current();
	if (get_file_by_descriptor(fd) == NULL) {
		exit(-1);
	}
	free(t->fd_table[fd]);
	t->fd_table[fd] = NULL;
	if (t->next_fd == 128) {
		t->next_fd = fd;
	}
}


void user_memory_valid(void *r){
	struct thread *current = thread_current();  
    uint64_t *pml4 = current->pml4;
	if (r == NULL || is_kernel_vaddr(r) || pml4_get_page(pml4,r) == NULL){
		exit(-1);
	}
}

struct file *get_file_by_descriptor(int fd)
{
	if (fd < 3 || fd > 128) return NULL;
	
	struct thread *t = thread_current();

	return t->fd_table[fd];
}