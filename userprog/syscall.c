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

#include "threads/synch.h"
#include <string.h>

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
bool user_memory_valid(const void *addr);
bool user_string_valid(const char *str);
void check_address(const void *addr);
void check_valid_buffer(void *buffer, unsigned size, bool to_write);
void check_valid_string(const char *str);
struct file *get_file_by_descriptor(int fd);
struct lock syscall_lock;

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

	lock_init(&syscall_lock);
}

const char* syscall_name(int syscall_number) {
    switch (syscall_number) {
        case SYS_HALT:
            return "halt";
        case SYS_EXIT:
            return "exit";
        case SYS_EXEC:
            return "exec";
        case SYS_WAIT:
            return "wait";
        case SYS_CREATE:
            return "create";
        case SYS_REMOVE:
            return "remove";
        case SYS_OPEN:
            return "open";
        case SYS_FILESIZE:
            return "filesize";
        case SYS_READ:
            return "read";
        case SYS_WRITE:
            return "write";
        case SYS_SEEK:
            return "seek";
        case SYS_TELL:
            return "tell";
        case SYS_CLOSE:
            return "close";
        default:
            return "unknown";
    }
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

	/* Print system call information */
    // printf("System Call Invoked: %s (%d) from RIP: 0x%016lx\n", syscall_name(f->R.rax), f->R.rax, f->rip);

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
			// f->R.rax=fork(arg1);
			f->R.rax = fork(arg1, f);		//(oom_update)
			break;
		case SYS_EXEC:							//  3 새로운 프로그램 실행
			// printf("SYS_EXEC\n");
			// user_memory_valid((void *)arg1, arg3);
			// f->R.rax=exec(arg1);
			// break;
			// if (!user_string_valid((const char *)arg1)) {
			// 	exit(-1);
			// }
			// f->R.rax = exec((const char *)arg1);
			// break;

			check_valid_string((const char *)arg1);
			f->R.rax = exec((const char *)arg1);
			break;
		case SYS_WAIT:							//  4 자식 프로세스 대기
			// printf("SYS_WAIT\n");
			f->R.rax=wait(arg1);
			break;
		case SYS_CREATE:						//  5 파일 생성
			// printf("SYS_CREATE\n");
			// user_memory_valid((void *)arg1, arg3);
			// f->R.rax=create(arg1,arg2);
			// break;

			check_valid_string((const char *)arg1);
			f->R.rax = create((const char *)arg1, arg2);
			break;
		case SYS_REMOVE:						//  6 파일 삭제
			// printf("SYS_REMOVE\n");
			// user_memory_valid((void *)arg1, arg3);
			// f->R.rax=remove(arg1);
			// break;

			check_valid_string((const char *)arg1);
			f->R.rax = remove((const char *)arg1);
			break;
		case SYS_OPEN:							//  7 파일 열기
			// printf("SYS_OPEN\n");
			// user_memory_valid((void *)arg1, arg3);
			// f->R.rax=open(arg1);
			// break;

			check_valid_string((const char *)arg1);
			f->R.rax = open((const char *)arg1);
			break;
		case SYS_FILESIZE:						//  8 파일 크기 조회
			// printf("SYS_FILESIZE\n");
			f->R.rax=filesize(arg1);
			break;
		case SYS_READ:							//  9 파일에서 읽기
			// printf("SYS_READ\n");
			// user_memory_valid((void *)arg2);
			// f->R.rax=read(arg1,arg2,arg3);
			// break;
			// if (!user_memory_valid((void *)arg2, arg3)) {
			// 	exit(-1);
			// }
			// f->R.rax = read(arg1, (void *)arg2, arg3);

			check_address((void *)arg2);
			f->R.rax = read(arg1, (void *)arg2, arg3);
			break;

			// check_valid_buffer((void *)arg2, arg3, true);
			// f->R.rax = read(arg1, (void *)arg2, arg3);
			// break;
		case SYS_WRITE:							//  10 파일에 쓰기
			// printf("SYS_WRITE\n");
			// user_memory_valid((void *)arg2);
			// f->R.rax=write((int)arg1,(void *)arg2,(unsigned)arg3);
			// break;
			// if (!user_memory_valid((void *)arg2, arg3)) {
			// 	exit(-1);
			// }
			// f->R.rax = write((int)arg1, (void *)arg2, (unsigned)arg3);
			// break;

			check_address((void *)arg2);
			f->R.rax = write(arg1, (void *)arg2, arg3);
			break;

			// check_valid_buffer((void *)arg2, arg3, false);
			// f->R.rax = write((int)arg1, (void *)arg2, (unsigned)arg3);
			// break;
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
	struct thread *curr = thread_current();
	curr->process_status = status;
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

pid_t fork (const char *thread_name, struct intr_frame *f) {	//(oom_update)
	return process_fork(thread_name, f);
}

int exec (const char *cmd_line){
	char *copy = palloc_get_page(PAL_ZERO);
	if (copy == NULL) {
		exit(-1);
	}
	strlcpy(copy, cmd_line, strlen(cmd_line) + 1);
	if (process_exec (copy) < 0) {
		exit(-1);
	}
	NOT_REACHED();
}

int wait (pid_t pid){
	return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){
	lock_acquire(&syscall_lock);		//minjae's
	bool create_return = filesys_create(file, initial_size);
	lock_release(&syscall_lock);		//minjae's
	return create_return;
}

bool remove (const char *file){
	return filesys_remove(file);
}

int open (const char *file) {	//(oom_update)
	lock_acquire(&syscall_lock);
	struct file *f = filesys_open(file);
	if (f == NULL){
		lock_release(&syscall_lock);
		return -1;
	}
	struct thread *curr = thread_current();
	struct file **fdt = curr->fd_table;

	while (curr->next_fd < FD_MAX && fdt[curr->next_fd])
		curr->next_fd++;

	if (curr->next_fd >= FD_MAX) {
		file_close (f);
		lock_release(&syscall_lock);
		return -1;
	}

	fdt[curr->next_fd] = f;
	lock_release(&syscall_lock);
	return curr->next_fd;
}

int filesize (int fd){
	struct file *file = get_file_by_descriptor(fd);
	return file_length(file);
}

// int read (int fd, void *buffer, unsigned size){
// 	if (fd == STD_IN) {                // keyboard로 직접 입력
// 		int i;  // 쓰레기 값 return 방지
// 		char c;
// 		unsigned char *buf = buffer;

// 		for (i = 0; i < size; i++) {
// 			c = input_getc();
// 			*buf++ = c;
// 			if (c == '\0')
// 				break;
// 		}
// 		return i;
// 	}
	
//     struct file *file = get_file_by_descriptor(fd);
// 	if (file == NULL || fd == STD_OUT || fd == STD_ERR)  // 빈 파일, stdout, stderr를 읽으려고 할 경우
// 		return -1;

// 	off_t bytes = -1;
// 	lock_acquire(&syscall_lock);
// 	bytes = file_read(file, buffer, size);
// 	lock_release(&syscall_lock);

// 	return bytes;
// }

int read(int fd, void *buffer, unsigned size) {
    if (fd == STD_IN) {
        unsigned char *buf = buffer;
        unsigned i;
        for (i = 0; i < size; i++) {
            char c = input_getc();
            buf[i] = c;
            if (c == '\0')
                break;
        }
        return i;
    }

    struct file *file = get_file_by_descriptor(fd);
    if (file == NULL || fd == STD_OUT || fd == STD_ERR) {
        return -1;
    }

    off_t bytes_read = -1;
    lock_acquire(&syscall_lock);
    bytes_read = file_read(file, buffer, size);
    lock_release(&syscall_lock);

    return bytes_read;
}

int write (int fd, const void *buffer, unsigned size){
	if (fd == STD_IN || fd == STD_ERR){
		return -1;
	}

	if (fd == STD_OUT){
		putbuf(buffer, size);
		return size;
	}

	struct file *file = get_file_by_descriptor(fd);
	if (file == NULL){
		return -1;
	}

	lock_acquire(&syscall_lock);
	int written = file_write(file, buffer, size);
	lock_release(&syscall_lock);

	return written;
}

void seek (int fd, unsigned position){
	if (fd < 3)
		return;

	struct file *file = get_file_by_descriptor(fd);
	if (file == NULL){
		return;
	}

	file_seek(file, position);
}

unsigned tell (int fd){
	if (fd < 3)
		return -1;

	struct file *file = get_file_by_descriptor(fd);
	if (file == NULL){
		return -1;
	}

	return file_tell(file);
}

void close (int fd){	//(oom_update)
	if (fd <= 2)
		return;
	struct thread *curr = thread_current ();
	struct file *f = curr->fd_table[fd];

	if (f == NULL){
		return;
	}
	curr->fd_table[fd] = NULL;
	curr->next_fd = 3;

	file_close(f);
}


// void user_memory_valid(void *r){
// 	struct thread *current = thread_current();  
// 	uint64_t *pml4 = current->pml4;
// 	if (r == NULL || is_kernel_vaddr(r) || pml4_get_page(pml4,r) == NULL){
// 		exit(-1);
// 	}
// }

// bool user_memory_valid(const void *addr, size_t size) {
//     struct thread *current = thread_current();
//     uint64_t *pml4 = current->pml4;

//     if (addr == NULL || !is_user_vaddr(addr)) {
//         return false;
//     }

//     const void *start = addr;
//     const void *end = (const char *)addr + size;

//     if (end < start || !is_user_vaddr(end)) {
//         return false;
//     }

//     /* Round down the start address to the nearest page boundary */
//     void *page_addr = pg_round_down(start);

//     while (page_addr < end) {
//         if (pml4_get_page(pml4, page_addr) == NULL) {
//             return false;
//         }
//         page_addr = (char *)page_addr + PGSIZE;
//     }

//     return true;
// }

bool user_memory_valid(const void *addr) {
    return addr != NULL && is_user_vaddr(addr);
}

bool user_string_valid(const char *str) {
    struct thread *current = thread_current();
    uint64_t *pml4 = current->pml4;

    if (str == NULL || !is_user_vaddr(str)) {
        return false;
    }

    while (true) {
        if (pml4_get_page(pml4, (void *)str) == NULL) {
            return false;
        }
        char c = *str;
        if (c == '\0') {
            break;
        }
        str++;
    }

    return true;
}

void check_address(const void *addr) {
    if (addr == NULL || !is_user_vaddr(addr)) {
        exit(-1);
    }

    // struct thread *current = thread_current();
    // void *page = pml4_get_page(current->pml4, addr);
    // if (page == NULL) {
    //     exit(-1);
    // }
}

void check_valid_buffer(void *buffer, unsigned size, bool to_write) {
    char *buf = (char *)buffer;
    char *end = buf + size;
    while (buf < end) {
        check_address(buf);

        if (to_write) {
            // Additional checks for write permissions can be added here.
        }

        // Move to the next page
        buf = (char *)pg_round_down(buf);
        buf += PGSIZE;
    }
}

void check_valid_string(const char *str) {
    while (true) {
        check_address((const void *)str);
        if (*str == '\0') {
            break;
        }
        str++;
    }
}

struct file *get_file_by_descriptor(int fd)
{
	if (fd < 3 || fd > 128)
		return NULL;
	struct thread *t = thread_current();
	return t->fd_table[fd];
}