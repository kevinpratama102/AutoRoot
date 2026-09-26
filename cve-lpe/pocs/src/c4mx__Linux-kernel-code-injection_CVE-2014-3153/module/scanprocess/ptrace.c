#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<fcntl.h>
#include<sys/ptrace.h>

int main(int argc, char ** argv)
{
    char mem_file_name[256];
    int mem_fd;
    FILE * f;
    int pid;
    int offset = 4194304;

    long sz = sysconf(_SC_PAGE_SIZE);
    char * buf = malloc(sz);

    sscanf(argv[1], "%i", &pid);
    printf("Process: %i\n", pid);
    printf("page size: %li", sz);
    sprintf(mem_file_name, "/proc/%i/mem", pid);
    mem_fd = open(mem_file_name, O_RDONLY);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    lseek(mem_fd, offset, SEEK_SET);
    read(mem_fd, buf, sz);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    f = fopen("out.bin", "w");
    fwrite(buf, sz, 1, f);
    fclose(f);


    return 0;
}
