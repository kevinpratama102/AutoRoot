#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2)
        printf("[*] Usage: ./call_getpgid <string>\n");
    else
        //printf("%s", strcat(argv[1], "\n"));
        getpgid(strcat(argv[1], "\n"));
    return 0;
}
