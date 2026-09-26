#include<syslog.h> 
#include<stdio.h>

int main(){
	long sp;
	asm ("mov %%rsp, %0" : "=m" (sp));
	printf("rsp = %#16lx\n", sp);
}
