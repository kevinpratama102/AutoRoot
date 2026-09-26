#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <iconv.h>
#include <stdio.h>

#include "constants.h"

int main()
{
	iconv_t conv;
	setenv("GCONV_PATH", "./" TROJAN_GCONV_PATH, 1);
	conv = iconv_open("UTF-8", TROJAN_CHARSET);
	if (conv == (iconv_t) -1) {
		fprintf(stderr, "Conversation failed: %s\n", strerror(errno));
		return 0;
	} else {
		iconv_close(conv);
		return 1;
	}
}
