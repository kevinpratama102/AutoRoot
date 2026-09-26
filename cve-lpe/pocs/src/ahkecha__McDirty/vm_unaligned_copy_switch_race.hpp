#ifndef __VM_UNALIGNED_COPY_SWITCH_RACE_H__
#define __VM_UNALIGNED_COPY_SWITCH_RACE_H__

#include <pthread.h>
#include <dispatch/dispatch.h>
#include <stdio.h>

#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <cstdio>
#include <unistd.h>
#include <iostream>
#include <limits>
#include <fstream>

#define T_QUIET
#define T_EXPECT_MACH_SUCCESS(a, b)
#define T_EXPECT_MACH_ERROR(a, b, c)
#define T_ASSERT_MACH_SUCCESS(a, b, ...)
#define T_ASSERT_MACH_ERROR(a, b, c)
#define T_ASSERT_POSIX_SUCCESS(a, b)
#define T_ASSERT_EQ(a, b, c) do{if ((a) != (b)) { fprintf(stderr, c "\n"); exit(1); }}while(0)
#define T_ASSERT_NE(a, b, c) do{if ((a) == (b)) { fprintf(stderr, c "\n"); exit(1); }}while(0)
#define T_ASSERT_TRUE(a, b, ...)
#define T_LOG(a, ...) fprintf(stderr, a "\n", __VA_ARGS__)
#define T_DECL(a, b) static void a(void)
#define T_PASS(a, ...) fprintf(stderr, a "\n", __VA_ARGS__)

#endif // __VM_UNALIGNED_COPY_SWITCH_RACE_H__
