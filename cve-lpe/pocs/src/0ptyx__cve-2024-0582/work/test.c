#include <stdio.h>
#include "liburing.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#define set_errno(...)                                                         \
	({                                                                     \
		typeof(__VA_ARGS__) _res = (__VA_ARGS__);                      \
		if (_res < 0)                                                  \
			errno = -_res;                                         \
		_res;                                                          \
	})

uint16_t buf_gid = 3;
int main()
{
	int ret = 0;
	struct io_uring ring = { 0 };
	struct io_uring_buf_reg buf_reg = { 0 };
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	ret = io_uring_queue_init(10, &ring, 0);
	if (ret < 0) {
		puts("Failed to setup uring");
		exit(1);
	}
	puts("[**] initialzied ring");

	buf_reg.bgid = buf_gid;
	buf_reg.ring_entries = 256;
	buf_reg.ring_addr = 0x0;
	buf_reg.flags |= IOU_PBUF_RING_MMAP;

	ret = io_uring_register_buf_ring(&ring, &buf_reg, 0);
	if (set_errno(ret) < 0) {
		perror("register");
		puts("Failed to register buffer ring");
		exit(1);
	}
	puts("[**] Registered buffer ring");
	void *buf_ring = mmap(
		0, 256 * sizeof(struct io_uring_buf), PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_POPULATE, ring.ring_fd,
		IORING_OFF_PBUF_RING |
			((unsigned long long)buf_gid << IORING_OFF_PBUF_SHIFT));

	if (buf_ring == MAP_FAILED) {
		puts("Failed to mmap ring buffer");
		exit(1);
	}

	struct io_uring_buf_ring *bring = (struct io_uring_buf_ring *)buf_ring;
	io_uring_buf_ring_init(bring);
	void *buff1 = mmap(0, 4096, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANON, 0, 0);
	if (buff1 == MAP_FAILED) {
		puts("[!!] failed to map buf1");
		exit(1);
	}

	io_uring_buf_ring_add(bring, buff1, 4096, 3,
			      io_uring_buf_ring_mask(256), 0);

	io_uring_buf_ring_advance(bring, 1);

	sqe = io_uring_get_sqe(&ring);
	int fd = open("/hello.txt", O_RDWR);
	if (fd < 0) {
		puts("[!!] failed to open hello.txt");
		exit(1);
	}
	io_uring_prep_read(sqe, fd, &bring->bufs[0], 20, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = buf_gid;
	// test reading a file
	//
	io_uring_submit(&ring);
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (set_errno(ret) < 0) {
		perror("cqe");
		puts("[!!] failed to get cqe");
		exit(1);
	}
	ret = cqe->res;
	if (set_errno(ret) < 0) {
		perror("read");
		puts("[!!] failed to read to buff ring");
		exit(1);
	}
	printf("[**] cqe flags: %d\n", cqe->flags);
	printf("[**] buffer id: %d\n", cqe->flags >> 16);

	io_uring_cqe_seen(&ring, cqe);

	printf("[**] %s\n", (char *)buff1);
	io_uring_unregister_buf_ring(&ring, buf_gid);

	return 0;
}
