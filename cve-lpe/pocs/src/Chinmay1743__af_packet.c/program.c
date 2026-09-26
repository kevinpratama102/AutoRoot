#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* ETH_P_ALL */
#include <arpa/inet.h> /* htons */
#include <stdint.h>

#define CAP_NET_RAW_BIT 12

/* read CapEff from /proc/self/status and return as 64-bit mask (0 on fail) */
static unsigned long long read_CapEff(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char *line = NULL;
    size_t len = 0;
    unsigned long long capeff = 0;
    while (getline(&line, &len, f) != -1) {
        if (strncmp(line, "CapEff:", 7) == 0) {
            // line format: "CapEff:\t0000000000000000\n"
            char *hex = line + 7;
            while (*hex == ' ' || *hex == '\t') ++hex;
            // remove newline
            char *nl = strchr(hex, '\n');
            if (nl) *nl = '\0';
            capeff = strtoull(hex, NULL, 16);
            break;
        }
    }
    free(line);
    fclose(f);
    return capeff;
}

int try_socket(int type)
{
    int fd = socket(AF_PACKET, type, htons(ETH_P_ALL));
    if (fd < 0) {
        printf("socket(AF_PACKET, %s, ETH_P_ALL) => FAILED: %s (errno=%d)\n",
               (type==SOCK_RAW) ? "SOCK_RAW" : "SOCK_DGRAM",
               strerror(errno), errno);
        return -1;
    } else {
        printf("socket(AF_PACKET, %s, ETH_P_ALL) => OK (fd=%d)\n",
               (type==SOCK_RAW) ? "SOCK_RAW" : "SOCK_DGRAM",
               fd);
    }
    return fd;
}

/* attempt a minimal PACKET_RX_RING setsockopt (invokes packet_set_ring in kernel) */
int try_packet_rx_ring(int fd)
{
    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    // Use conservative small sizes that are valid on many kernels:
    req.tp_block_size = 1 << 16;  // 64KB block
    req.tp_block_nr   = 1;        // 1 block
    req.tp_frame_size = 1 << 11;  // 2KB frame
    req.tp_frame_nr   = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

    int rc = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rc < 0) {
        printf("setsockopt(PACKET_RX_RING) => FAILED: %s (errno=%d)\n",
               strerror(errno), errno);
        return -1;
    } else {
        printf("setsockopt(PACKET_RX_RING) => OK\n");
        return 0;
    }
}

int main(void)
{
    uid_t uid = getuid();
    uid_t euid = geteuid();
    printf("\n=== AF_PACKET privilege probe ===\n");
    printf("UID=%u  EUID=%u\n\n", (unsigned)uid, (unsigned)euid);

    unsigned long long capeff = read_CapEff();
    if (capeff == 0) {
        printf("WARNING: couldn't read CapEff from /proc/self/status. Continuing anyway.\n");
    } else {
        printf("CapEff (hex) = 0x%016" PRIx64 "\n", (uint64_t)capeff);
        int has_net_raw = ((capeff >> CAP_NET_RAW_BIT) & 1ULL) ? 1 : 0;
        printf(" -> CAP_NET_RAW (bit %d) = %s\n\n", CAP_NET_RAW_BIT, has_net_raw ? "YES" : "NO");
    }

    printf("Stage 1: try AF_PACKET + SOCK_DGRAM (no CAP_NET_RAW required by kernel check)\n");
    int fd_dgram = try_socket(SOCK_DGRAM);
    if (fd_dgram >= 0) close(fd_dgram);

    printf("\nStage 2: try AF_PACKET + SOCK_RAW (kernel checks CAP_NET_RAW for SOCK_RAW)\n");
    int fd_raw = try_socket(SOCK_RAW);
    if (fd_raw >= 0) {
        printf("Since RAW socket creation succeeded, we likely have CAP_NET_RAW (or are root).\n");
        printf("\nStage 3: try setsockopt PACKET_RX_RING (this invokes packet_set_ring in kernel)\n");
        try_packet_rx_ring(fd_raw);
        close(fd_raw);
    } else {
        printf("RAW socket creation failed: you cannot reach packet_set_ring() from user-land without CAP_NET_RAW.\n");
        printf("Common results:\n");
        printf(" - errno=EPERM (Operation not permitted) : you lack CAP_NET_RAW\n");
        printf(" - errno=EACCES : sometimes indicates policy or network namespace restrictions\n");
    }

    printf("\nNotes:\n");
    printf(" - The kernel enforces CAP_NET_RAW at socket creation: look for a check like\n");
    printf("     if (sock->type == SOCK_RAW && !capable(CAP_NET_RAW)) return -EPERM;\n");
    printf("   in net/packet/af_packet.c (this is why PACKET_RX_RING is unreachable without that socket).\n");
    printf(" - If you run this program as root or with CAP_NET_RAW, the RAW socket will succeed and\n");
    printf("   setsockopt(PACKET_RX_RING) will attempt to configure the ring (it may still fail with EINVAL\n");
    printf("   if your parameters are invalid, but you will have invoked packet_set_ring()).\n");
    printf("\n=== Done ===\n\n");
    return 0;
}



