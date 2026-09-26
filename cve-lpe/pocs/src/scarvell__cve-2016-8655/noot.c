#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>




int main(int argc, char **argp) {
  struct tpacket_req3 req;
  int err, fd, v = TPACKET_V3, vvv = TPACKET_V1;
  unsigned int blocksiz = 1 << 22, framesiz = 1 << 11, blocknum = 64;
  struct timespec start, end;


  fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd < 0) {
    perror("socket");
    exit(1);
  }
  err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
  if (err < 0) {
    perror("setsockopt");
    exit(1);
  }
  memset(&req, 0, sizeof(req));
  req.tp_block_size = blocksiz;
  req.tp_frame_size = framesiz;
  req.tp_block_nr = blocknum;
  req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
  req.tp_retire_blk_tov = 60;
  req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

  clock_gettime(CLOCK_MONOTONIC_RAW, &start);
  err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req,
    sizeof(req));
  clock_gettime(CLOCK_MONOTONIC_RAW, &end);
  if (err < 0) {
    perror("setsockopt");
    exit(1);
  }
  uint64_t ring_init_us = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_nsec - start.tv_nsec) / 1000;
  close(fd);

  for( float mul=0.9; mul > 0; mul -= 0.1 ) {
    // begin dirty shit
    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
      perror("socket");
      exit(1);
    }
    err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (err < 0) {
      perror("setsockopt");
      exit(1);
    }
    memset(&req, 0, sizeof(req));
    req.tp_block_size = blocksiz;
    req.tp_frame_size = framesiz;
    req.tp_block_nr = blocknum;
    req.tp_frame_nr = (blocksiz * blocknum) / framesiz;
    req.tp_retire_blk_tov = 60;
    req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    pid_t pid = fork();
    if( pid == 0 ) {
      // child
      err = setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req,
        sizeof(req));
      if (err < 0) {
        perror("setsockopt");
        exit(1);
      }
      exit(69);
    }
    else {
      // parent
      usleep((int) (ring_init_us * mul));
      err = setsockopt(fd, SOL_PACKET, PACKET_VERSION, &vvv, sizeof(vvv));
      if (err < 0) {
        perror("setsockopt");
        //exit(2);
      }
      usleep(ring_init_us);
      close(fd);
    }
    printf("no luck with sleeping for %d :(\n", (int) (ring_init_us * mul));
  }

}
