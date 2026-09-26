#ifndef GETROOT_H
#define GETROOT_H

#include "threadinfo.h"

int read_at_address_pipe(void* address, void* buf, ssize_t len);
int write_at_address_pipe(void* address, void* buf, ssize_t len);
inline int writel_at_address_pipe(void* address, unsigned long val);
int modify_task_cred_uc(struct thread_info* info);

#endif /* GETROOT_H */
