#include <string.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/syscall.h>
 
#include <sys/prctl.h>
#include <fcntl.h>

#include "exp_sys_call.h"
#include "kallsyms.h"
#include "log.h"

unsigned long int exp_sys_call_address;

#define PR_GET_SECCOMP  21

int config_seccomp() {
  if (kallsyms_exist_sym("__audit_seccomp"))
    return 1;

  int ret = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (ret < 0) {
        switch (errno) {
        case ENOSYS:
            return 0;
        case EINVAL:
                return 0;
        default:
                return 1;
        }
    }
    return 1;
}

int config_oabi() {
  return kallsyms_exist_sym("sys_oabi_call_table");
}

unsigned long get_sys_table_base_via_swi()
{
    const void *swi_addr = 0xFFFF0008;
    unsigned long vector_swi_offset = 0;
    unsigned long vector_swi_instruction = 0;
    unsigned long *vector_swi_addr_ptr = NULL;
    unsigned long offset = 0xC4;
    
    memcpy(&vector_swi_instruction, swi_addr, sizeof(vector_swi_instruction));
    vector_swi_offset = vector_swi_instruction & (unsigned long)0x00000fff;
    if (config_oabi()) {
      offset += 0x24;
    }
    if (config_seccomp()) {
      offset += 0x20;
    }
    vector_swi_addr_ptr = (unsigned long *)((unsigned long)swi_addr + vector_swi_offset + 8);
    LOGE("offset:%x\n", offset);
    LOGE("addr:%x\n", (*vector_swi_addr_ptr));
    return *vector_swi_addr_ptr + offset;
}

unsigned long get_sys_table_base() {
  unsigned long syscall_base = (unsigned long)kallsyms_get_symbol_address("sys_call_table");
  if (syscall_base)
    return syscall_base;

  return get_sys_table_base_via_swi();
}

bool
setup_exp_sys_call_address(void)
{
  unsigned long sys_call_table = get_sys_table_base();

  if (sys_call_table == 0)
    return false;

  exp_sys_call_address = (unsigned long int)sys_call_table + __NR_exp_ * 4;
  return true;
}
