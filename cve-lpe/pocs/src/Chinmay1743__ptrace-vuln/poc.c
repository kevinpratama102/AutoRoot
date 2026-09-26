#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <stdio.h>

int main() {
    pid_t child_pid = fork();

    if (child_pid == 0) { // Child process
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/echo", "echo", "Hello, ptrace!", NULL);
    } else { // Parent process
        int status;
        struct user_regs_struct regs;

        while (1) {
            wait(&status);
            if (WIFEXITED(status)) break;

            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            printf("Syscall: %lld\n", regs.orig_rax); // System call number (x86-64)

            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); // Continue to next syscall
        }
    }
    return 0;
}

