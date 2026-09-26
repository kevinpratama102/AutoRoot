all: shellcode exploit

shellcode: shellcode.c
	mkdir -p libnss_x  
	gcc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c

exploit: exploit.asm
	nasm -f elf64 -o exploit.o exploit.asm
	ld -o exploit exploit.o -g

clean:
	rm -rf libnss_x exploit *.o
