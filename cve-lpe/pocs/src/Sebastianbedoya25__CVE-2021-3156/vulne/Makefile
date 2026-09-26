all: shellcode exploit

shellcode: shellcode.c
	mkdir libnss_x
	$(CC) -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c

exploit: exploit.c
	$(CC) -O3 -o exploit exploit.c

dos: dos.c
	$(CC) -O3 -o exploit dos.c
	
clean:
	rm -rf libnss_x exploit