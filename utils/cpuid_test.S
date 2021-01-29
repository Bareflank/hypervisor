    .code64
    .intel_syntax noprefix

    .globl  main
    .type   main, @function
main:

    push rbx

    mov rdi, 0x100000
loop:
    xor rax, rax
    xor rcx, rcx
    cpuid

    dec rdi
    cmp rdi, 0
    jne loop
   
    pop rbx
    ret
