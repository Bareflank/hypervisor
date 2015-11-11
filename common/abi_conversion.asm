global exec_ms64tosv64

section .text
exec_ms64tosv64:

    ; Microsoft ABI
    ;   - RCX: First argument (entry point)
    ;   - RDX: Second argument (argument to be given to the entry point)
    ;   - RAX: Return register

    ; System V ABI
    ;   - RDI: First argument (argument to be given to the entry point)
    ;   - RAX: Return register

    ; Save off the nonvolatile registers as defined by the following:
    ; https://msdn.microsoft.com/en-us/library/6t169e9c.aspx
    push rbx
    push rbp
    push rdi
    push rsi
    push rsp
    push r12
    push r13
    push r14
    push r15

    mov     rdi, rdx
    call    rcx

    ; Restore the nonvolatile registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsp
    pop rsi
    pop rdi
    pop rbp
    pop rbx

    ret
