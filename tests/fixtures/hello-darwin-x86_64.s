.section __TEXT,__text,regular,pure_instructions
.globl _start
.p2align 4, 0x90
_start:
    movabsq $0x02000004, %rax
    movabsq $1, %rdi
    leaq message(%rip), %rsi
    movabsq $message_length, %rdx
    syscall

    movabsq $0x02000001, %rax
    movabsq $0, %rdi
    syscall

message:
    .ascii "hello from Intel Darwin\n"
.set message_length, . - message
