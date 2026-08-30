.section __TEXT,__text,regular,pure_instructions
.globl _start
.p2align 4, 0x90
_start:
    movl (%rsp), %edi
    leaq 8(%rsp), %rsi
    callq _main

    cmpl $42, %eax
    jne failed

    movabsq $0x02000004, %rax
    movabsq $1, %rdi
    leaq message(%rip), %rsi
    movabsq $message_length, %rdx
    syscall

    xorl %edi, %edi
    jmp exit

failed:
    movl $1, %edi

exit:
    movabsq $0x02000001, %rax
    syscall

message:
    .ascii "C main returned 42\n"
.set message_length, . - message
