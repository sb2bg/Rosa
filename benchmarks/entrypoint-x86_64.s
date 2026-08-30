.section __TEXT,__text,regular,pure_instructions
.globl _start
.p2align 4, 0x90
_start:
    movabsq $200000000, %rcx

loop:
    decq %rcx
    jne loop

    movabsq $0x02000001, %rax
    xorq %rdi, %rdi
    syscall
