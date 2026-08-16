#define ROSA_DIFFERENTIAL_CASE(name, ...) \
    .globl _rosa_oracle_case_##name ;     \
    .p2align 4 ;                          \
_rosa_oracle_case_##name: ;               \
    .byte __VA_ARGS__ ;                   \
    ret

.text
#include "Cases.def"
#undef ROSA_DIFFERENTIAL_CASE

.globl _rosa_oracle_run
.p2align 4
_rosa_oracle_run:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, _rosa_oracle_host_rsp(%rip)
    movq %rdi, _rosa_oracle_function(%rip)

    movq _rosa_oracle_input+56(%rip), %rax
    leaq Lcapture(%rip), %rcx
    movq %rcx, (%rax)

    pushq _rosa_oracle_input+136(%rip)
    popfq
    movdqu _rosa_oracle_input+144(%rip), %xmm0
    movdqu _rosa_oracle_input+160(%rip), %xmm1
    movdqu _rosa_oracle_input+176(%rip), %xmm2
    movdqu _rosa_oracle_input+192(%rip), %xmm3
    movdqu _rosa_oracle_input+208(%rip), %xmm4
    movdqu _rosa_oracle_input+224(%rip), %xmm5
    movdqu _rosa_oracle_input+240(%rip), %xmm6
    movdqu _rosa_oracle_input+256(%rip), %xmm7
    movdqu _rosa_oracle_input+272(%rip), %xmm8
    movdqu _rosa_oracle_input+288(%rip), %xmm9
    movdqu _rosa_oracle_input+304(%rip), %xmm10
    movdqu _rosa_oracle_input+320(%rip), %xmm11
    movdqu _rosa_oracle_input+336(%rip), %xmm12
    movdqu _rosa_oracle_input+352(%rip), %xmm13
    movdqu _rosa_oracle_input+368(%rip), %xmm14
    movdqu _rosa_oracle_input+384(%rip), %xmm15

    movq _rosa_oracle_input+0(%rip), %rax
    movq _rosa_oracle_input+8(%rip), %rbx
    movq _rosa_oracle_input+16(%rip), %rcx
    movq _rosa_oracle_input+24(%rip), %rdx
    movq _rosa_oracle_input+32(%rip), %rsi
    movq _rosa_oracle_input+40(%rip), %rdi
    movq _rosa_oracle_input+48(%rip), %rbp
    movq _rosa_oracle_input+64(%rip), %r8
    movq _rosa_oracle_input+72(%rip), %r9
    movq _rosa_oracle_input+80(%rip), %r10
    movq _rosa_oracle_input+88(%rip), %r11
    movq _rosa_oracle_input+96(%rip), %r12
    movq _rosa_oracle_input+104(%rip), %r13
    movq _rosa_oracle_input+112(%rip), %r14
    movq _rosa_oracle_input+120(%rip), %r15
    movq _rosa_oracle_input+56(%rip), %rsp
    jmpq *_rosa_oracle_function(%rip)

Lcapture:
    movq %rax, _rosa_oracle_output+0(%rip)
    movq %rbx, _rosa_oracle_output+8(%rip)
    movq %rcx, _rosa_oracle_output+16(%rip)
    movq %rdx, _rosa_oracle_output+24(%rip)
    movq %rsi, _rosa_oracle_output+32(%rip)
    movq %rdi, _rosa_oracle_output+40(%rip)
    movq %rbp, _rosa_oracle_output+48(%rip)
    movq %rsp, _rosa_oracle_output+56(%rip)
    movq %r8, _rosa_oracle_output+64(%rip)
    movq %r9, _rosa_oracle_output+72(%rip)
    movq %r10, _rosa_oracle_output+80(%rip)
    movq %r11, _rosa_oracle_output+88(%rip)
    movq %r12, _rosa_oracle_output+96(%rip)
    movq %r13, _rosa_oracle_output+104(%rip)
    movq %r14, _rosa_oracle_output+112(%rip)
    movq %r15, _rosa_oracle_output+120(%rip)
    pushfq
    popq _rosa_oracle_output+136(%rip)
    cld
    movdqu %xmm0, _rosa_oracle_output+144(%rip)
    movdqu %xmm1, _rosa_oracle_output+160(%rip)
    movdqu %xmm2, _rosa_oracle_output+176(%rip)
    movdqu %xmm3, _rosa_oracle_output+192(%rip)
    movdqu %xmm4, _rosa_oracle_output+208(%rip)
    movdqu %xmm5, _rosa_oracle_output+224(%rip)
    movdqu %xmm6, _rosa_oracle_output+240(%rip)
    movdqu %xmm7, _rosa_oracle_output+256(%rip)
    movdqu %xmm8, _rosa_oracle_output+272(%rip)
    movdqu %xmm9, _rosa_oracle_output+288(%rip)
    movdqu %xmm10, _rosa_oracle_output+304(%rip)
    movdqu %xmm11, _rosa_oracle_output+320(%rip)
    movdqu %xmm12, _rosa_oracle_output+336(%rip)
    movdqu %xmm13, _rosa_oracle_output+352(%rip)
    movdqu %xmm14, _rosa_oracle_output+368(%rip)
    movdqu %xmm15, _rosa_oracle_output+384(%rip)

    movq _rosa_oracle_host_rsp(%rip), %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
