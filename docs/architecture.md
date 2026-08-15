# Rosa architecture

This document describes code that exists now. Longer-term direction belongs in milestone planning until a vertical slice validates it.

## Implemented pipeline through controlled R4

```text
built-in bytes or controlled/universal x86_64 Mach-O
        ↓
bounded parsing + complete segment mapping + initial stack
        ↓
Rosa x86 decoder
        ↓
small typed SSA-like IR
        ↓
naive local value-to-register assignment
        ↓
custom AArch64 encoder
        ↓
MAP_JIT code buffer
        ↓
generated ARM64 mutates X86State and exits to dispatcher
        ↓
block cache + guest call/return stack handling
        ↓
semantic Darwin write/exit boundary for x86 syscall
```

The CPU path is a real DBT path, not an interpreter: data operations, arithmetic, compare results, and conditional selection become AArch64 instructions in generated code mappings. C++ helpers currently calculate x86 arithmetic flags, and the dispatcher handles cross-block `call`/`ret` effects.

## State boundaries

Guest architectural state is represented by `x86::X86State`. Generated blocks take an `X86State*` in host register `x0`. The R1 backend uses `x9`–`x15` as temporary value registers and writes guest values back explicitly. Guest register identities are translated through `registerOffset`; their enum encoding is never used as a host struct offset.

Every generated exit writes the next guest RIP or the address of a terminating guest `ret`. Direct and conditional branches select the next RIP in generated ARM64. The dispatcher handles `call` pushes and `ret` pops against the guest address space, so host return addresses never enter guest state.

Guest addresses use the `GuestAddress` strong type. The address space provides permission-checked anonymous and Mach-O segment mappings with a 4 KiB guest-page contract, byte copies, and explicit little-endian 64-bit accesses. Instruction fetches and syscall buffers come from those mappings; generated code does not treat guest virtual addresses as host pointers.

## Flags

`add r64, imm8` and `cmp r64, imm8` eagerly compute `CF`, `PF`, `AF`, `ZF`, `SF`, and `OF`. `and` clears `CF`/`OF` and computes `PF`/`ZF`/`SF` (Rosa deterministically clears the architecturally undefined `AF`). Results are generated ARM64. Narrow C++ helpers compute flags from inputs and results; generated blocks call them using the host ABI.

## Control flow and cache

The decoder ends blocks at `jmp`, `je`/`jne`, `call`, `ret`, or `syscall`. A cache owns one `MAP_JIT` translation per guest start RIP. Generated conditional exits test the stored x86 `ZF` with AArch64 test branches. The dispatcher has an explicit block limit and fetches only from executable guest mappings. The dyld experiment can deliberately cap translations at one guest instruction so a supported prefix executes before the next missing instruction is reported; this remains generated code, not interpretation.

## Mach-O boundary

The parser accepts little-endian, 64-bit x86 executables and dynamic linkers and extracts x86_64 slices from standard 32-bit or 64-bit universal containers. It bounds-checks the header, architecture table, complete load-command region, every command size, segment/section counts, file ranges, virtual ranges, and entry location. `LC_MAIN` is preferred; a correctly flavored x86_64 `LC_UNIXTHREAD` supplies the dyld entry.

The loader maps every nonempty segment at its guest virtual address plus an optional slide. File bytes are copied, the remaining virtual size is zero-filled, and `initprot` becomes guest permissions. No-access `__PAGEZERO` is represented sparsely. The startup builder creates a 16-byte-aligned stack containing `argc`, `argv`, `envp`, `apple[]`, their null terminators, and strings.

Rebasing, binding, chained fixups, shared-cache mapping, code signatures, and dyld's additional kernel contracts are not implemented.

## Darwin syscall boundary

Generated code recognizes x86 `0F 05`, records `RCX`, `R11`, and the next guest RIP, and returns a distinct syscall exit reason. The semantic dispatcher decodes x86 Darwin registers (`RAX`; arguments in `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`) and accepts only BSD-class `write` and `exit`. Guest buffers are copied through `AddressSpace`; no guest pointer is passed to the host kernel. Success/error translation maintains x86 `CF`. Unsupported numbers fail with the number, syscall RIP, and all six arguments.

## Executable memory

`ExecutableCode` allocates with Apple's `MAP_JIT`. Writes occur inside an explicit `pthread_jit_write_protect_np(0/1)` scope, followed by instruction-cache invalidation. The code is not modified after publication. The abstraction owns and unmaps the allocation with RAII.

## Current constraints

- arm64 macOS only;
- seven temporary SSA values before the intentionally simple allocator rejects a block;
- one host thread and one guest thread;
- no guest `mmap`/`mprotect`/`munmap` or generated data-load/store fast path;
- only Darwin BSD `write` to stdout/stderr and `exit`;
- no Mach syscall/trap boundary;
- no dyld fixups or shared cache;
- only the encodings listed in the README are accepted.

The current dyld experiment reaches `push imm8` at its entry stub after executing three translated instructions. The next slice should implement guest stack stores for `push` without conflating guest addresses with host pointers, then continue one failure at a time. Mach traps and shared-cache work should wait until an actual trace requires them.
