# Rosa architecture

This document describes code that exists now. Longer-term direction belongs in milestone planning until a vertical slice validates it.

## Implemented pipeline through controlled R4 and the R5 probe

```text
built-in bytes, controlled x86_64 Mach-O, or x86_64 dyld slice
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
pooled MAP_JIT code arena
        ↓
generated ARM64 and narrow semantic helpers mutate X86State
        ↓
block cache + guest call/return stack handling
        ↓
semantic Darwin/Mach boundary or next guest block
```

The CPU path is a real DBT path, not an interpreter: data operations, arithmetic, compare results, address construction, and conditional selection become AArch64 instructions in generated code mappings. Narrow C++ helpers calculate flags, perform permission-checked guest-memory accesses, and implement a few state operations that must commit atomically. The dispatcher handles cross-block guest control flow.

## State boundaries

Guest architectural state is represented by `x86::X86State`, including all general-purpose registers, RIP, RFLAGS, and explicit 128-bit XMM values. Generated blocks take an `X86State*` in host register `x0`. The first-tier backend uses `x8`–`x15` as temporary value registers and writes guest values back explicitly. Guest register identities are translated through `registerOffset`; their enum encoding is never used as a host struct offset.

Every generated exit reconstructs guest state and writes the next guest RIP. Direct, conditional, and register-indirect branches select a guest RIP; they never branch to a guest address as a host pointer. The dispatcher handles guest `call` pushes and `ret` pops against the guest address space, so host return addresses never enter guest state.

Guest addresses use the `GuestAddress` strong type. The address space provides permission-checked anonymous, sparse, commpage, and Mach-O segment mappings with a 4 KiB guest-page contract. Generated helpers cover guarded 8/16/32/64-bit integer and 128-bit XMM accesses. Repeated byte loops may cache a checked anonymous mapping as a host span, coalesce checks for adjacent loads, and elide per-iteration checks for monotonic read or write spans only after a runtime guard proves exact termination and the complete remaining range; executable and file-backed mappings stay on the helper path. Instruction fetches and syscall buffers come from the mapping model, and no guest virtual address is directly reinterpreted as a host pointer.

Guest Mach names live in a task-local `GuestPortSpace`. It records receive, send, and send-once rights, urefs, queue limits, contexts, guards, and synthetic task/host/reply object types without ever reusing a host `mach_port_t`. Guest file descriptors likewise live in a task-local `GuestFileSpace`; duplicated descriptors retain a shared open-description identity. The current root and cryptex-directory capabilities are synthetic guest VFS objects, not host descriptors.

## Flags

Observed 8/16/32/64-bit arithmetic and comparison forms eagerly compute `CF`, `PF`, `AF`, `ZF`, `SF`, and `OF` at the guest width. Logic forms clear `CF`/`OF` and compute `PF`/`ZF`/`SF`; Rosa deterministically clears undefined `AF`. `inc`/`dec` preserve `CF`. Signed `imul` replaces only its defined `CF`/`OF` and preserves other undefined flag bits. Narrow C++ helpers receive generated values through the host ABI.

## Control flow and cache

The decoder ends blocks at direct/indirect transfers, conditional branches,
calls, returns, or syscalls. A cache owns one immutable translation per guest
start RIP. Generated conditional exits test the relevant stored x86 flag bits
with AArch64 test branches. The dispatcher has an explicit block limit and
fetches only from executable guest mappings. The dyld path caps straight-line
translations at 16 guest instructions: control-flow boundaries usually end
them earlier, while the cap keeps unsupported-instruction diagnostics
attributable without paying a dispatch and cache entry per instruction.

An opt-in persistent cache stores source bytes, immutable generated AArch64,
block-exit metadata, and fixed-width helper-pointer relocations. Its build
fingerprint rejects incompatible emitters. On a hit, source bytes are checked
before execution, helper pointers are adjusted for the current ASLR slide, all
cached programs are published as one JIT batch, and decoded x86 metadata is
reconstructed only if diagnostics request it. Writable executable mappings
still use the in-process source/version invalidation path.

## Mach-O boundary

The parser accepts little-endian, 64-bit x86 executables and dynamic linkers and extracts x86_64 slices from standard 32-bit or 64-bit universal containers. It bounds-checks the header, architecture table, complete load-command region, every command size, segment/section counts, file ranges, virtual ranges, and entry location. `LC_MAIN` is preferred; a correctly flavored x86_64 `LC_UNIXTHREAD` supplies the dyld entry.

The loader maps every nonempty segment at its guest virtual address plus an optional slide. File bytes are copied, the remaining virtual size is zero-filled, and `initprot` becomes guest permissions. No-access `__PAGEZERO` is represented sparsely. The startup builder creates a 16-byte-aligned stack containing `argc`, `argv`, `envp`, `apple[]`, their null terminators, and strings.

Rosa relies on dyld guest code to interpret application and cache structures. A manually supplied Intel shared cache is validated with all declared subcaches, mapped as private file-backed guest regions at slide zero, and accompanied by a guest dynamic-data page. Version-2 chained fixups are applied once per 4 KiB guest page on first access rather than eagerly rewriting the entire cache. `shared_region_check_np` returns its guest base; no cache pointer is passed to the host kernel.

Parsed cache image metadata resolves an executed guest PC to cache image index, UUID, and path. Fatal diagnostics include that provenance, recent guest instructions, registers, mappings, translation counts, hot blocks, and the guest Mach-port summary. This has verified execution in cache image 2, `/usr/lib/dyld`; it has not yet observed execution in another cached image.

## Darwin syscall boundary

Generated code recognizes x86 `0F 05`, records `RCX`, `R11`, and the next guest RIP, and returns a distinct syscall exit reason. The semantic dispatcher decodes x86 Darwin registers (`RAX`; arguments in `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`) and distinguishes BSD, Mach, and x86 machdep classes. Guest buffers and ABI values are translated through `AddressSpace`; no guest pointer is passed to the host kernel. Success/error translation follows the relevant guest convention. Unsupported calls fail with the number, syscall RIP, and arguments. The exact narrow call set is documented in `darwin-boundary.md`.

## Executable memory

`ExecutableArena` allocates 16 MiB chunks with Apple's `MAP_JIT` and bump
allocates aligned immutable translations inside them. Each publication occurs
inside an explicit `pthread_jit_write_protect_np(0/1)` scope and is followed by
instruction-cache invalidation. An `ExecutableCode` keeps the shared arena
alive; the arena unmaps its chunks with RAII after the last translated block
releases them. A one-off generated function uses the same abstraction with a
page-sized arena rather than reserving a full chunk. Persistent-cache programs
are copied together and invalidate each contiguous arena range once.

## Current constraints

- arm64 macOS only;
- eight temporary SSA values before the intentionally simple allocator rejects a block;
- one host thread and one guest thread;
- no general guest `mmap`, identity map, or unchecked host-pointer memory path; the observed BSD `munmap` and Mach VM operations are semantic guest-map operations;
- only the failure-driven BSD, Mach, VFS, and x86 machdep operations listed in `darwin-boundary.md`;
- only version-2 x86 shared-cache slide fixups; no general Mach-O binding/rebase engine;
- instruction encodings remain deliberately incomplete and are added only after an observed failure.

On the tested userspace, the ordinary C fixture completes through dyld,
21 shared-cache images, libSystem initialization, libc `printf`, return from
`main`, and guest exit. With 32-instruction translation bounds it executes
about 784,000 blocks, creates about 12,847 translations, and consumes about
3.97 MiB in one JIT arena mapping. Unsupported instructions and Darwin
operations still fail with their precise guest address and diagnostic state.

The scalar prime-sieve fixture uses the same dynamic path and executes about
25.3 million blocks. Internal self-edge batching keeps repeated baseline blocks
inside generated code. A checked first byte access can install an anonymous
mapping window; adjacent loads share range guards, while monotonic read and
write loops may reuse a host pointer only after a runtime guard proves exact
termination, positive nonwrapping stride, and complete mapping containment. The
LLVM tier accepts narrow read-only exact-stride and write-only unsigned-below
forms after performing the same whole-invocation proof. It keeps mixed-width
guest values and intermediate conditions in SSA and falls back to the baseline
before executing when a direct anonymous view cannot be proven. Persistent
blocks rebuild omitted IR only after a self-loop becomes hot. On the M1 Pro
development host, 61 alternating warm process trials put the same scalar
x86_64 binary at a 24.4 ms Rosetta median and a 65.0 ms baseline Rosa median, a
2.7x gap rather than the earlier 21.0x. Forced LLVM promotion saved about 8 ms
inside the traces but cost about 29 ms to compile, so the production memory-tier
threshold is 100 million observed executions and this benchmark stays baseline.
