# Rosa architecture

This document describes the code as it exists. Planned work belongs in [milestones.md](milestones.md) until a tested slice lands.

## Pipeline

```text
built-in bytes, x86_64 Mach-O, or x86_64 dyld
        ↓
bounded Mach-O parsing + segment mapping + initial stack
        ↓
instruction decode + bounded block formation
        ↓
x86 lowering to typed SSA-like IR
        ↓
shared IR optimization (guest-register forwarding)
        ↓
register allocation + AArch64 emission (custom encoder)
        ↓
pooled MAP_JIT code arena
        ↓
generated AArch64 and narrow helpers update X86State
        ↓
dispatcher: block cache, guest call/return, next block or Darwin boundary
```

Translated code does the real work: data movement, arithmetic, comparisons, address computation, and conditional selection become AArch64 instructions. Narrow C++ helpers compute some flags, perform permission-checked guest-memory accesses, and implement a few operations that must commit atomically. The dispatcher handles control flow between blocks. There is no interpreter.

## State boundaries

Guest architectural state lives in `x86::X86State`: general-purpose registers, RIP, RFLAGS, segment bases, and 128-bit XMM registers. Generated blocks receive an `X86State*` in `x0`. The baseline backend uses `x8`–`x15` for temporaries and writes guest values back explicitly. Guest register identities map to struct offsets through `registerOffset`; their enum encoding is never used as an offset.

Every block exit leaves guest state consistent and writes the next guest RIP. Direct, conditional, and indirect branches select a guest RIP and never branch to a guest address as a host pointer. The dispatcher performs guest `call` pushes and `ret` pops in guest memory, so host return addresses never enter guest state.

Guest addresses use the `GuestAddress` strong type and are never reinterpreted as host pointers. See [guest-memory.md](guest-memory.md) for the address-space model and its fast paths.

Per-process Darwin state lives in `darwin::GuestTask`:

- `GuestPortSpace` holds guest Mach names: receive, send, and send-once rights, urefs, queue limits, contexts, guards, and synthetic task, host, thread, and reply objects. Host `mach_port_t` values never enter it.
- `GuestFileSpace` is the descriptor table: lowest-free numbering over shared open file descriptions, some backed by host fds and some synthetic. See [darwin-boundary.md](darwin-boundary.md#descriptors-and-paths).
- Signal dispositions and dyld image registration are recorded without host side effects.

## Flags

Arithmetic and comparison forms compute `CF`, `PF`, `AF`, `ZF`, `SF`, and `OF` at the operation width. Logic forms clear `CF`/`OF`, compute `PF`/`ZF`/`SF`, and clear the undefined `AF`. `inc`/`dec` preserve `CF`. Signed `imul` sets only its defined `CF`/`OF`. Flag computation may be deferred within a block, but flags are materialized before any exit or helper that can observe them.

## Blocks and the translation cache

The decoder ends a block at a jump, conditional branch, call, return, or syscall. The dyld path also caps blocks at 32 instructions: long enough to amortize dispatch, short enough that an unsupported-instruction diagnostic points at a small region. Controlled fixtures have no cap.

The block cache holds one immutable translation per guest start RIP. Conditional exits test stored x86 flag bits with AArch64 test-and-branch instructions. The dispatcher fetches only from executable guest mappings and enforces an optional block limit. A block that branches back to itself can run repeatedly inside generated code before returning to the dispatcher.

A guest write to executable memory bumps the address space's executable version and stops a running batch. The next lookup of a block from an older version compares its saved x86 source bytes with guest memory and retranslates if they differ.

## Persistent translation cache

`--translation-cache` stores source bytes, generated AArch64, block-exit metadata, and fixed-width helper-address relocations. On load:

1. the file's fingerprint must match the running build;
2. each entry's x86 source bytes must match guest memory;
3. helper addresses are relocated for the current ASLR slide;
4. all programs are copied into the arena and published in one JIT write and instruction-cache transaction.

The fingerprint is the linker UUID of the image containing the runtime helpers. It changes whenever lowering, optimization, emission, or helper code changes and stays stable across ASLR slides. Without a usable UUID, persistence is disabled. Decoded x86 and IR are reconstructed from the source bytes only when a dump or the optimizing tier needs them.

## Optimizing tier

When built with Homebrew LLVM, CMake reports `Rosa LLVM optimizing JIT`. A self-loop block becomes a promotion candidate after 1,024 executions if it is register-only, or after 100 million if it touches memory, and only when at least ten million dispatcher executions remain in the block budget.

The tier keeps guest registers in LLVM SSA, materializes x86 flags only at the side exit, and compiles at `-O2` through ORC. Memory loops are accepted only for anonymous byte reads and writes whose whole invocation range is proven in bounds before LLVM receives a host span. Executable, file-backed, wrapping, and faulting cases stay on the baseline. The high memory-loop threshold exists because ORC compilation costs about 29 ms for the prime-sieve loops, more than the roughly 8 ms it saves on that benchmark.

`-DROSA_ENABLE_LLVM_JIT=OFF` (or the `baseline` preset) builds without the tier.

## Mach-O and the shared cache

The parser accepts little-endian 64-bit x86 executables and dynamic linkers, including x86_64 slices of 32- and 64-bit universal files. It bounds-checks the header, architecture table, load-command region, every command size, segment and section counts, file and virtual ranges, and the entry point. `LC_MAIN` is preferred; dyld's entry comes from an x86_64 `LC_UNIXTHREAD`.

The loader maps every nonempty segment at its virtual address plus an optional slide, copies file bytes, zero-fills the rest, and converts `initprot` into guest permissions. `__PAGEZERO` is a sparse no-access mapping. The startup builder writes a 16-byte-aligned stack with `argc`, `argv`, `envp`, `apple[]`, their terminators, and their strings.

Rosa leaves application and cache structure interpretation to the guest's own dyld. A supplied Intel shared cache is validated along with all of its subcaches, mapped as private file-backed guest regions at slide zero, and accompanied by a dynamic-data page. Version-2 chained fixups are applied lazily, one 4 KiB guest page at a time on first access. `shared_region_check_np` returns the guest cache base; no cache pointer reaches the host kernel.

Fatal diagnostics resolve the faulting PC to its cache image index, UUID, and path, and list every cache image executed so far, recent instructions, registers, nearby mappings, translation counts, hot blocks, and the guest port namespace.

## Darwin syscall boundary

Generated code treats `0F 05` as a block terminator: it records `RCX`, `R11`, and the next RIP and exits with a syscall reason. The dispatcher decodes the x86_64 Darwin convention (`RAX` for the number; `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9` for arguments) and routes BSD, Mach, and machdep calls to their handlers. Guest buffers are copied through the address space. BSD results use the carry-flag convention; Mach traps return `kern_return_t` in `RAX`. Unsupported calls stop with the number, RIP, and arguments. [darwin-boundary.md](darwin-boundary.md) lists what is implemented.

## Executable memory

`ExecutableArena` allocates 16 MiB `MAP_JIT` chunks and bump-allocates immutable translations inside them. Each publication happens inside an explicit `pthread_jit_write_protect_np` scope followed by instruction-cache invalidation. `ExecutableCode` keeps its arena alive; the arena unmaps its chunks after the last block that uses them is released. One-off generated functions use a page-sized arena instead of a full chunk.

## Current constraints

- arm64 macOS hosts only.
- One host thread and one guest thread.
- The baseline register allocator rejects a block that needs more than eight live temporaries.
- No general guest `mmap`, no identity mapping, no unchecked host-pointer memory path. Observed BSD `mmap`, `munmap`, `mprotect`, and Mach VM calls operate on guest mappings.
- Only the BSD, Mach, and machdep operations in [darwin-boundary.md](darwin-boundary.md).
- Only version-2 x86 shared-cache slide fixups; no general Mach-O bind/rebase engine.
- Instruction encodings are added when a real program needs them, not in bulk.
