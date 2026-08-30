# Host backend contract

Rosa's x86 frontend and Darwin compatibility layer should remain independent of the host instruction set. The current backend emits AArch64 for Apple Silicon, but the interfaces below define the boundary a future backend must preserve.

This is an architectural contract, not a promise that another backend is currently implemented.

## Pipeline ownership

The portable pipeline owns:

1. x86_64 instruction decoding;
2. construction and verification of Rosa IR;
3. explicit `X86State` layout and architectural semantics;
4. guest virtual-memory access through `AddressSpace`;
5. block dispatch, guest control flow, and translation-cache policy;
6. Mach-O loading and the Darwin BSD, Mach, and machdep boundary.

A host backend owns only:

1. lowering verified Rosa IR to a host-specific instruction stream;
2. host register allocation and calling-convention details;
3. branch relocation and executable-code materialization;
4. host instruction-cache synchronization and executable-memory policy;
5. entry from C++ into generated code and return of a `BlockExit` value.

The backend must not decode x86 instructions, reinterpret guest addresses, or issue Darwin operations directly.

## Generated block ABI

Every generated block receives the architectural state explicitly. Conceptually, its entry point is:

```cpp
BlockExit generated(X86State *state, GuestExecutionContext *context);
```

The concrete signature may be wrapped by `TranslatedBlock`, but the following properties are required:

- `X86State *` is the sole persistent home of guest registers, flags, RIP, segment bases, and XMM state across block boundaries.
- `GuestExecutionContext` carries narrow runtime services such as `AddressSpace` and the timestamp-counter reader. It is not guest architectural state.
- Generated code must obey the host ABI for stack alignment, callee-saved registers, and unwind across helper calls.
- No guest register may remain authoritative only in a host register when the block exits or invokes a helper that can observe state.
- A helper failure is reported through the execution context and a defined `BlockExit`; C++ exceptions never unwind through generated machine code.

A backend may keep temporary Rosa IR values in host registers within a block. It must commit architecturally visible state in the same order required by x86 fault and partial-register semantics.

## Guest memory

A backend must treat every guest address as an integer in Rosa's guest address space. It must never reinterpret a guest virtual address as a host pointer.

Generated loads, stores, atomics, string operations, stack operations, and instruction fetches must use one of two mechanisms:

- a backend-independent helper that calls `AddressSpace`; or
- a future validated fast path whose metadata and slow path are owned by `AddressSpace` and preserve identical permissions, sparse-data behavior, cross-mapping behavior, and fault reporting.

Direct host loads or stores are not permitted merely because a guest mapping currently has contiguous host backing.

Self-modifying code and writable executable mappings require explicit translated-block invalidation. A backend must not assume generated translations remain valid after guest writes or permission changes.

## Control flow and exits

A translated block must end at a boundary known to the portable dispatcher. The supported exit classes are represented by `BlockExit` and include ordinary continuation, call, return, syscall, and fault exits.

The backend must preserve these rules:

- Direct and conditional x86 targets are guest addresses, not host code pointers.
- An indirect target returns to the dispatcher unless a future block-linking layer validates and owns the link.
- Calls expose the guest return address as metadata so the dispatcher can perform the guest stack write transactionally.
- Returns read the target through `AddressSpace` before changing the guest stack pointer.
- An x86 `syscall` exits generated code. It is never lowered to a host `svc`, `syscall`, or equivalent instruction.
- Unsupported instructions stop translation with their guest RIP and encoding; they do not switch to an interpreter silently.

A future direct block-linking optimization must retain a way to invalidate links when guest code mappings or translations change.

## Rosa IR requirements

Backends consume only verified Rosa IR. A backend may reject an opcode it does not support, but must do so diagnostically before executing the block.

For each operation, a backend must preserve:

- declared integer width and truncation or extension behavior;
- partial-register and 32-bit zero-extension rules;
- the exact set of architecturally defined flags;
- preservation of undefined or unaffected state where the frontend requires it;
- memory-fault ordering relative to register and flag updates;
- XMM lane preservation and alignment checks;
- atomicity and ordering requirements of locked operations and fences.

Host condition flags are implementation details. They may be used transiently, but guest RFLAGS must remain explicit and correct at observable boundaries.

## Executable memory capability

Executable-code allocation is a backend capability with this logical lifecycle:

1. allocate writable storage of a checked, page-rounded size;
2. copy or emit the complete instruction stream;
3. resolve every relocation before publication;
4. synchronize the host instruction cache as required;
5. transition to the host's executable state;
6. publish an immutable entry point;
7. release the immutable allocation and free its arena mapping when the owning
   code cache dies.

The Apple Silicon implementation pools immutable translations in bump-allocated
`MAP_JIT` arenas and uses per-thread JIT write protection for each publication.
Persistent programs encode helper addresses as fixed-width relocatable
immediates. A cache load must validate its emitter fingerprint and guest source,
resolve every helper for the current ASLR slide, and only then batch-publish
the immutable programs.
Other hosts may use different mechanisms, but writable and executable
transitions must stay explicit. A backend must never publish a partially
relocated program.

## Backend interface direction

The current `Translator` combines portable lowering and AArch64 emission. A future extraction should proceed without changing semantics:

```text
x86 Decoder
    -> portable block builder
    -> verified Rosa IR
    -> HostBackend::compile(IR block)
    -> ExecutableBlock
```

A minimal backend interface should expose capabilities rather than host conditionals throughout the translator. Likely responsibilities include:

```cpp
class HostBackend {
  public:
    virtual ExecutableBlock compile(const ir::Block &) const = 0;
    virtual BackendCapabilities capabilities() const noexcept = 0;
};
```

`ExecutableBlock` should own code bytes, relocations already applied, executable storage, diagnostic listing, and immutable entry metadata. `BackendCapabilities` should describe semantic facilities such as atomic widths or executable-memory constraints; it must not be used to silently weaken guest behavior.

The extraction should keep the existing AArch64 path as the reference implementation and move one verified IR family at a time. Do not introduce an abstract backend layer that merely mirrors every AArch64 assembler method.

## Additional host architectures

### x86_64 host

An x86_64 backend can often emit guest-like instructions, but it still must use explicit `X86State`, guest memory, and Darwin emulation. Native execution of the guest Mach-O with `exec`, direct guest syscalls, or guest pointers is outside Rosa's model.

An x86_64 backend is useful as a second implementation for backend differential testing, not as permission to bypass the compatibility boundaries.

### RISC-V host

A future RV64 backend would need explicit support for x86 flags, unaligned memory semantics, 128-bit compare-exchange behavior, and host instruction-cache synchronization. Missing host primitives should lower through helpers rather than approximate x86 semantics.

### Portable verifier

A small IR evaluator may be useful as an independent test oracle for individual IR operations. It must remain a verification tool, not an automatic runtime fallback for unsupported production translations.

## Validation matrix

A backend change should be validated at four levels:

1. assembler or encoder tests for exact host instruction words and relocation ranges;
2. Rosa IR semantic cases against an independent x86 oracle where Rosetta is available;
3. dispatcher tests covering calls, returns, syscalls, faults, and cache reuse;
4. end-to-end controlled Mach-O fixtures.

Backend-specific executable-memory and calling-convention changes require execution on the corresponding host. Static review alone may establish invariants and overflow safety, but must not be reported as runtime verification.

## Non-goals

The backend abstraction must not:

- turn Rosa into a general-purpose CPU emulator with permissive fallback;
- expose host kernel ABI structs to guest code;
- merge guest and host address spaces;
- make host architecture visible to Mach-O or Darwin compatibility code;
- duplicate x86 decode or semantic logic independently in each backend;
- hide unsupported behavior behind host-native execution.
