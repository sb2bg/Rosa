# Contributing to Rosa

Rosa is a compatibility runtime, so a change is complete only when it preserves the semantics at every boundary it crosses. Small, explicit vertical slices are preferred over broad instruction or ABI coverage that silently falls back to a different execution model.

## Architecture invariants

These constraints are part of Rosa's design, not implementation details:

- Guest virtual addresses are values in Rosa's address-space model. Never reinterpret a guest address as a host pointer.
- Generated code receives an explicit `X86State *`. Architectural guest state must not be hidden in host thread-local state or host registers across dispatch boundaries.
- x86 system calls and Mach traps cross a semantic compatibility boundary. Do not translate an x86 `syscall` into a host AArch64 `svc`, and do not pass guest structs directly to host kernel APIs.
- Supported x86 instructions execute as generated AArch64. Do not add an implicit interpreter fallback for unsupported encodings.
- Unsupported instructions, load commands, traps, and syscalls must fail diagnostically rather than approximate semantics.
- The runtime must not depend on Rosetta 2. Rosetta is permitted only as an independent differential-test oracle.
- Apple binaries, dyld shared caches, and other locally provisioned proprietary artifacts must never be committed.

## Preferred development workflow

1. Start from a controlled fixture, a differential case, or a captured real-program failure.
2. Identify the narrowest missing boundary: decode, IR, emission, guest memory, Mach-O, Darwin ABI, or dispatch.
3. Implement the complete vertical slice for that behavior.
4. Preserve useful failure information at the next unsupported boundary.
5. Add or update verification notes when the supported surface changes.

Avoid adding speculative instruction families in bulk. Encoding-specific support makes failures attributable and keeps prefix, width, and flag behavior reviewable.

## Adding an x86 instruction

An instruction change should account explicitly for:

- opcode map, prefixes, REX behavior, ModRM/SIB forms, and immediate width;
- operand-size and address-size behavior;
- partial-register writes, zero-extension, and high-byte register restrictions;
- effective-address calculation and guest-memory fault ordering;
- every architecturally defined flag, while avoiding assertions about undefined flags;
- control-flow termination and the next guest RIP;
- scalar or SIMD lane width and preservation of unaffected lanes.

Prefer lowering through the typed IR. Direct emitter special cases should be reserved for behavior that cannot be represented cleanly in the IR, and the reason should be documented.

For differential tests, compare only architecturally defined state. A host-oracle disagreement involving undefined flags is not evidence that either implementation is wrong.

## Guest memory and executable code

All guest accesses must go through `AddressSpace` or a deliberately narrow helper owned by it. Multi-mapping reads and writes must validate the full operation before mutating guest state when partial completion would be architecturally incorrect.

Keep writable and executable host-memory transitions explicit. Changes around `MAP_JIT`, JIT write protection, instruction-cache invalidation, or generated-code lifetime require an Apple Silicon runtime validation before being described as verified.

## Darwin compatibility

Model Darwin behavior in guest terms:

- Decode guest syscall and trap arguments from `X86State`.
- Copy guest data through `AddressSpace`; do not expose host pointers.
- Use guest-layout structs with explicit sizes and fields.
- Preserve the distinction between BSD errors (return value plus carry flag) and Mach return codes.
- Keep guest process, thread, port, and file identities separate from host identities unless the equivalence is intentional and documented.
- Treat malformed Mach-O and shared-cache metadata as untrusted input and validate ranges before allocation, mapping, or pointer arithmetic.

## Performance changes

The dispatcher, translated-block lookup, guest-memory lookup, generated memory helpers, and code cache are hot paths. Prefer moving work from repeated dispatch into translation or mapping setup while retaining deterministic diagnostics.

Do not trade correctness or observable failure behavior for speed. A performance commit should state which repeated operation it removes or reduces. Benchmark claims require measurements on Apple Silicon; otherwise describe only the structural change.

## Validation levels

Use the strongest validation available for the change:

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

When relevant, also run the UBSan preset and the Rosetta differential suite. Shared-cache or dyld changes should be exercised with developer-supplied compatible artifacts that remain outside the repository.

Some changes can be reviewed statically but still require runtime validation. Commit messages and pull-request descriptions should say plainly when a change was not built or executed.

## Commit discipline

Keep commits narrow and independently reviewable. Separate cleanup, correctness, performance, instruction coverage, and documentation changes. A useful commit message names the boundary and the behavior, for example:

- `fix: reject overflowing Mach-O segment ranges`
- `perf: index translated blocks by guest RIP`
- `x86: lower 64-bit ADC register forms`

Do not combine generated artifacts, local caches, or unrelated formatting with semantic changes.
