# Whack-a-Mole Through dyld: Bringing an Intel Darwin Process to Its Main Entrypoint on Apple Silicon

*August 30, 2026*

Today Rosa crossed the line I had been aiming at since the project began: an
unmodified Intel Darwin executable entered the real x86_64 dyld, initialized
against an intact Intel dyld shared cache, passed through more than twenty
cached system libraries, returned to application code, printed its message,
and exited successfully on an Apple Silicon host.

```text
hello from Intel Darwin
dyld experiment: app-entry=0x1000002f0 dyld-entry=0x7ff700004e50 \
  initial-rsp=0x7000000fff10 shared-cache=0x7ff800000000 slide=0x0
dyld experiment exited: status=0
```

No interpreter fallback carried it over the difficult parts. Rosetta was not
in the runtime path. The x86 instructions were decoded by Rosa, lowered through
Rosa's IR, emitted as AArch64, and executed against Rosa's explicit x86 machine
state. Darwin syscalls and Mach messages crossed semantic compatibility layers
rather than being renumbered and forwarded to the arm64 kernel.

One precision matters here. “Main entrypoint” means the application entry
selected by Mach-O's `LC_MAIN`. The tiny fixture defines that entry as `_start`
and makes direct Darwin `write` and `exit` syscalls; it does not contain a C
runtime that later calls a source-level `main()`. The milestone is that x86_64
dyld completed its work and handed control back to the executable's real
application entry. That is the boundary Rosa had never crossed before.

This post is the story of getting there.

## The starting point was already far from “hello world”

Rosa could already run the fixture directly. It could parse the x86_64 Mach-O,
map its segments, build a Darwin startup stack, translate two basic blocks, and
service its `write` and `exit` syscalls. That proved the smallest end-to-end
translation path, but carefully avoided the operating system's dynamic loader.

The dyld research path was different. It supplied a local x86_64 dyld and dyld
shared cache, mapped them without patching, and started at dyld's own entrypoint.
At the previous recorded milestone, that path had executed 1,079,752 guest
blocks and produced 24,954 translations. It had entered dyld-in-cache, but no
cached image other than dyld itself had executed. The next failure was an
unimplemented `fstatat64` structure copyout.

That was meaningful progress, but it was still on the loader side of the wall:

```text
x86_64 executable
        │
        ▼
standalone dyld → dyld in shared cache → load and initialize dependencies
                                                 │
                                                 ▼
                                      application LC_MAIN entry
```

Every arrow hides a large contract. dyld expects x86 instruction semantics,
Mach-O metadata, a 4 KiB guest memory model, the x86 commpage, Mach ports, MIG
message layouts, BSD structures, filesystem identity, code-signing policy,
process metadata, and dozens of small Darwin conventions to agree at once.

The only practical way through was controlled whack-a-mole.

## The loop: fail loudly, implement narrowly, repeat

Rosa intentionally has no “close enough” fallback for an unknown instruction or
Darwin operation. It stops and reports the guest state instead. A typical
failure includes:

- the guest RIP and instruction bytes;
- the containing shared-cache image;
- general registers, flags, GS base, and stack state;
- nearby mappings and recent guest instructions;
- execution and translation counters;
- the guest Mach-port namespace; and
- the set of shared-cache images that have executed.

That diagnostic turns an enormous compatibility problem into a sequence of
bounded questions. For each failure I used the same loop:

1. Reproduce the stop at the same guest RIP.
2. Decode the exact instruction or ABI request that dyld made.
3. Determine its architectural and Darwin semantics.
4. Implement only the justified form, preserving guest/host separation.
5. Add success, boundary, and fault-atomicity tests.
6. Run the complete suite.
7. Start dyld again and meet the next mole.

Narrow support is a feature here. If the trace exercises one RIP-relative SIMD
load, implementing that encoding correctly is safer than claiming an entire
instruction family. Unsupported neighbors continue to fail loudly.

This approach also gives each step a concrete reason to exist. The decoder did
not grow from a checklist. It grew from captured instructions in real system
software, backed by focused execution tests and, where applicable, comparisons
with an independent x86_64 oracle.

## The loader did not need one big fix

There was no single missing “run libSystem” function. Progress required work
across every major layer of Rosa.

### Guest memory and Mach-O state

dyld constantly maps, protects, unmaps, and inspects address ranges. Those
operations must preserve a guest view rather than leaking host virtual-memory
assumptions. The bring-up expanded shared-cache metadata, Mach-O image
information, mapping transformations, and invalidation of translated blocks
when executable guest memory changed.

The rule stayed simple even when the implementation did not: a guest virtual
address is never a host pointer.

### The Darwin BSD boundary

The dynamic loader and system libraries needed a much wider semantic syscall
surface: filesystem metadata and enumeration, synthetic root and cryptex paths,
process information, code-signing queries, entropy, memory operations, and
multiple `sysctl` forms.

These could not be implemented by passing x86 syscall numbers or structures to
the arm64 host. Rosa had to decode the x86 ABI, validate guest buffers, obtain or
synthesize the appropriate information, and encode the result back into the
guest layout.

Fault behavior mattered as much as successful behavior. If a copyout crossed a
read-only or unmapped page, the operation had to return the right failure
without partially changing guest memory or committing related process state.

### Mach messages and the guest port namespace

System initialization also exercised task, host, clock, semaphore, and port
operations. Rosa models these as guest rights with guest names and reference
counts. Host Mach port identities do not escape into the x86 process.

The later trace required exact MIG request and reply layouts for operations such
as task information and special ports. Message size, descriptor disposition,
reply ID, NDR record, trailer, receive capacity, and copyout ordering all had to
match the observed ABI. A writable-buffer fault could not leave a new special
port installed or consume a right prematurely.

### The x86 translator

Finally, every newly reached library brought its own instruction vocabulary.
The work covered integer, flag, memory, atomic, control-flow, and SIMD forms.
Memory forms were particularly important: based addressing was not enough once
position-independent system libraries began using RIP-relative globals and
constant tables everywhere.

The translator retained its core contract throughout:

```text
x86 bytes → decoded instruction → typed Rosa IR → generated AArch64
```

Generated helpers receive explicit guest state. Memory helpers use the guest
address space and report faults back to the dispatcher. Legacy XMM instructions
preserve the upper YMM state where the architecture requires it. Flags are
changed only when the x86 instruction defines them.

## The final chain was a miniature version of the whole project

The last stretch began with a request for the private-looking sysctl name
`kern.osvariant_status`. Darwin first asked the `CTL_SYSCTL/NAME2OID` path to
translate the name, then queried MIB `{1, 141}` for an opaque 8-byte value.

Rosa now resolves that name through the same two-stage flow and mirrors the host
status bytes into controlled guest memory. It supports a size query, rejects a
short buffer with the observed behavior, and leaves output untouched on a
fault.

Returning the value did not finish the job. `libsystem_darwin` immediately used
a compact SIMD sequence to unpack it:

```asm
movq       xmm0, rax
pshufd     xmm1, xmm0, 0x44
movdqa     xmm2, xmm0
psrlq      xmm2, 32
movdqa     xmm3, xmm1
psrlq      xmm3, 33
pblendw    xmm3, xmm2, 0x0f
psrlq      xmm0, 34
psrlq      xmm1, 35
pblendw    xmm1, xmm0, 0x0f
movd       xmm0, dword [rip+constant]
pshufb     xmm1, xmm0
pshufb     xmm3, xmm0
punpcklwd  xmm3, xmm1
pand       xmm3, [rip+mask]
movd       dword [rip+global], xmm3
```

That one status word exposed five separate gaps in succession:

- `PSRLQ xmm, imm8`, including counts 32–35 and architectural zeroing at 64;
- RIP-relative `MOVD xmm, m32`;
- `PUNPCKLWD xmm, xmm`, including aliased operands;
- RIP-relative `MOVD m32, xmm`; and
- the surrounding RIP-relative SIMD memory behavior.

Each was implemented and tested, then the trace moved one instruction farther.
The sequence eventually completed, wrote the reconstructed variant state to its
global, and escaped `libsystem_darwin` initialization.

The penultimate failure appeared much later in `libobjc.A.dylib`:

```asm
not   r15b
or    r15b, byte [rip+0x40c73921]
```

Rosa already supported byte OR from based guest memory. It did not support this
RIP-relative form with an extended low-byte destination. Adding it required
correct next-RIP address calculation, preservation of the upper 56 bits of
`R15`, exact logic flags, and a test proving that an unmapped load left both the
register and flags unchanged.

That was the last mole.

The next run printed the fixture's message and exited zero.

## What the successful handoff proves

At the last diagnostic stop before success, Rosa had executed 3,546,716 guest
blocks and created 61,826 translations. The trace showed execution in more than
twenty shared-cache images, including dyld, libSystem, libsystem_kernel,
libsystem_pthread, libsystem_c, libdispatch, libobjc, libc++abi, libxpc,
libsystem_trace, libsystem_secinit, and libsystem_darwin.

Reaching the application entry proves that one coherent vertical slice now
works across:

- x86_64 Mach-O and dyld startup state;
- intact Intel shared-cache mapping and image traversal;
- dynamic dependency loading and system-library initialization;
- generated AArch64 execution of the observed x86 instruction set;
- explicit x86 GPR, flag, XMM, YMM, GS, and control-flow state;
- guest memory permissions and transactional faults;
- BSD syscalls and x86 Darwin structures;
- Mach traps, MIG messages, and guest-only port rights; and
- transfer from the loader back to the executable's `LC_MAIN` entry.

The implementation landed as commit `0357a2e`, touching 28 files. The raw diff
was 28,060 insertions and 3,562 deletions, with a large fraction devoted to
focused tests. Line count is not the achievement; the meaningful result is that
all of those contracts agreed long enough for real x86 system software to
complete initialization.

The standard debug suite passed. The UndefinedBehaviorSanitizer and
AddressSanitizer suites passed as well, and the complete dyld/shared-cache run
reached the application entry and exited zero under both sanitizers.

## What it does not prove

This is a foundation, not a declaration of general compatibility.

The fixture is deliberately tiny once dyld hands over control. Arbitrary Intel
applications will immediately explore instructions, syscalls, messages, loader
features, and error paths that Rosa does not implement. Major remaining areas
include:

- broader x86_64 and SIMD coverage;
- multiple guest threads and processes;
- signals, exceptions, and debugger interactions;
- a much larger Darwin syscall and Mach surface;
- complete filesystem and code-signing behavior;
- cache and OS-version portability;
- performance work beyond correctness-first execution; and
- real application and framework compatibility testing.

There is also no interpreter safety net. That makes early compatibility grow
more slowly, but it keeps the claim honest: supported code runs through the DBT,
and unsupported code identifies the next boundary.

## Why this milestone changes the project

Before this run, Rosa had working parts and an increasingly deep loader trace.
Now it has proof that those parts can form a complete loop:

```text
application → dyld → shared-cache system libraries → application
```

That changes the character of future work. The question is no longer whether
the architecture can carry an Intel Darwin process through the loader. It did.
The question is how quickly and carefully the successful vertical slice can be
widened.

The debugging method also earned its keep. The final breakthrough did not come
from replacing the design or adding a permissive fallback. It came from making
each failure precise enough to solve, preserving the compatibility boundaries,
and repeating the loop until dyld ran out of reasons to stop.

Whack-a-mole is usually a criticism of debugging. For compatibility work, with
strong diagnostics and regression tests, it can be a development strategy.

Rosa drove around the block. Now the road gets interesting.

---

For implementation context, see Rosa's [architecture](../architecture.md),
[guest-memory model](../guest-memory.md), and
[Darwin boundary](../darwin-boundary.md).
