# Guest memory

`guest::AddressSpace` gives the guest 4 KiB pages, independent of the host's 16 KiB pages. Every guest access goes through it, and a `GuestAddress` is never reinterpreted as a host pointer.

## Mappings

- Page-aligned anonymous mappings.
- Private file-backed mappings, used for the shared cache and its subcaches. Guest writes stay private to Rosa.
- Mach-O segments with file bytes and zero-filled tails.
- Sparse no-access mappings such as the 4 GiB `__PAGEZERO`.
- A sparse read-only x86 commpage.

Mapping requests that overlap an existing mapping or overflow the address range are rejected. Each mapping carries read, write, and execute permissions plus a maximum protection. Protect and deallocate operations round to pages, split mappings as needed, and implement `VM_PROT_COPY`.

On the tested host, the x86_64 shared cache is seven files mapped as 28 guest mappings at slide zero.

## Accesses

- Byte copies may cross mappings and are bounds-checked as a whole.
- Generated code uses checked little-endian 8/16/32/64-bit loads and stores, and aligned and unaligned 128-bit XMM loads and stores.
- Stack pushes, loads, stores, and the 16-bit increment read-modify-write are fault-atomic: a fault leaves guest memory and registers unchanged.
- The decoder fetches instructions only from executable mappings.

The R2 self-test uses a small read/write mapping as its stack. Mach-O fixtures and dyld get a 1 MiB stack holding `argc`, `argv`, `envp`, and `apple[]`. `push` and `call` decrement `RSP` and write guest memory; `pop` and `ret` read guest memory and increment `RSP`. Branch targets are guest RIPs returned to the dispatcher, never host code pointers.

## Fast paths

Hot byte loops can skip the per-access helper, but only after a runtime check:

- A loop over an anonymous mapping resolves the mapping once and reuses its host span.
- Adjacent byte loads share one range check.
- A monotonic byte read or write loop may run without per-iteration checks after a guard proves exact termination, a positive non-wrapping stride, and that the entire remaining range lies in the mapping.
- The LLVM tier receives a host span only after proving every byte the current invocation will touch. If the proof fails, execution returns to the checked baseline before guest state changes.

Executable, file-backed, and sparse mappings always use the checked helper. A write to executable memory also bumps the executable version and stops the running batch so stale translations cannot run.

## Not implemented

General BSD `mmap`, dirty tracking, identity mapping, direct-memory fast paths wider than one byte, and memory shared between guest processes.
