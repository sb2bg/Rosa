# Guest memory

Rosa currently exposes a 4 KiB guest-page contract through `guest::AddressSpace`, independent of the host's 16 KiB page size.

Implemented behavior is intentionally small:

- page-aligned anonymous mappings;
- complete Mach-O segment mappings with file bytes and zero-filled virtual tails;
- sparse no-access mappings such as the 4 GiB `__PAGEZERO`;
- overlap and integer-overflow rejection;
- explicit read/write/execute permission metadata;
- bounds-checked cross-mapping byte copies and little-endian 8/16/32/64-bit generated loads/stores;
- guarded 128-bit XMM loads/stores with aligned and unaligned forms;
- fault-atomic stack pushes, loads, stores, and the observed 16-bit increment read/modify/write;
- sparse read-only x86 commpage population;
- executable instruction views used by the decoder;
- no conversion from `GuestAddress` to a host pointer.

R2 uses a small read/write mapping as the x86 test stack. R3/R4 and the dyld probe map a 1 MiB stack and populate Darwin-shaped `argc`, `argv`, `envp`, and `apple[]` vectors. `push` and `call` decrement guest `RSP` and write guest memory; `pop` and `ret` read guest memory and increment `RSP`. Dynamic guest branch targets are written to guest RIP and returned to the dispatcher, never treated as host code pointers.

`write(2)` copies its guest buffer through the mapping table before invoking the host API. No guest address becomes a host pointer.

Not implemented: 4 KiB subpage protection within a 16 KiB host page, `mmap`/`mprotect`/`munmap`, dirty tracking, identity-map experiments, direct host-pointer memory fast paths, shared-cache mappings, or shared writable mappings.
