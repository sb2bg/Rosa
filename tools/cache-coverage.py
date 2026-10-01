#!/usr/bin/env python3
"""List the instructions in a shared-cache function that Rosa cannot decode.

When a guest stops on an unsupported instruction, the rest of the function
usually needs more. This finds the function containing a guest address in the
x86_64 dyld shared cache, splits it into instructions with llvm-objdump, runs each
through `rosa decode`, and groups the failures by shape so a whole function's
gaps can be implemented together.

    tools/cache-coverage.py --rosa build/release/rosa 0x7ff802bced56
    tools/cache-coverage.py --rosa build/release/rosa 0x7ff802bced56 --list

The function start is found by scanning back for the `push rbp; mov rbp, rsp`
prologue, which Apple's x86_64 frameworks keep. Disassembly stops at the first
RET past the address, or at --length bytes.
"""

import argparse
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile

DEFAULT_CACHE = ("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/"
                 "dyld_shared_cache_x86_64")
PROLOGUE = b"\x55\x48\x89\xe5"


def executable_mapping(rosa, cache, address):
    info = subprocess.run([rosa, "cache", "inspect", cache], capture_output=True, text=True,
                          check=True).stdout
    paths = dict(re.findall(r'^  (\S+) vm-offset=\S+ uuid=\S+ path="([^"]+)"', info, re.M))
    pattern = (r"^  (\S+) guest=0x([0-9a-f]+) size=0x([0-9a-f]+) "
               r"fileoff=0x([0-9a-f]+) init=r-x")
    for suffix, guest, size, fileoff in re.findall(pattern, info, re.M):
        guest, size, fileoff = int(guest, 16), int(size, 16), int(fileoff, 16)
        if guest <= address < guest + size:
            return paths[suffix], guest, fileoff
    sys.exit("0x%x is not in an executable shared-cache mapping" % address)


def function_bytes(path, guest, fileoff, address, length):
    window = max(guest, address - 0x4000)
    with open(path, "rb") as handle:
        handle.seek(fileoff + window - guest)
        data = handle.read(address - window + length)
    prologue = data.rfind(PROLOGUE, 0, address - window + 1)
    start = window + (prologue if prologue >= 0 else address - window)
    return start, data[start - window:]


def split_instructions(objdump, start, code, address):
    # Assemble the raw bytes into an object so llvm-objdump reports each
    # instruction's original bytes. (llvm-mc --show-encoding re-encodes, which
    # drops redundant prefixes such as the 66 on multi-byte NOPs.)
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "function.s")
        objectFile = os.path.join(directory, "function.o")
        with open(source, "w") as handle:
            handle.write(".text\n")
            for offset in range(0, len(code), 32):
                chunk = code[offset:offset + 32]
                handle.write(".byte " + ",".join("0x%02x" % byte for byte in chunk) + "\n")
        subprocess.run(["clang", "-c", "-arch", "x86_64", "-x", "assembler", source, "-o", objectFile],
                       check=True)
        listing = subprocess.run([objdump, "-d", "--x86-asm-syntax=intel", objectFile],
                                 capture_output=True, text=True, check=True).stdout
    instructions = []
    for line in listing.splitlines():
        # "   1a: 48 ba 00 ... e0<TAB>movabs<TAB>rdx, ..."
        match = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f ]+?)\t(.*)$", line)
        if not match:
            continue
        offset = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2))
        text = " ".join(match.group(3).split())
        instructions.append((start + offset, raw, text))
        if text.startswith("ret") and start + offset + len(raw) > address:
            break
    return instructions


def shape(text):
    mnemonic, _, operands = text.partition(" ")
    operands = re.sub(r"\b[re]?[a-z]{1,2}[xlhpi]?\b|\br\d+[dwb]?\b|\b[xy]mm\d+\b", "R", operands)
    return mnemonic + " " + re.sub(r"[-+]?\b(0x)?[0-9a-f]+\b", "N", operands)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("address", help="guest address inside the function (hex)")
    parser.add_argument("--rosa", required=True, help="path to the rosa executable")
    parser.add_argument("--cache", default=DEFAULT_CACHE, help="x86_64 dyld shared cache")
    parser.add_argument("--llvm-objdump", default=shutil.which("llvm-objdump") or
                        "/opt/homebrew/opt/llvm/bin/llvm-objdump", help="llvm-objdump executable")
    parser.add_argument("--length", type=lambda value: int(value, 0), default=0x4000,
                        help="maximum bytes past the address to examine")
    parser.add_argument("--list", action="store_true",
                        help="print every instruction with Rosa's verdict")
    options = parser.parse_args()

    address = int(options.address, 16)
    path, guest, fileoff = executable_mapping(options.rosa, options.cache, address)
    start, code = function_bytes(path, guest, fileoff, address, options.length)
    instructions = split_instructions(options.llvm_objdump, start, code, address)
    verdicts = subprocess.run(
        [options.rosa, "decode", "--address", "%x" % start],
        input="\n".join(raw.hex(" ") for _, raw, _ in instructions),
        capture_output=True, text=True, check=True).stdout.splitlines()

    failures = collections.OrderedDict()
    for (pc, raw, text), verdict in zip(instructions, verdicts):
        supported = verdict.startswith("ok")
        if options.list:
            print("%s 0x%x: %-28s %s" % ("  " if supported else "!!", pc, raw.hex(" "), text))
        if not supported:
            failures.setdefault(shape(text), []).append((pc, raw.hex(" "), text))
    print("function 0x%x: %d instructions, %d undecodable in %d shapes" % (
        start, len(instructions), sum(len(items) for items in failures.values()), len(failures)))
    for items in failures.values():
        pc, raw, text = items[0]
        print("%5d x  %-44s first at 0x%x: %s" % (len(items), text[:44], pc, raw))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
