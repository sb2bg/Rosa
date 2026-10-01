#!/usr/bin/env python3
"""Byte-exact conformance of host programs under Rosa.

Each program under tests/compat/programs names a universal binary on the host.
Rosa executes its x86_64 slice; the host runs the binary itself, whose arm64e
slice is the same build, as the oracle. (A thinned copy of that slice is not
runnable: it fails platform code-signing checks.) Every case compares stdout,
stderr, and exit status byte for byte. Both sides run in the same generated
fixture tree with the same controlled environment and program name.

    tests/compat/compat.py --rosa build/release/rosa
    tests/compat/compat.py --rosa build/release/rosa grep -k recursive -v
    tests/compat/compat.py --rosa build/release/rosa grep --exclude-tag compression

Exit status is 0 when every selected case matches, 1 otherwise, and 77 when
the host cannot provide a selected program's x86_64 slice (the CTest skip code).
"""

import argparse
import bz2
import gzip
import importlib
import lzma
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
PROGRAMS_DIRECTORY = os.path.join(HERE, "programs")
SKIP_STATUS = 77
ROSA_FAILURE_STATUS = 125


def available_programs():
    return sorted(name[:-3] for name in os.listdir(PROGRAMS_DIRECTORY)
                  if name.endswith(".py") and not name.startswith("_"))


def load_program(name):
    return importlib.import_module("programs." + name)


def write(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def build_fixtures(root):
    lines = (b"alpha\nbeta\ngamma beta\nBeta\nBETA\ngamma\ndelta\naa\nbab\n"
             b"a.b\naxb\n-x\nEpsilon\nalphabet\nalpha beta gamma\n\nzeta\n")
    write(os.path.join(root, "in.txt"), b"alpha\nbeta\ngamma beta\n")
    write(os.path.join(root, "words.txt"), lines)
    write(os.path.join(root, "patterns.txt"), b"delta\n^zeta$\n")
    write(os.path.join(root, "empty.txt"), b"")
    write(os.path.join(root, "noeol.txt"), b"head\ntail")
    write(os.path.join(root, "crlf.txt"), b"line one\r\nline two\r\n")
    write(os.path.join(root, "blanks.txt"), b"one\n\n\n\ntwo\n\nthree\n\n\n")
    write(os.path.join(root, "tabs.txt"), b"a\tb\tc\n\tlead\n")
    write(os.path.join(root, "long.txt"), b"x" * 100000 + b"needle" + b"y" * 1000 + b"\n")
    write(os.path.join(root, "big.txt"),
          b"".join(b"%d\n" % number for number in range(1, 200001)))
    write(os.path.join(root, "binary.bin"), b"head\x00\x01\x02payload\nmore\x00\x7f\x80\xff\n")
    write(os.path.join(root, "nul.txt"), b"one\x00two\x00three\x00")
    write(os.path.join(root, "utf8.txt"),
          "café\nnaïve\nÜber alles\nüber\n日本語\n".encode("utf-8"))
    write(os.path.join(root, "latin1.txt"), b"caf\xe9 x\n\xff\xfe x\nplain x\n")
    unreadable = os.path.join(root, "unreadable.txt")
    write(unreadable, b"beta\n")
    os.chmod(unreadable, 0)

    tree = os.path.join(root, "tree")
    write(os.path.join(tree, "a.txt"), b"beta one\n")
    write(os.path.join(tree, ".hidden"), b"beta hidden\n")
    write(os.path.join(tree, "sub", "b.txt"), b"beta two\nnothing\n")
    write(os.path.join(tree, "sub", "skip.log"), b"beta log\n")
    write(os.path.join(tree, "sub", "deep", "c.c"), b"int beta = 3;\n")
    write(os.path.join(tree, "sub", "empty.txt"), b"")
    os.symlink("a.txt", os.path.join(tree, "link.txt"))
    os.symlink("../outside", os.path.join(tree, "dirlink"))
    write(os.path.join(root, "outside", "o.txt"), b"beta outside\n")

    source = os.path.join(root, "in.txt")
    with open(source, "rb") as handle:
        text = handle.read()
    write(source + ".gz", gzip.compress(text, mtime=0))
    write(source + ".bz2", bz2.compress(text))
    write(source + ".xz", lzma.compress(text, format=lzma.FORMAT_XZ))
    write(source + ".lzma", lzma.compress(text, format=lzma.FORMAT_ALONE))


def thin_x86_64(binary, destination):
    result = subprocess.run(["lipo", binary, "-thin", "x86_64", "-output", destination],
                            capture_output=True)
    return result.returncode == 0


def run_one(argv, executable, cwd, env, stdin, timeout):
    # Bytes reach the program through a pipe; a name opens that fixture file.
    if isinstance(stdin, bytes):
        redirect = {"input": stdin}
        source = None
    else:
        source = open(os.path.join(cwd, stdin), "rb") if stdin else subprocess.DEVNULL
        redirect = {"stdin": source}
    started = time.monotonic()
    try:
        result = subprocess.run(argv, executable=executable, cwd=cwd, env=env,
                                capture_output=True, timeout=timeout, **redirect)
        outcome = (result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired as expired:
        outcome = ("timeout", expired.stdout or b"", expired.stderr or b"")
    finally:
        if hasattr(source, "close"):
            source.close()
    return outcome, time.monotonic() - started


def describe_difference(expected, actual, limit):
    lines = []
    for label, want, got in zip(("status", "stdout", "stderr"), expected, actual):
        if want == got:
            continue
        if label == "status":
            lines.append("    status: expected %s, got %s" % (want, got))
            continue
        lines.append("    %s expected: %r" % (label, want[:limit]))
        lines.append("    %s actual:   %r" % (label, got[:limit]))
    return "\n".join(lines)


def rosa_failure_reason(stderr):
    reasons = [line.strip() for line in stderr.decode("utf-8", "replace").splitlines()
               if "reason:" in line]
    return reasons[-1] if reasons else "rosa runtime failure"


def run_program(name, options, rosa, workspace, fixtures):
    program = load_program(name)
    cases = [case for case in program.CASES
             if (not options.keyword or any(word in case.name for word in options.keyword))
             and not (case.tags & set(options.exclude_tag))]
    if options.list:
        for case in cases:
            print("%s %s" % (name, case.name))
        return 0, 0, False
    guest_directory = os.path.join(workspace, "bin", name)
    os.makedirs(guest_directory)
    guest = os.path.join(guest_directory, name)
    if not thin_x86_64(program.BINARY, guest):
        print("[skip] %s has no x86_64 slice" % program.BINARY)
        return 0, 0, True

    failures = 0
    for case in cases:
        env = {"PATH": "/usr/bin:/bin", "HOME": workspace}
        if options.env_padding:
            # Shifts the initial stack and string alignments, which steer
            # libc's alignment-dependent copy and compare paths.
            env["ROSA_COMPAT_PADDING"] = "x" * options.env_padding
        env.update(case.env)
        expected, _ = run_one([name] + case.args, program.BINARY, fixtures, env, case.stdin, 30)
        actual, elapsed = run_one([rosa, "exec", "--argv0", name, guest] + case.args, rosa,
                                  fixtures, env, case.stdin, options.timeout)
        if expected == actual:
            marker = "PASS"
        elif actual[0] == ROSA_FAILURE_STATUS:
            marker = "CRASH"
        elif actual[0] == "timeout":
            marker = "TIMEOUT"
        else:
            marker = "FAIL"
        print("%-7s %-9s %-28s %6.2fs  %s %s" % (marker, name, case.name, elapsed, name,
                                                 " ".join(case.args)))
        if marker == "PASS":
            continue
        failures += 1
        if options.verbose:
            if marker == "CRASH":
                print("    " + rosa_failure_reason(actual[2]))
            else:
                print(describe_difference(expected, actual, 400))
    return len(cases), failures, False


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("programs", nargs="*",
                        help="programs to check (default: all of %s)" %
                             ", ".join(available_programs()))
    parser.add_argument("--rosa", required=True, help="path to the rosa executable")
    parser.add_argument("-k", dest="keyword", action="append", default=[],
                        help="run only cases whose name contains this text (repeatable)")
    parser.add_argument("--exclude-tag", action="append", default=[],
                        help="skip cases carrying this tag (repeatable)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show expected and actual output for mismatches")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="per-case timeout in seconds for the Rosa run")
    parser.add_argument("--env-padding", type=int, default=0, metavar="BYTES",
                        help="add an environment variable of this many bytes")
    parser.add_argument("--list", action="store_true", help="list case names and exit")
    parser.add_argument("--keep", action="store_true", help="keep the fixture directory")
    options = parser.parse_args()

    programs = options.programs or available_programs()
    unknown = sorted(set(programs) - set(available_programs()))
    if unknown:
        print("unknown program(s): %s" % ", ".join(unknown), file=sys.stderr)
        return 2
    rosa = os.path.abspath(options.rosa)
    if not options.list and not os.access(rosa, os.X_OK):
        print("rosa executable not found: %s" % rosa, file=sys.stderr)
        return 2

    workspace = tempfile.mkdtemp(prefix="rosa-compat-")
    try:
        fixtures = os.path.join(workspace, "fixtures")
        build_fixtures(fixtures)
        totals = []
        skipped = False
        for name in programs:
            count, failures, skip = run_program(name, options, rosa, workspace, fixtures)
            skipped = skipped or skip
            totals.append((name, count, failures))
        if options.list:
            return 0
        print()
        for name, count, failures in totals:
            print("%-9s %d/%d cases match the host" % (name, count - failures, count))
        if skipped:
            return SKIP_STATUS
        return 0 if all(failures == 0 for _, _, failures in totals) else 1
    finally:
        if options.keep:
            print("fixtures kept in %s" % workspace)
        else:
            unreadable = os.path.join(workspace, "fixtures", "unreadable.txt")
            if os.path.exists(unreadable):
                os.chmod(unreadable, 0o600)
            shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
