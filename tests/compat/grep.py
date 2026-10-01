#!/usr/bin/env python3
"""Byte-exact grep conformance: Rosa versus the host's own grep.

/usr/bin/grep is a universal binary. Rosa executes its x86_64 slice; the arm64e
slice of the same build is the oracle. Every case compares stdout, stderr, and
exit status byte for byte. Both run in the same generated fixture tree with the
same controlled environment and the program name "grep".

    tests/compat/grep.py --rosa build/release/rosa
    tests/compat/grep.py --rosa build/release/rosa -k recursive -v

Exit status is 0 when every selected case matches, 1 otherwise, and 77 when
the host cannot provide both slices (the CTest skip code).
"""

import argparse
import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import sys
import tempfile
import time

HOST_GREP = "/usr/bin/grep"
SKIP_STATUS = 77


class Case:
    def __init__(self, name, args, stdin=None, env=None):
        self.name = name
        self.args = list(args)
        self.stdin = stdin
        self.env = env or {}


UTF8 = {"LANG": "en_US.UTF-8"}

CASES = [
    # Basic matching and output selection.
    Case("literal", ["beta", "in.txt"]),
    Case("no-match-status", ["zzz", "in.txt"]),
    Case("missing-file", ["beta", "missing.txt"]),
    Case("missing-file-silent", ["-s", "beta", "missing.txt"]),
    Case("two-files", ["beta", "in.txt", "words.txt"]),
    Case("with-filename", ["-H", "beta", "in.txt"]),
    Case("no-filename", ["-h", "beta", "in.txt", "words.txt"]),
    Case("line-number", ["-n", "beta", "in.txt"]),
    Case("byte-offset", ["-b", "beta", "in.txt"]),
    Case("count", ["-c", "beta", "in.txt", "words.txt"]),
    Case("count-invert", ["-vc", "beta", "in.txt"]),
    Case("invert", ["-v", "beta", "in.txt"]),
    Case("ignore-case", ["-i", "BETA", "words.txt"]),
    Case("ignore-case-y", ["-y", "BETA", "words.txt"]),
    Case("word", ["-w", "gam", "words.txt"]),
    Case("word-match", ["-w", "beta", "words.txt"]),
    Case("line", ["-x", "beta", "words.txt"]),
    Case("only-matching", ["-o", "b.ta", "words.txt"]),
    Case("only-matching-multi", ["-on", "a", "in.txt"]),
    Case("max-count", ["-m", "1", "beta", "words.txt"]),
    Case("max-count-context", ["-m", "1", "-A", "1", "beta", "words.txt"]),
    Case("quiet-match", ["-q", "beta", "in.txt"]),
    Case("quiet-nomatch", ["-q", "zzz", "in.txt"]),
    Case("files-with-matches", ["-l", "beta", "in.txt", "words.txt", "empty.txt"]),
    Case("files-without-match", ["-L", "beta", "in.txt", "words.txt", "empty.txt"]),
    Case("null-after-name", ["--null", "-l", "beta", "in.txt", "words.txt"]),
    Case("label-stdin", ["--label=piped", "-H", "beta"], stdin="in.txt"),
    # Pattern syntax and sources.
    Case("basic-regex", ["-G", "be*ta", "words.txt"]),
    Case("basic-interval", ["a\\{2\\}", "words.txt"]),
    Case("basic-backref", ["\\(a\\)\\1", "words.txt"]),
    Case("extended-alternation", ["-E", "al(ph|xx)a|gamma", "words.txt"]),
    Case("extended-plus", ["-E", "e+t", "words.txt"]),
    Case("extended-class", ["-E", "^[[:upper:]][[:alpha:]]+$", "words.txt"]),
    Case("fixed-strings", ["-F", "a.b", "words.txt"]),
    Case("fixed-multi", ["-F", "-e", "alpha", "-e", "delta", "words.txt"]),
    Case("multiple-e", ["-e", "alpha", "-e", "^gamma", "words.txt"]),
    Case("pattern-file", ["-f", "patterns.txt", "words.txt"]),
    Case("pattern-file-empty", ["-f", "empty.txt", "words.txt"]),
    Case("empty-pattern", ["", "in.txt"]),
    Case("anchors", ["^beta$", "words.txt"]),
    Case("invalid-regex", ["-E", "a(b", "in.txt"]),
    Case("dash-pattern", ["-e", "-x", "words.txt"]),
    # Context.
    Case("after", ["-A", "1", "alpha", "words.txt"]),
    Case("before", ["-B", "2", "delta", "words.txt"]),
    Case("context", ["-C", "1", "gamma", "words.txt"]),
    Case("context-numeric", ["-1", "gamma", "words.txt"]),
    Case("context-separators", ["-n", "-A", "1", "a", "words.txt"]),
    # Colour.
    Case("color-always", ["--color=always", "beta", "words.txt"]),
    Case("color-never", ["--color=never", "beta", "words.txt"]),
    Case("color-env", ["--color=always", "beta", "words.txt"],
         env={"GREP_COLOR": "01;32"}),
    Case("color-only", ["--color=always", "-o", "e", "in.txt"]),
    # Input shapes.
    Case("stdin", ["beta"], stdin="in.txt"),
    Case("stdin-dash", ["beta", "-"], stdin="in.txt"),
    Case("stdin-count", ["-c", "a"], stdin="words.txt"),
    Case("empty-file", ["beta", "empty.txt"]),
    Case("no-trailing-newline", ["tail", "noeol.txt"]),
    Case("crlf", ["-c", "line", "crlf.txt"]),
    Case("long-line", ["-c", "needle", "long.txt"]),
    Case("large-file", ["-c", "99999", "big.txt"]),
    Case("large-file-n", ["-n", "^1999[0-9]9$", "big.txt"]),
    Case("binary-default", ["payload", "binary.bin"]),
    Case("binary-text", ["-a", "payload", "binary.bin"]),
    Case("binary-ignore", ["-I", "payload", "binary.bin"]),
    Case("binary-files-without", ["--binary-files=without-match", "payload", "binary.bin"]),
    Case("null-data", ["-z", "two", "nul.txt"]),
    Case("mmap", ["--mmap", "beta", "in.txt"]),
    Case("line-buffered", ["--line-buffered", "beta", "in.txt"]),
    Case("unreadable", ["beta", "unreadable.txt"]),
    # Directories and recursion.
    Case("directory-arg", ["beta", "tree"]),
    Case("directory-skip", ["-d", "skip", "beta", "tree"]),
    Case("directory-read", ["-d", "read", "beta", "tree"]),
    Case("recursive", ["-r", "beta", "tree"]),
    Case("recursive-n", ["-rn", "beta", "tree"]),
    Case("recursive-l", ["-rl", "beta", "tree"]),
    Case("recursive-count", ["-rc", "beta", "tree"]),
    Case("recursive-include", ["-r", "--include=*.c", "beta", "tree"]),
    Case("recursive-exclude", ["-r", "--exclude=*.log", "beta", "tree"]),
    Case("recursive-exclude-dir", ["-r", "--exclude-dir=deep", "beta", "tree"]),
    Case("recursive-follow-all", ["-R", "-S", "beta", "tree"]),
    Case("recursive-no-follow", ["-R", "-p", "beta", "tree"]),
    Case("recursive-cwd", ["-r", "gamma", "."]),
    Case("devices-skip", ["-D", "skip", "beta", "-"], stdin="in.txt"),
    # Compressed input.
    Case("gzip", ["-Z", "beta", "in.txt.gz"]),
    Case("bzip2", ["-J", "beta", "in.txt.bz2"]),
    Case("xz", ["-X", "beta", "in.txt.xz"]),
    Case("lzma", ["-M", "beta", "in.txt.lzma"]),
    # Locales.
    Case("utf8-dot", ["-o", "caf.", "utf8.txt"], env=UTF8),
    Case("utf8-ignore-case", ["-i", "ÜBER", "utf8.txt"], env=UTF8),
    Case("utf8-class", ["-o", "[[:alpha:]]*ve", "utf8.txt"], env=UTF8),
    Case("utf8-invalid-bytes", ["-c", "x", "latin1.txt"], env=UTF8),
    Case("c-locale-bytes", ["-o", "caf.", "utf8.txt"]),
    # Diagnostics and usage.
    Case("version", ["-V"]),
    Case("help", ["--help"]),
    Case("bad-option", ["--definitely-not-an-option", "x", "in.txt"]),
    Case("no-pattern", []),
    Case("bad-context", ["-A", "lots", "x", "in.txt"]),
]


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
    write(os.path.join(root, "long.txt"), b"x" * 100000 + b"needle" + b"y" * 1000 + b"\n")
    write(os.path.join(root, "big.txt"),
          b"".join(b"%d\n" % number for number in range(1, 200001)))
    write(os.path.join(root, "binary.bin"), b"head\x00\x01\x02payload\nmore\x00\n")
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


def thin(slice_name, destination):
    result = subprocess.run(["lipo", HOST_GREP, "-thin", slice_name, "-output", destination],
                            capture_output=True)
    return result.returncode == 0


def run_one(argv, executable, cwd, env, stdin_path, timeout):
    stdin = open(os.path.join(cwd, stdin_path), "rb") if stdin_path else subprocess.DEVNULL
    started = time.monotonic()
    try:
        result = subprocess.run(argv, executable=executable, cwd=cwd, env=env, stdin=stdin,
                                capture_output=True, timeout=timeout)
        outcome = (result.returncode, result.stdout, result.stderr)
    except subprocess.TimeoutExpired as expired:
        outcome = ("timeout", expired.stdout or b"", expired.stderr or b"")
    finally:
        if stdin_path:
            stdin.close()
    return outcome, time.monotonic() - started


def describe_difference(expected, actual, limit):
    lines = []
    labels = ("status", "stdout", "stderr")
    for label, want, got in zip(labels, expected, actual):
        if want == got:
            continue
        if label == "status":
            lines.append("    status: expected %s, got %s" % (want, got))
            continue
        lines.append("    %s expected: %r" % (label, want[:limit]))
        lines.append("    %s actual:   %r" % (label, got[:limit]))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rosa", required=True, help="path to the rosa executable")
    parser.add_argument("-k", dest="keyword", action="append", default=[],
                        help="run only cases whose name contains this text (repeatable)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show expected and actual output for mismatches")
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="per-case timeout in seconds for the Rosa run")
    parser.add_argument("--list", action="store_true", help="list case names and exit")
    parser.add_argument("--keep", action="store_true", help="keep the fixture directory")
    options = parser.parse_args()

    selected = [case for case in CASES
                if not options.keyword or any(word in case.name for word in options.keyword)]
    if options.list:
        for case in selected:
            print(case.name)
        return 0

    rosa = os.path.abspath(options.rosa)
    if not os.access(rosa, os.X_OK):
        print("rosa executable not found: %s" % rosa, file=sys.stderr)
        return 2

    workspace = tempfile.mkdtemp(prefix="rosa-grep-compat-")
    try:
        binaries = os.path.join(workspace, "bin")
        os.makedirs(os.path.join(binaries, "x86"))
        os.makedirs(os.path.join(binaries, "host"))
        guest = os.path.join(binaries, "x86", "grep")
        oracle = os.path.join(binaries, "host", "grep")
        if not thin("x86_64", guest) or not thin("arm64e", oracle):
            print("[skip] %s lacks x86_64 and arm64e slices" % HOST_GREP)
            return SKIP_STATUS
        fixtures = os.path.join(workspace, "fixtures")
        build_fixtures(fixtures)

        failures = []
        for case in selected:
            env = {"PATH": "/usr/bin:/bin", "HOME": workspace}
            env.update(case.env)
            expected, _ = run_one(["grep"] + case.args, oracle, fixtures, env, case.stdin, 30)
            actual, elapsed = run_one([rosa, "exec", guest] + case.args, rosa, fixtures, env,
                                      case.stdin, options.timeout)
            matched = expected == actual
            marker = "PASS" if matched else "FAIL"
            if actual[0] == 125:
                marker = "CRASH"
            elif actual[0] == "timeout":
                marker = "TIMEOUT"
            print("%-7s %-28s %6.2fs  grep %s" % (marker, case.name, elapsed,
                                                  " ".join(case.args)))
            if not matched:
                failures.append(case.name)
                if options.verbose:
                    if marker == "CRASH":
                        reasons = [line.strip() for line in actual[2].decode(
                            "utf-8", "replace").splitlines() if "reason:" in line]
                        print("    " + (reasons[-1] if reasons else "rosa runtime failure"))
                    else:
                        print(describe_difference(expected, actual, 400))
        passed = len(selected) - len(failures)
        print("\n%d/%d grep cases match the host oracle" % (passed, len(selected)))
        return 0 if not failures else 1
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
