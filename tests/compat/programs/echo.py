"""echo: the BSD utility, not a shell builtin."""

from case import Case

BINARY = "/bin/echo"

CASES = [
    Case("single", ["hello"]),
    Case("several", ["hello", "rosa", "world"]),
    Case("none", []),
    Case("empty-argument", [""]),
    Case("no-newline", ["-n", "hello"]),
    Case("no-newline-only", ["-n"]),
    Case("trailing-backslash-c", ["hello\\c"]),
    Case("dash-e-is-text", ["-e", "a\\tb"]),
    Case("double-dash-is-text", ["--", "x"]),
    Case("spaces-preserved", ["  padded  "]),
    Case("utf8", ["café", "日本"]),
    Case("long", ["x" * 100000]),
]
