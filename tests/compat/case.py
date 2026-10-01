"""One conformance case: guest arguments, input, and environment."""

UTF8 = {"LANG": "en_US.UTF-8"}


class Case:
    def __init__(self, name, args, stdin=None, env=None, tags=()):
        self.name = name
        self.args = list(args)
        # A fixture file name, or bytes fed through a pipe.
        self.stdin = stdin
        self.env = env or {}
        self.tags = set(tags)
