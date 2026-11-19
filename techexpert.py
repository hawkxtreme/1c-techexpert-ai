"""Run directly from a checkout; no dependency installation is required."""
import sys

# The same entrypoint runs inside the verified installation cache.
if __name__ == '__main__':
    sys.dont_write_bytecode = True

from src.techexpert.cli import main

if __name__ == '__main__':
    raise SystemExit(main())
