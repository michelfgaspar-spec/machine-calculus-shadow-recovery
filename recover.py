#!/usr/bin/env python3
"""Recover Machine Calculus solely from the 121 supplied shadows."""
import argparse
from pathlib import Path
import subprocess
import sys

from recovery.common import BuildError, encoded
from recovery.engine import reconstruct, reconstruct_directory, verify


ROOT = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('verify', 'book', 'sources', 'all'):
        item = commands.add_parser(name)
        item.add_argument('--expected-fingerprint', help='Independently retained source signing-key fingerprint')
        if name != 'verify':
            item.add_argument('--output', type=Path, required=True,
                              help=('New PDF path outside any Git worktree' if name == 'book'
                                    else 'New directory outside any Git worktree'))
    args = parser.parse_args(argv)
    progress = lambda message: print(message, flush=True)
    try:
        if args.command == 'verify':
            print(encoded(verify(ROOT, args.expected_fingerprint, progress)).decode(), end='')
        elif args.command == 'book':
            path = reconstruct(ROOT, args.output, args.expected_fingerprint, progress)
            print('Recovered and verified all 242 pages: ' + str(path))
        else:
            path = reconstruct_directory(ROOT, args.output, args.expected_fingerprint,
                                         progress, book=args.command == 'all')
            detail = '29 canonical TeX files and all 242 pages' if args.command == 'all' else '29 canonical TeX files'
            print('Recovered and verified ' + detail + ': ' + str(path))
    except (BuildError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print('error: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
