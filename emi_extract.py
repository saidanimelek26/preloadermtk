#!/usr/bin/env python3
"""EMI extractor clone — command-line entry point.

Behaviour mirrors the original Windows tool ``emi_ext.exe`` v1.1.2:

* every existing path argument is treated as an input file;
* ``-h`` / ``--help`` prints ``Usage: <program> -h``;
* success is silent;
* output is written next to the input as ``MemoryDeviceList_<platform>.xls``;
* the persistent parser state is shared between input files, exactly like the
  original global variables.

Run ``python emi_extract.py -h`` for the short help, or read README.md.
"""

from __future__ import annotations

import os
import sys

from emi_parser import EmiFormatError, EmiState
from emi_writer import EmiWriteError, write_workbook


def _option_error(args):
    """Return ``(position, bad_option)`` for the first invalid option.

    The original uses Free Pascal's TCustomApplication option parser, whose
    errors look like::

        Invalid option at position 1: "x".
        Invalid option at position 1: "foo".   (for ``--foo``)
    """
    for position, argument in enumerate(args, 1):
        if argument == "-":
            return position, "-"
        if argument.startswith("--"):
            name = argument[2:]
            if name == "help":
                continue
            return position, name
        if argument.startswith("-"):
            for char in argument[1:]:
                if char == "h":
                    continue
                return position, char
    return None


def _requests_help(args) -> bool:
    # The original only reacts to the exact options "-h" / "--help"; clustered
    # forms such as "-hh" are accepted by FPC's parser but do not trigger help.
    return any(argument in ("-h", "--help") for argument in args)


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    program = os.path.abspath(sys.argv[0])

    invalid = _option_error(args)
    if invalid is not None:
        position, bad_option = invalid
        print(
            "Exception at 00000000: Exception:\n"
            f'Invalid option at position {position}: "{bad_option}".'
        )
        return 0

    if _requests_help(args):
        print(f"Usage: {program} -h")
        return 0

    template_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "template.xls"
    )

    # Shared state: the original does not reset platform/count/records between
    # input files.  Keep one instance for the whole invocation.
    state = EmiState()

    for argument in args:
        if not os.path.isfile(argument):
            # Nonexistent paths are silently skipped by the original.
            continue

        try:
            state.load_file(argument)
            if state.count > 0:
                write_workbook(state, argument, template_path)
        except (OSError, EmiFormatError, EmiWriteError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
