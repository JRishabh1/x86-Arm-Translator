"""Command-line interface: `python3 -m x86arm <command> program.exe`."""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict

from x86arm import pe, shims


def cmd_info(args: argparse.Namespace) -> int:
    exe = pe.parse(args.exe)
    entry_section = exe.section_for_rva(exe.entry_rva)
    print(f"{exe.path.name}: x86-64 {exe.subsystem_name} program")
    print(f"  image base   {exe.image_base:#x}")
    print(f"  entry point  {exe.image_base + exe.entry_rva:#x}"
          f" (in {entry_section.name if entry_section else '?'})")
    print(f"  image size   {exe.size_of_image:#x}")
    print("  sections:")
    for s in exe.sections:
        perms = "r" + ("w" if s.writable else "-") + ("x" if s.executable else "-")
        print(f"    {s.name:<8} {exe.image_base + s.virtual_address:#014x}  {s.virtual_size:#8x}  {perms}")
    dlls = sorted({imp.dll for imp in exe.imports}, key=str.lower)
    print(f"  imports: {len(exe.imports)} functions from {len(dlls)} DLLs")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Report which of the program's imports the runtime implements.

    Exit status is 0 when everything is supported, 1 otherwise, so this can
    gate scripts and CI.
    """
    exe = pe.parse(args.exe)
    table = shims.supported()

    by_dll: dict[str, list[pe.Import]] = defaultdict(list)
    for imp in exe.imports:
        by_dll[shims.canonical_dll(imp.dll)].append(imp)

    missing = 0
    for dll in sorted(by_dll):
        imps = by_dll[dll]
        ok = [i for i in imps if i.name in table.get(dll, set())]
        print(f"{dll}  ({len(ok)}/{len(imps)} supported)")
        for imp in sorted(imps, key=lambda i: i.name or ""):
            name = imp.name or f"#{imp.ordinal}"
            supported = imp in ok
            if not supported:
                missing += 1
            if supported and not args.verbose:
                continue
            print(f"  {'ok     ' if supported else 'MISSING'}  {name}")

    total = len(exe.imports)
    print(f"\n{total - missing}/{total} imports supported", end="")
    print("." if missing == 0 else f"; {missing} missing.")
    return 0 if missing == 0 else 1


def cmd_build(args: argparse.Namespace) -> int:
    print("build is not implemented yet: see docs/roadmap.md, milestone 1.", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="x86arm",
        description="Statically recompile Windows x86-64 programs into native macOS arm64 programs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("info", help="show headers and sections of an exe")
    p.add_argument("exe")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("check", help="report which Windows imports the runtime supports")
    p.add_argument("exe")
    p.add_argument("-v", "--verbose", action="store_true", help="also list supported imports")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("build", help="recompile an exe into a Mac binary (not implemented yet)")
    p.add_argument("exe")
    p.add_argument("-o", "--output")
    p.set_defaults(func=cmd_build)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (pe.PEError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
