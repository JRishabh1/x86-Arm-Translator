"""Which Windows API functions the runtime implements.

The source of truth is the C runtime itself: every `SHIM(dll, Name)` in
runtime/win32/*.c counts as supported, so this list can never drift from the
code.
"""

from __future__ import annotations

import re
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parent.parent / "runtime"

_SHIM_RE = re.compile(r"^SHIM\(\s*(\w+)\s*,\s*(\w+)\s*\)", re.MULTILINE)


def canonical_dll(name: str) -> str:
    """Normalize a DLL name as it appears in an import table.

    "KERNEL32.dll" -> "kernel32". The Universal C Runtime is split into
    API sets ("api-ms-win-crt-stdio-l1-1-0.dll", ...) that Windows redirects to
    ucrtbase.dll, so they all map to "ucrtbase".
    """
    name = name.lower()
    if name.endswith(".dll"):
        name = name[:-4]
    if name.startswith("api-ms-win-crt-"):
        return "ucrtbase"
    return name


def supported(runtime_dir: Path = RUNTIME_DIR) -> dict[str, set[str]]:
    """Map each canonical DLL name to the set of function names with a shim."""
    table: dict[str, set[str]] = {}
    for src in sorted((runtime_dir / "win32").glob("*.c")):
        for dll, func in _SHIM_RE.findall(src.read_text()):
            table.setdefault(dll.lower(), set()).add(func)
    return table
