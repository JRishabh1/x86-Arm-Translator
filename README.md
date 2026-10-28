# x86-Arm-Translator

Statically recompile Windows x86-64 programs (`.exe`) into native macOS arm64
programs.

The recompiler translates the program's x86-64 code into C, and clang compiles
that to arm64. A small runtime replaces the Windows DLLs the program expects
(`kernel32`, the C runtime, ...) with implementations built on macOS APIs. No
CPU emulator is involved at runtime.

**Status:** early. `info` and `check` work; `build` is next. See
[docs/roadmap.md](docs/roadmap.md).

## Setup

```bash
brew install mingw-w64    # cross-compiler for the Windows test programs
make                      # build test fixtures, compile-check runtime, run tests
```

## Usage

```bash
python3 -m x86arm info tests/fixtures/tiny.exe     # headers, sections, entry point
python3 -m x86arm check tests/fixtures/tiny.exe    # which Windows imports are supported
python3 -m x86arm check -v tests/fixtures/hello.exe
```

`check` exits 0 when every import has a shim, 1 otherwise.

## Layout

```
x86arm/            recompiler (Python)
  pe.py            PE32+ parser: headers, sections, imports
  shims.py         reads the supported-API list from the runtime
  cli.py           info / check / build
runtime/           C runtime linked into every recompiled program
  runtime.h        Ctx (guest registers), memory access, SHIM calling convention
  win32/*.c        Windows API shims, one file per DLL
tests/fixtures/    small Windows programs in C, built with MinGW
docs/roadmap.md    milestones, defined by which programs work
```

## Adding a Windows API function

Add a `SHIM(dll, FunctionName)` to `runtime/win32/<dll>.c`. `check` picks it
up automatically. Read arguments with `shim_arg(c, n)` and finish with
`shim_return(c, value)`; see `kernel32.c` for examples.
