# Roadmap

The goal is not "run any exe". It is a **clearly defined class of exes that
works, and grows**. What makes an exe easy or hard is mostly *which Windows APIs
it imports*, not which instructions it uses, so each rung below is defined by
its imports and verified with `x86arm check`.

## How a recompiled program works

```
program.exe ──► x86arm build ──► program.c ──► clang -O2 ──► arm64 binary
                                                  ▲
                         runtime/ (loader, Ctx, Win32 shims)
```

- **Recompiler** (Python): finds the code, translates each x86-64 instruction
  to C that operates on a `Ctx` register struct (`runtime/runtime.h`).
- **Runtime** (C): maps the exe's sections at their original addresses, sets up
  the stack and TEB, and implements Windows functions as `SHIM(dll, Name)`.
- **Missed code**: an indirect jump to an address the recompiler didn't find
  aborts with that address. Add it to the config and rebuild. No interpreter
  needed at first.

## Target ladder

Each rung's fixtures go in `tests/fixtures/` and must produce the same output
as on Windows (or Wine).

### Milestone 1: `tiny.exe` runs on the Mac
No C runtime, 3 kernel32 imports, ~15 instructions.

- [x] PE parser, `info` and `check` commands
- [x] Runtime: `Ctx`, `SHIM` registry, GetStdHandle / WriteFile / ExitProcess
- [ ] Disassembler (`pip install capstone`) and code discovery from the entry point
- [ ] Translate: `sub`, `mov`, `lea` (incl. RIP-relative), `call [rip+x]`, `nop`
- [ ] Import calls: map each IAT slot to its shim
- [ ] Loader: `mmap` sections at the image base, allocate the stack, call the entry point
- [ ] `build` command: emit C, compile with the runtime, run

### Milestone 2: plain C, no C runtime
Still `-nostdlib`, but real code: loops, `if`/`switch`, arithmetic, function
calls, structs, arrays.

- [ ] Integer ALU and all flags; conditional jumps; `cmov`, `setcc`
- [ ] Direct calls and returns between recompiled functions
- [ ] Jump tables (`switch`), found via the base relocation table
- [ ] SSE scalar float/double (x64 uses SSE for floats, not x87)
- [ ] Differential tests: same output as the exe under Wine

### Milestone 3: real C programs (`hello.exe`)
Linked against the Universal C Runtime: ~40 imports for hello world.

- [ ] Decide: shim `ucrtbase` functions by mapping them onto macOS libc
      (`printf`, `malloc`, `fopen`...) where the behavior matches
- [ ] CRT startup imports (`_initterm`, `_set_app_type`, `__p___argv`...)
- [ ] TEB at `gs:[0]`, thread-local storage
- [ ] Windows file paths, more kernel32 (files, heap, time, environment)

### Milestone 4: real-world command-line tools
Prebuilt Windows binaries of open-source tools, so you can compare against a
native Mac build: **lua.exe**, **sqlite3.exe**, zlib/minigzip, nasm.

- [ ] Whatever `check` reports missing for each one
- [ ] MSVC-compiled binaries (different code patterns than MinGW)

### Milestone 5: C++ and exceptions
- [ ] Virtual calls (vtables found via relocations)
- [ ] Structured exception handling / C++ exceptions (unwind tables in `.pdata`/`.xdata`)

### Milestone 6: graphics
Small SDL2 + OpenGL programs (SDL2 itself would be shimmed onto the Mac's
SDL2), then raw Win32 windows (`user32`/`gdi32`), then OpenGL games.

### Later
- `.app` bundle output (the user supplies their own exe; never ship
  recompiled copyrighted code)
- An x86 → arm64 JIT as a fallback for code static analysis can't find
- Threads, `WaitForMultipleObjects`, Winsock, audio
