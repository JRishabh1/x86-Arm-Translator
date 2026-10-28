// Runtime shared by every recompiled program.
//
// Recompiled code does not run on the host's registers directly. Each x86-64
// register lives in a Ctx struct, and the generated C reads and writes it:
//
//     // add rax, [rbx+8]
//     c->rax += R64(c->rbx + 8);
//
// Guest memory is identity-mapped: the loader places the exe at its preferred
// image base inside this process, so a guest address is a valid host pointer.
#pragma once

#include <stdint.h>
#include <string.h>

typedef union {
    uint8_t  b[16];
    uint32_t d[4];
    uint64_t q[2];
    float    f[4];
    double   dbl[2];
} Xmm;

typedef struct Ctx {
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    // Flags stored one per byte so generated code can set and test them cheaply;
    // clang removes the ones nothing reads.
    uint8_t cf, pf, af, zf, sf, of, df;
    Xmm xmm[16];
    uint64_t gs_base;  // Windows keeps the thread info block (TEB) at gs:[0]
} Ctx;

// Unaligned-safe guest memory access.
#define DEFINE_ACCESS(bits)                                                  \
    static inline uint##bits##_t R##bits(uint64_t addr) {                    \
        uint##bits##_t v; memcpy(&v, (void *)addr, sizeof v); return v;      \
    }                                                                        \
    static inline void W##bits(uint64_t addr, uint##bits##_t v) {           \
        memcpy((void *)addr, &v, sizeof v);                                  \
    }
DEFINE_ACCESS(8)
DEFINE_ACCESS(16)
DEFINE_ACCESS(32)
DEFINE_ACCESS(64)

// ---- Windows API shims ------------------------------------------------------
//
// SHIM(kernel32, WriteFile) defines the host implementation of
// kernel32!WriteFile. `x86arm check` scans runtime/win32/*.c for these to
// decide which imports are supported, so every shim must use this macro.
//
// Calling convention: recompiled code performs a guest `call`, so on entry
// c->rsp points at the return address, exactly as on Windows. Under the
// Windows x64 ABI the first four integer arguments are in rcx, rdx, r8, r9;
// the fifth and later are on the stack after the return address and the
// 32-byte shadow space. Shims finish with shim_return().
#define SHIM(dll, name) void shim_##dll##_##name(Ctx *c)

static inline uint64_t shim_arg(Ctx *c, int n) {
    switch (n) {
    case 0: return c->rcx;
    case 1: return c->rdx;
    case 2: return c->r8;
    case 3: return c->r9;
    default: return R64(c->rsp + 8 + 32 + 8 * (uint64_t)(n - 4));
    }
}

// Set the return value and pop the return address (the guest `ret`).
static inline void shim_return(Ctx *c, uint64_t value) {
    c->rax = value;
    c->rip = R64(c->rsp);
    c->rsp += 8;
}

// ---- Handles ----------------------------------------------------------------
//
// Windows hands out opaque HANDLE values for files, threads, events and more.
// The runtime keeps its own table mapping them to host resources.
int handle_to_fd(uint64_t handle);  // -1 if the handle is not a file
