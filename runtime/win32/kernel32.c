// kernel32.dll: core Windows services (processes, files, memory, threads).
// Docs for each function: https://learn.microsoft.com/en-us/windows/win32/api/
#include <stdlib.h>
#include <unistd.h>

#include "../runtime.h"

// GetStdHandle takes these values, which are -10, -11, -12 as a 32-bit DWORD.
#define STD_INPUT_HANDLE  0xFFFFFFF6u
#define STD_OUTPUT_HANDLE 0xFFFFFFF5u
#define STD_ERROR_HANDLE  0xFFFFFFF4u

#define INVALID_HANDLE_VALUE UINT64_MAX

// Handles 4, 8, 12 stand for stdin, stdout, stderr. Real Windows handles are
// also multiples of 4, which some programs rely on.
int handle_to_fd(uint64_t handle) {
    switch (handle) {
    case 4:  return STDIN_FILENO;
    case 8:  return STDOUT_FILENO;
    case 12: return STDERR_FILENO;
    default: return -1;
    }
}

// HANDLE GetStdHandle(DWORD nStdHandle)
SHIM(kernel32, GetStdHandle) {
    switch ((uint32_t)shim_arg(c, 0)) {
    case STD_INPUT_HANDLE:  shim_return(c, 4); break;
    case STD_OUTPUT_HANDLE: shim_return(c, 8); break;
    case STD_ERROR_HANDLE:  shim_return(c, 12); break;
    default:                shim_return(c, INVALID_HANDLE_VALUE); break;
    }
}

// BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
//                LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
SHIM(kernel32, WriteFile) {
    int fd = handle_to_fd(shim_arg(c, 0));
    const void *buf = (const void *)shim_arg(c, 1);
    uint32_t len = (uint32_t)shim_arg(c, 2);
    uint64_t written_ptr = shim_arg(c, 3);

    ssize_t n = fd < 0 ? -1 : write(fd, buf, len);
    if (written_ptr)
        W32(written_ptr, n < 0 ? 0 : (uint32_t)n);
    shim_return(c, n >= 0);  // TODO: SetLastError on failure
}

// void ExitProcess(UINT uExitCode)
SHIM(kernel32, ExitProcess) {
    exit((int)(uint32_t)shim_arg(c, 0));
}
