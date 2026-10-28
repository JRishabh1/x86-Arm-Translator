// The smallest useful Windows program: no C runtime, three kernel32 imports.
// Milestone 1 target for the recompiler.
#include <windows.h>

void start(void) {
    DWORD written;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(out, "hello from tiny.exe\n", 20, &written, NULL);
    ExitProcess(0);
}
