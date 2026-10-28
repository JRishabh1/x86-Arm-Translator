# Test programs are cross-compiled from C with MinGW: brew install mingw-w64
MINGW ?= x86_64-w64-mingw32-gcc
FIXTURES := tests/fixtures

.PHONY: all fixtures runtime test clean

all: fixtures runtime test

# tiny.exe skips the C runtime: entry point `start`, kernel32 only.
$(FIXTURES)/tiny.exe: $(FIXTURES)/tiny.c
	$(MINGW) -O1 -nostdlib -e start -o $@ $< -lkernel32

$(FIXTURES)/%.exe: $(FIXTURES)/%.c
	$(MINGW) -O1 -o $@ $<

fixtures: $(patsubst %.c,%.exe,$(wildcard $(FIXTURES)/*.c))

# Compile-check the runtime until `build` links it into real programs.
runtime:
	clang -std=c11 -Wall -Wextra -Werror -fsyntax-only runtime/win32/*.c

test: fixtures
	python3 -m unittest discover -s tests -v

clean:
	rm -f $(FIXTURES)/*.exe
