"""Minimal parser for 64-bit Windows executables (PE32+).

Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

File layout, in order:
    DOS header      "MZ" magic; the field at 0x3C points to the PE header
    PE signature    b"PE\\0\\0"
    COFF header     machine type, section count, optional header size
    Optional header entry point, image base, data directories (imports, relocs, ...)
    Section table   one 40-byte entry per section (.text, .data, .rdata, ...)
    Section data

Addresses inside a PE are usually RVAs (relative virtual addresses): offsets
from the image base once the file is loaded into memory. To read them from the
file on disk, find the section containing the RVA and convert it to a file
offset (see `PEFile.rva_to_offset`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

MACHINE_AMD64 = 0x8664
OPTIONAL_MAGIC_PE32_PLUS = 0x20B

# Indexes into the optional header's data directory array.
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_BASERELOC = 5

SUBSYSTEMS = {2: "GUI", 3: "console"}

# Section characteristics flags.
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000


class PEError(Exception):
    """The file is not a PE file this tool understands."""


@dataclass
class Section:
    name: str
    virtual_address: int  # RVA where the section is loaded
    virtual_size: int     # size in memory (may exceed raw_size; the rest is zero-filled)
    raw_offset: int       # where the section's bytes start in the file
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + max(self.virtual_size, self.raw_size)


@dataclass
class Import:
    dll: str
    name: str | None      # None when imported by ordinal only
    ordinal: int | None
    iat_rva: int          # slot the loader fills with the function's address


@dataclass
class PEFile:
    path: Path
    data: bytes
    machine: int
    image_base: int
    entry_rva: int
    subsystem: int
    size_of_image: int
    sections: list[Section]
    data_dirs: list[tuple[int, int]]  # (rva, size) pairs
    imports: list[Import] = field(default_factory=list)

    @property
    def subsystem_name(self) -> str:
        return SUBSYSTEMS.get(self.subsystem, f"unknown ({self.subsystem})")

    def rva_to_offset(self, rva: int) -> int:
        for s in self.sections:
            if s.contains_rva(rva):
                delta = rva - s.virtual_address
                if delta >= s.raw_size:
                    raise PEError(f"RVA {rva:#x} is in zero-filled memory, not in the file")
                return s.raw_offset + delta
        raise PEError(f"RVA {rva:#x} is not inside any section")

    def section_for_rva(self, rva: int) -> Section | None:
        return next((s for s in self.sections if s.contains_rva(rva)), None)

    def read_cstring(self, rva: int) -> str:
        start = self.rva_to_offset(rva)
        end = self.data.index(b"\0", start)
        return self.data[start:end].decode("ascii", errors="replace")


def parse(path: str | Path) -> PEFile:
    path = Path(path)
    data = path.read_bytes()

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError(f"{path}: not a Windows executable (missing MZ header)")
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise PEError(f"{path}: missing PE signature")

    coff = pe_offset + 4
    machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
    if machine != MACHINE_AMD64:
        raise PEError(f"{path}: machine type {machine:#x} is not x86-64 (only x86-64 is supported)")

    opt = coff + 20
    (magic,) = struct.unpack_from("<H", data, opt)
    if magic != OPTIONAL_MAGIC_PE32_PLUS:
        raise PEError(f"{path}: optional header magic {magic:#x} is not PE32+")

    (entry_rva,) = struct.unpack_from("<I", data, opt + 16)
    (image_base,) = struct.unpack_from("<Q", data, opt + 24)
    (size_of_image,) = struct.unpack_from("<I", data, opt + 56)
    (subsystem,) = struct.unpack_from("<H", data, opt + 68)
    (num_dirs,) = struct.unpack_from("<I", data, opt + 108)
    data_dirs = [struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in range(num_dirs)]

    sections = []
    table = opt + opt_size
    for i in range(num_sections):
        off = table + 40 * i
        raw_name, vsize, vaddr, raw_size, raw_off = struct.unpack_from("<8sIIII", data, off)
        (chars,) = struct.unpack_from("<I", data, off + 36)
        name = raw_name.rstrip(b"\0").decode("ascii", errors="replace")
        sections.append(Section(name, vaddr, vsize, raw_off, raw_size, chars))

    pe = PEFile(path, data, machine, image_base, entry_rva, subsystem, size_of_image, sections, data_dirs)
    pe.imports = _parse_imports(pe)
    return pe


def _parse_imports(pe: PEFile) -> list[Import]:
    """Walk the import directory: one 20-byte descriptor per DLL, terminated by zeros.

    Each descriptor points to a lookup table of 8-byte entries, one per function.
    If the top bit is set the function is imported by ordinal (a number);
    otherwise the entry is an RVA to a 2-byte hint followed by the function name.
    """
    if len(pe.data_dirs) <= DIR_IMPORT or pe.data_dirs[DIR_IMPORT][0] == 0:
        return []

    imports = []
    desc_rva = pe.data_dirs[DIR_IMPORT][0]
    while True:
        lookup_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", pe.data, pe.rva_to_offset(desc_rva))
        if name_rva == 0:
            break
        dll = pe.read_cstring(name_rva)
        # Old linkers leave the lookup table empty and only fill the IAT.
        table_rva = lookup_rva or iat_rva
        i = 0
        while True:
            (entry,) = struct.unpack_from("<Q", pe.data, pe.rva_to_offset(table_rva + 8 * i))
            if entry == 0:
                break
            slot = iat_rva + 8 * i
            if entry & (1 << 63):
                imports.append(Import(dll, None, entry & 0xFFFF, slot))
            else:
                imports.append(Import(dll, pe.read_cstring((entry & 0x7FFFFFFF) + 2), None, slot))
            i += 1
        desc_rva += 20
    return imports
