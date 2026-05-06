from __future__ import annotations

import argparse
import struct
from pathlib import Path


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_hello_elf(path: Path) -> None:
    base = 0x400000
    text_offset = 0x1000
    text_vaddr = base + text_offset

    main = bytes.fromhex("55 48 89 e5 b8 2a 00 00 00 5d c3")
    start_offset = len(main)
    rel32 = 0 - (start_offset + 5)
    start = b"\xe8" + struct.pack("<i", rel32) + bytes.fromhex("89 c7 b8 3c 00 00 00 0f 05")
    text = main + start

    strtab = b"\x00main\x00_start\x00"
    shstrtab = b"\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00"
    name_text = shstrtab.index(b".text")
    name_symtab = shstrtab.index(b".symtab")
    name_strtab = shstrtab.index(b".strtab")
    name_shstrtab = shstrtab.index(b".shstrtab")

    symtab = b"".join(
        [
            struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0),
            struct.pack("<IBBHQQ", 1, 0x12, 0, 1, text_vaddr, len(main)),
            struct.pack("<IBBHQQ", 6, 0x12, 0, 1, text_vaddr + start_offset, len(start)),
        ]
    )

    symtab_offset = align(text_offset + len(text), 8)
    strtab_offset = align(symtab_offset + len(symtab), 1)
    shstrtab_offset = align(strtab_offset + len(strtab), 1)
    shoff = align(shstrtab_offset + len(shstrtab), 8)

    phoff = 64
    ehsize = 64
    phentsize = 56
    shentsize = 64
    phnum = 1
    shnum = 5
    entry = text_vaddr + start_offset
    file_end = shoff + shnum * shentsize

    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        62,
        1,
        entry,
        phoff,
        shoff,
        0,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        4,
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, text_offset + len(text), text_offset + len(text), 0x1000)

    sections = [
        struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        struct.pack("<IIQQQQIIQQ", name_text, 1, 0x6, text_vaddr, text_offset, len(text), 0, 0, 16, 0),
        struct.pack("<IIQQQQIIQQ", name_symtab, 2, 0, 0, symtab_offset, len(symtab), 3, 1, 8, 24),
        struct.pack("<IIQQQQIIQQ", name_strtab, 3, 0, 0, strtab_offset, len(strtab), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", name_shstrtab, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0),
    ]

    data = bytearray(file_end)
    data[: len(ehdr)] = ehdr
    data[phoff : phoff + len(phdr)] = phdr
    data[text_offset : text_offset + len(text)] = text
    data[symtab_offset : symtab_offset + len(symtab)] = symtab
    data[strtab_offset : strtab_offset + len(strtab)] = strtab
    data[shstrtab_offset : shstrtab_offset + len(shstrtab)] = shstrtab
    data[shoff : shoff + shnum * shentsize] = b"".join(sections)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o755)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    build_hello_elf(args.output)


if __name__ == "__main__":
    main()

