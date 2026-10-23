#!/usr/bin/env python3
"""Post-link seal for ParallaxLover: hash .text into .data.parallax_seal."""
import hashlib
import struct
import sys

MAGIC = b"PXHASH01"
TAIL = b"PXEND001"


def read_elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    if data[5] != 1:
        raise ValueError("expected little-endian ELF")
    if elf_class == 2:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        shoff = struct.unpack_from("<Q", data, 40)[0]
        phentsize = struct.unpack_from("<H", data, 54)[0]
        phnum = struct.unpack_from("<H", data, 56)[0]
        shentsize = struct.unpack_from("<H", data, 58)[0]
        shnum = struct.unpack_from("<H", data, 60)[0]
        shstrndx = struct.unpack_from("<H", data, 62)[0]
    elif elf_class == 1:
        phoff = struct.unpack_from("<I", data, 28)[0]
        shoff = struct.unpack_from("<I", data, 32)[0]
        phentsize = struct.unpack_from("<H", data, 42)[0]
        phnum = struct.unpack_from("<H", data, 44)[0]
        shentsize = struct.unpack_from("<H", data, 46)[0]
        shnum = struct.unpack_from("<H", data, 48)[0]
        shstrndx = struct.unpack_from("<H", data, 50)[0]
    else:
        raise ValueError("unsupported ELF class")
    if shoff == 0 or shentsize == 0 or shnum == 0 or shstrndx >= shnum:
        raise ValueError("missing section headers")
    return elf_class, phoff, phentsize, phnum, shoff, shentsize, shnum, shstrndx


def section_at(data, elf_class, shoff, shentsize, index):
    base = shoff + index * shentsize
    if elf_class == 2:
        name, stype = struct.unpack_from("<II", data, base)
        addr, offset, size = struct.unpack_from("<QQQ", data, base + 16)
    else:
        name, stype = struct.unpack_from("<II", data, base)
        addr, offset, size = struct.unpack_from("<III", data, base + 12)
    return name, stype, addr, offset, size


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: seal_native_hash.py <shared-library>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, "rb") as handle:
        data = bytearray(handle.read())

    try:
        elf_class, _, _, _, shoff, shentsize, shnum, shstrndx = read_elf(data)
        _, _, _, str_offset, str_size = section_at(
            data, elf_class, shoff, shentsize, shstrndx
        )
        strings = data[str_offset:str_offset + str_size]
        text = None
        for index in range(shnum):
            name_off, stype, addr, offset, size = section_at(
                data, elf_class, shoff, shentsize, index
            )
            if name_off >= len(strings):
                continue
            name = strings[name_off:strings.find(b"\x00", name_off)]
            if name == b".text" and stype == 1:
                text = (addr, offset, size)
                break
        if text is None:
            raise ValueError(".text section not found")
        text_addr, text_offset, text_size = text
        if text_size == 0 or text_offset + text_size > len(data):
            raise ValueError("invalid .text range")
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1

    digest = hashlib.sha256(data[text_offset:text_offset + text_size]).digest()
    marker = data.find(MAGIC)
    if marker < 0 or data.find(MAGIC, marker + 1) >= 0:
        print("native hash marker missing or duplicated", file=sys.stderr)
        return 1
    if bytes(data[marker + 56:marker + 64]) != TAIL:
        print("native hash tail missing", file=sys.stderr)
        return 1

    struct.pack_into("<Q", data, marker + 8, text_addr)
    struct.pack_into("<Q", data, marker + 16, text_size)
    data[marker + 24:marker + 56] = digest
    with open(path, "wb") as handle:
        handle.write(data)
    print("sealed %s (.text %d bytes @ 0x%x)" % (path, text_size, text_addr))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
