#!/usr/bin/env python3
import hashlib
import re
import struct
import sys
import zipfile
from pathlib import Path

DEX_RE = re.compile(r"^classes(?:[2-9][0-9]*)?\.dex$")


def read_uleb128(data: bytes, off: int):
    value = 0
    shift = 0
    for _ in range(5):
        if off >= len(data):
            raise ValueError("truncated uleb128")
        b = data[off]
        off += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return value, off
        shift += 7
    raise ValueError("invalid uleb128")


def class_descriptors(data: bytes):
    if len(data) < 112 or not data.startswith(b"dex\n"):
        raise ValueError("invalid DEX header")

    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 56)
    type_ids_size, type_ids_off = struct.unpack_from("<II", data, 64)
    class_defs_size, class_defs_off = struct.unpack_from("<II", data, 96)

    def dex_string(index: int):
        if index >= string_ids_size:
            raise ValueError("bad string index")
        (off,) = struct.unpack_from("<I", data, string_ids_off + index * 4)
        _, off = read_uleb128(data, off)
        end = data.find(b"\0", off)
        if end < 0:
            raise ValueError("unterminated DEX string")
        return data[off:end].decode("utf-8", "replace")

    result = set()
    for i in range(class_defs_size):
        (class_idx,) = struct.unpack_from("<I", data, class_defs_off + i * 32)
        if class_idx >= type_ids_size:
            raise ValueError("bad class type index")
        (string_idx,) = struct.unpack_from("<I", data, type_ids_off + class_idx * 4)
        result.add(dex_string(string_idx))
    return result


def source_classes(apk: Path):
    classes = set()
    hashes = set()
    with zipfile.ZipFile(apk) as zf:
        names = [n for n in zf.namelist() if DEX_RE.fullmatch(n)]
        if not names:
            raise SystemExit("source APK has no DEX")
        for name in names:
            data = zf.read(name)
            classes |= class_descriptors(data)
            hashes.add(hashlib.sha256(data).hexdigest())
    return classes, hashes


def verify(source_apk: Path, protected_apk: Path):
    original_classes, original_hashes = source_classes(source_apk)

    with zipfile.ZipFile(protected_apk) as zf:
        names = zf.namelist()
        dex_entries = [n for n in names if DEX_RE.fullmatch(n)]
        if dex_entries != ["classes.dex"]:
            raise SystemExit(
                f"protected APK must expose exactly one bootstrap classes.dex; got {dex_entries}"
            )

        bootstrap = zf.read("classes.dex")
        if len(bootstrap) > 128 * 1024:
            raise SystemExit(f"bootstrap DEX too large: {len(bootstrap)} bytes")

        protected_classes = class_descriptors(bootstrap)
        leaked_classes = sorted(original_classes & protected_classes)
        if leaked_classes:
            sample = "\n".join(leaked_classes[:25])
            raise SystemExit(
                "original source class definitions leaked into bootstrap DEX:\n" + sample
            )

        if hashlib.sha256(bootstrap).hexdigest() in original_hashes:
            raise SystemExit("protected classes.dex is byte-identical to a source DEX")

        for info in zf.infolist():
            if info.filename == "classes.dex" or info.is_dir():
                continue
            with zf.open(info) as fh:
                prefix = fh.read(8)
            if prefix.startswith(b"dex\n") or prefix.startswith(b"cdex"):
                raise SystemExit(
                    f"plaintext DEX sidecar detected outside bootstrap: {info.filename}"
                )

    print(
        "PASS: bootstrap-only DEX; "
        f"{len(original_classes)} source classes removed from static DEX surface; "
        f"{len(protected_classes)} bootstrap classes remain"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_protected_apk.py SOURCE.apk PROTECTED.apk")
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
