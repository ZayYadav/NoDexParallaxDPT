#!/usr/bin/env python3
import hashlib
import io
import re
import struct
import sys
import zipfile
from pathlib import Path

DEX_RE = re.compile(r"^classes(?:[2-9][0-9]*)?\.dex$")
MAX_BOOTSTRAP_DEX = 128 * 1024
MAX_EMBEDDED_DEX_ARCHIVE = 768 * 1024 * 1024


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

    def checked_range(off: int, size: int):
        if off < 0 or size < 0 or off > len(data) or size > len(data) - off:
            raise ValueError("DEX table outside bootstrap boundary")

    checked_range(string_ids_off, string_ids_size * 4)
    checked_range(type_ids_off, type_ids_size * 4)
    checked_range(class_defs_off, class_defs_size * 32)

    def dex_string(index: int):
        if index >= string_ids_size:
            raise ValueError("bad string index")
        (off,) = struct.unpack_from("<I", data, string_ids_off + index * 4)
        if off >= len(data):
            raise ValueError("DEX string outside bootstrap boundary")
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
    dex_count = 0
    with zipfile.ZipFile(apk) as zf:
        names = [n for n in zf.namelist() if DEX_RE.fullmatch(n)]
        if not names:
            raise SystemExit("source APK has no DEX")
        for name in names:
            data = zf.read(name)
            classes |= class_descriptors(data)
            hashes.add(hashlib.sha256(data).hexdigest())
            dex_count += 1
    return classes, hashes, dex_count


def split_combined_classes(blob: bytes):
    if len(blob) < 116 or not blob.startswith(b"dex\n"):
        raise SystemExit("protected classes.dex is invalid")
    embedded_len = int.from_bytes(blob[-4:], "big")
    if embedded_len <= 0 or embedded_len > MAX_EMBEDDED_DEX_ARCHIVE:
        raise SystemExit(f"invalid appended hollowed DEX archive length: {embedded_len}")
    bootstrap_len = len(blob) - embedded_len - 4
    if bootstrap_len < 112 or bootstrap_len > MAX_BOOTSTRAP_DEX:
        raise SystemExit(f"bootstrap DEX prefix outside size policy: {bootstrap_len} bytes")

    bootstrap = blob[:bootstrap_len]
    embedded = blob[bootstrap_len:bootstrap_len + embedded_len]
    if not embedded.startswith(b"PK"):
        raise SystemExit("appended hollowed DEX archive is not ZIP-formatted")
    return bootstrap, embedded


def verify_embedded_hollowed_archive(embedded: bytes, source_hashes):
    with zipfile.ZipFile(io.BytesIO(embedded)) as zf:
        if not zf.comment.startswith(b"PXH1:") or len(zf.comment) != 69:
            raise SystemExit("embedded hollowed DEX archive lacks PXH1 authentication marker")
        dex_entries = [n for n in zf.namelist() if DEX_RE.fullmatch(n)]
        if not dex_entries:
            raise SystemExit("embedded hollowed DEX archive contains no DEX")
        for name in dex_entries:
            data = zf.read(name)
            if not data.startswith(b"dex\n"):
                raise SystemExit(f"invalid embedded hollowed DEX: {name}")
            if hashlib.sha256(data).hexdigest() in source_hashes:
                raise SystemExit(f"source DEX survived byte-identical in protected payload: {name}")
        return len(dex_entries)


def verify(source_apk: Path, protected_apk: Path):
    original_classes, original_hashes, source_dex_count = source_classes(source_apk)

    with zipfile.ZipFile(protected_apk) as zf:
        names = zf.namelist()
        dex_entries = [n for n in names if DEX_RE.fullmatch(n)]
        if dex_entries != ["classes.dex"]:
            raise SystemExit(
                f"protected APK must expose exactly one classes.dex entry; got {dex_entries}"
            )

        combined = zf.read("classes.dex")
        bootstrap, embedded = split_combined_classes(combined)
        protected_classes = class_descriptors(bootstrap)

        leaked_classes = sorted(original_classes & protected_classes)
        if leaked_classes:
            sample = "\n".join(leaked_classes[:25])
            raise SystemExit(
                "source class definitions leaked into bootstrap DEX:\n" + sample
            )

        embedded_dex_count = verify_embedded_hollowed_archive(embedded, original_hashes)

        vault_name = "assets/Parallax.love"
        if vault_name not in names:
            raise SystemExit("encrypted method-body vault is missing")
        vault = zf.read(vault_name)
        if len(vault) < 32 or not vault.startswith(b"PCI3"):
            raise SystemExit("method-body vault is not PCI3 sealed")

        for info in zf.infolist():
            if info.filename == "classes.dex" or info.is_dir():
                continue
            with zf.open(info) as fh:
                prefix = fh.read(8)
            if prefix.startswith(b"dex\n") or prefix.startswith(b"cdex"):
                raise SystemExit(
                    f"plaintext DEX sidecar detected outside combined classes.dex: {info.filename}"
                )

    print(
        "PASS: one combined classes.dex; "
        f"bootstrap={len(bootstrap)} bytes/{len(protected_classes)} protection classes; "
        f"embedded hollowed DEXes={embedded_dex_count} (source={source_dex_count}); "
        "PCI3 method vault present; no separate plaintext DEX sidecars"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_protected_apk.py SOURCE.apk PROTECTED.apk")
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
