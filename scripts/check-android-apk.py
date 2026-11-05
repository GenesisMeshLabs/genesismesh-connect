"""Check 64-bit APK native ELF/RELRO and uncompressed ZIP 16 KiB alignment.

Uses only Python's standard library; never executes or extracts native code.
https://developer.android.com/guide/practices/page-sizes
"""
import argparse
import struct
import zipfile
from pathlib import Path

PAGE = 16384
PT_LOAD, PT_GNU_RELRO = 1, 0x6474E552


def elf_headers(stream, size):
    header = stream.read(64)
    if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 library")
    offset = struct.unpack_from("<Q", header, 32)[0]
    entry_size, count = struct.unpack_from("<HH", header, 54)
    if entry_size != 56 or not 0 < count <= 1024 or offset + entry_size * count > min(size, 65536):
        raise ValueError("invalid or oversized ELF program header table")
    stream.seek(offset)
    data = stream.read(entry_size * count)
    if len(data) != entry_size * count:
        raise ValueError("truncated ELF program headers")
    return [struct.unpack_from("<IIQQQQQQ", data, n * entry_size) for n in range(count)]


def check_elf(stream, size):
    headers = elf_headers(stream, size)
    loads = [h for h in headers if h[0] == PT_LOAD]
    if not loads:
        raise ValueError("no LOAD segments")
    for _, _, offset, address, _, file_size, memory_size, alignment in loads:
        if alignment < PAGE or alignment & (alignment - 1) or (offset - address) % PAGE:
            raise ValueError(f"LOAD segment not 16 KiB aligned (alignment={alignment:#x})")
        if file_size > memory_size or offset + file_size > size:
            raise ValueError("invalid LOAD segment bounds")
    for h in headers:
        if h[0] != PT_GNU_RELRO:
            continue
        end = h[3] + h[6]
        if end % PAGE and not any(p[3] <= h[3] and p[3] + p[6] == end for p in loads):
            raise ValueError("RELRO end shares a partial 16 KiB page with following data")
    return len(loads)


def check_apk(path):
    checked = []
    with zipfile.ZipFile(path) as archive, path.open("rb") as raw:
        for entry in archive.infolist():
            if not entry.filename.startswith(("lib/arm64-v8a/", "lib/x86_64/")) or not entry.filename.endswith(".so"):
                continue
            with archive.open(entry) as stream:
                count = check_elf(stream, entry.file_size)
            if entry.compress_type == zipfile.ZIP_STORED:
                raw.seek(entry.header_offset)
                local = raw.read(30)
                if len(local) != 30 or local[:4] != b"PK\x03\x04":
                    raise ValueError("invalid ZIP local header")
                name_length, extra_length = struct.unpack_from("<HH", local, 26)
                if (entry.header_offset + 30 + name_length + extra_length) % PAGE:
                    raise ValueError(f"{entry.filename}: uncompressed ZIP entry is not 16 KiB aligned")
            checked.append((entry.filename, count))
    if not checked:
        raise ValueError("APK has no 64-bit native libraries to qualify")
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk", type=Path)
    args = parser.parse_args()
    try:
        for name, count in check_apk(args.apk):
            print(f"16 KiB ELF/RELRO/ZIP passed: {name} ({count} LOAD segments)")
    except (ValueError, OSError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Android alignment check failed: {error}\n")


if __name__ == "__main__":
    main()
