#!/usr/bin/env python3
"""Unwrap the Acrodea VIVID `35 21 14 14` LZMA container.

Used by every VIVID library, bootstrap.exe, and each .rpk member.

    magic  35 21 14 14   (4 bytes)
    size   uint32 LE     (uncompressed size)
    body   raw LZMA1 ("alone") stream

Usage:
    python unwrap_lzma.py <input> <output>
"""
import lzma
import sys

MAGIC = b'\x35\x21\x14\x14'


def unwrap(data: bytes) -> bytes:
    if data[:4] != MAGIC:
        raise ValueError('bad magic %s (expected %s)' % (data[:4].hex(), MAGIC.hex()))
    declared = int.from_bytes(data[4:8], 'little')
    p = data[8:]
    # The size field must be replaced with 0xFF*8 ("unknown"). The stream carries an
    # end-of-stream marker, and liblzma rejects a known size together with a marker.
    out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
        p[:5] + b'\xff' * 8 + p[5:]
    )
    if len(out) != declared:
        print('warning: declared %d, got %d' % (declared, len(out)), file=sys.stderr)
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    data = open(sys.argv[1], 'rb').read()
    out = unwrap(data)
    open(sys.argv[2], 'wb').write(out)
    kind = 'ARM ELF' if out[:4] == b'\x7fELF' else repr(out[:8])
    print('%s -> %s (%d bytes, %s)' % (sys.argv[1], sys.argv[2], len(out), kind))
    return 0


if __name__ == '__main__':
    sys.exit(main())
