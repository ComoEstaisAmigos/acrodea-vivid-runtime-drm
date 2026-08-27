#!/usr/bin/env python3
"""Parse a VIVID expansion package (.obb) and report its encrypted region.

The package is a ZIP with a 32-byte header prepended, so every offset stored in
the ZIP structures is shifted by 0x20 relative to the file.

Usage:
    python parse_package.py <package.obb>
"""
import struct
import sys

SHIFT = 0x20


def parse(path):
    d = open(path, 'rb').read()
    print('size %d (0x%x)' % (len(d), len(d)))

    eocd = d.rfind(b'PK\x05\x06')
    n_entries, cd_size, cd_off = struct.unpack('<HII', d[eocd + 10:eocd + 20])
    print('EOCD @ 0x%x, %d entries, CD claims offset 0x%x (real: 0x%x)'
          % (eocd, n_entries, cd_off, cd_off + SHIFT))

    off = cd_off + SHIFT
    entries = []
    for _ in range(n_entries):
        hdr = struct.unpack('<IHHHHHHIIIHHHHHII', d[off:off + 46])
        if hdr[0] != 0x02014b50:
            raise ValueError('bad central header at 0x%x' % off)
        (_, _, vne, flag, method, mtime, mdate, crc, csize, usize,
         nlen, elen, clen, _, _, _, lho) = hdr
        name = d[off + 46:off + 46 + nlen]
        entries.append(dict(name=name, vne=vne, flag=flag, method=method,
                            mtime=mtime, mdate=mdate, crc=crc,
                            csize=csize, usize=usize, lho=lho))
        off += 46 + nlen + elen + clen

    print()
    print('%-22s %6s %10s %11s %11s %12s  %s'
          % ('name', 'method', 'crc32', 'csize', 'usize', 'LFH(+0x20)', 'state'))
    first_plain = None
    for e in entries:
        at = e['lho'] + SHIFT
        plain = d[at:at + 4] == b'PK\x03\x04'
        if plain and first_plain is None:
            first_plain = at
        print('%-22s %6d   %08x %11d %11d   0x%08x  %s'
              % (e['name'].decode('utf-8', 'replace'), e['method'], e['crc'],
                 e['csize'], e['usize'], at, 'plaintext' if plain else 'ENCRYPTED'))

    if first_plain:
        print()
        print('encrypted region: [0x00000000, 0x%08x)  = %d bytes'
              % (first_plain, first_plain))
        print('plaintext length: 0x%x (%d bytes), ciphertext is %d bytes longer'
              % (first_plain - SHIFT, first_plain - SHIFT, SHIFT))
        print('padding: %s (plaintext length %% 16 = %d)'
              % ('none' if (first_plain - SHIFT) % 16 else 'possible',
                 (first_plain - SHIFT) % 16))
    return entries


def build_known_plaintext(entry):
    """Rebuild an entry's ZIP local file header from its central-directory record.

    Every field is recoverable, which yields ~40 bytes of known plaintext at
    plaintext offset 0 for the first entry.
    """
    return struct.pack('<IHHHHHIIIHH', 0x04034b50, entry['vne'], entry['flag'],
                       entry['method'], entry['mtime'], entry['mdate'],
                       entry['crc'], entry['csize'], entry['usize'],
                       len(entry['name']), 0) + entry['name']


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(1)
    ents = parse(sys.argv[1])
    print()
    print('known plaintext for first entry (%s):' % ents[0]['name'].decode())
    print(' ', build_known_plaintext(ents[0]).hex())
