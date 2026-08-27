#!/usr/bin/env python3
"""Reverse the fs_packed inner scramble (`fs_packed::fsPacked_randomize`).

Entries inside res.pak are XOR-scrambled with a keyless LCG using the classic
ANSI-C rand() constants. This is the layer *behind* the AES: once an
AES-decrypted package exists, entries are fully recoverable with no key.

Usage (as a library):
    from fspacked_descramble import descramble
    plain = descramble(entry_position, scrambled_bytes)
"""
import sys

MULT = 0x41c64e6d
INC = 0x3039
M32 = 0xffffffff


def descramble(pos: int, buf: bytes) -> bytes:
    """XOR is symmetric, so this both scrambles and descrambles."""
    b = bytearray(buf)
    seed = ((pos & 0x7fffffff) * MULT + INC) & M32
    i, n = 0, len(b)
    while n - i > 1:
        seed = (seed * MULT + INC) & M32
        w = (b[i] | (b[i + 1] << 8)) ^ ((seed >> 8) & 0xffff)
        b[i] = w & 0xff
        b[i + 1] = (w >> 8) & 0xff
        i += 2
    if i < n:
        b[i] ^= ((seed * MULT + INC) >> 8) & 0xff
    return bytes(b)


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(__doc__)
        print('CLI usage: python fspacked_descramble.py <pos> <in> <out>')
        sys.exit(1)
    pos = int(sys.argv[1], 0)
    data = open(sys.argv[2], 'rb').read()
    open(sys.argv[3], 'wb').write(descramble(pos, data))
    print('descrambled %d bytes at pos=%d' % (len(data), pos))
