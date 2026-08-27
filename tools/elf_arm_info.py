#!/usr/bin/env python3
"""Report an ARM ELF's .ARM.attributes CPU architecture and e_flags.

Confirms that VIVID binaries predate armeabi-v7a:
    libacrodea_runtime.so  -> Tag_CPU_arch 6 (ARM v6)
    bootstrap.exe          -> Tag_CPU_arch 4 (ARMv5TE)

Usage:
    python elf_arm_info.py <file.so|file.elf>
"""
import struct
import sys

ARCH = {0: 'Pre-v4', 1: 'v4', 2: 'v4T', 3: 'v5T', 4: 'v5TE', 5: 'v5TEJ', 6: 'v6',
        7: 'v6KZ', 8: 'v6T2', 9: 'v6K', 10: 'v7', 11: 'v6-M', 12: 'v6S-M',
        13: 'v7E-M', 14: 'v8'}


def _uleb(b, i):
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7f) << s
        if not x & 0x80:
            return r, i
        s += 7


def info(path):
    d = open(path, 'rb').read()
    if d[:4] != b'\x7fELF':
        return 'not an ELF'
    e_shoff, = struct.unpack('<I', d[0x20:0x24])
    e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHH', d[0x2e:0x34])
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        nm, _, _, _, off, sz = struct.unpack('<IIIIII', d[o:o + 24])
        secs.append((nm, off, sz))
    strt = d[secs[e_shstrndx][1]:secs[e_shstrndx][1] + secs[e_shstrndx][2]]

    attr = None
    for nm, off, sz in secs:
        if strt[nm:strt.index(b'\x00', nm)] == b'.ARM.attributes':
            attr = d[off:off + sz]
    e_flags, = struct.unpack('<I', d[0x24:0x28])
    if not attr:
        return 'no .ARM.attributes, e_flags=0x%x' % e_flags

    p = attr.index(b'aeabi\x00') + 6
    p += 1                                     # Tag_File
    size, = struct.unpack('<I', attr[p:p + 4])
    p += 4
    end = p - 5 + size
    vals = {}
    while p < end:
        t, p = _uleb(attr, p)
        if t in (4, 5, 32, 65, 67):            # string-valued tags
            s = attr.index(b'\x00', p)
            vals[t] = attr[p:s]
            p = s + 1
        else:
            vals[t], p = _uleb(attr, p)
    arch = vals.get(6, '?')
    return ('Tag_CPU_arch=%s (%s), Tag_CPU_name=%r, e_flags=0x%x'
            % (arch, ARCH.get(arch, '?'), vals.get(5), e_flags))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for path in sys.argv[1:]:
        print('%-40s %s' % (path.split('/')[-1], info(path)))
