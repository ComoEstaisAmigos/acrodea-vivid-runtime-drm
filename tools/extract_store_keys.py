#!/usr/bin/env python3
"""
Lift the keystore/datastore key constants out of an Acrodea VIVID `bootstrap.exe`.

bootstrap.exe builds each store key like this (Thumb, ARMv4T):

    std::string k("oYga9NQJHQqbnZhe", 16);   // placeholder - the bytes are
    *(u32*)&k[0]  = A0; ... *(u32*)&k[12] = A3;   // decoy set, overwritten
    *(u32*)&k[8]  = B2; *(u32*)&k[4] = B1;        // real set
    *(u32*)&k[12] = B3; *(u32*)&k[0] = B0;
    for (i = 0, p = id.begin(); i < k.size(); ++i, ++p) {
        if (p == id.end()) p = id.begin();
        k[i] ^= *p;                                // id = kdQueryAttribcv(0x24d)
    }

kdQueryAttribcv(0x24d) resolves, via libacrodea_runtime.so's
__kdExtensionDeviceAttribcv, to __acbDeviceGetIMEI() -> the Java
MyDevice.getImei(), which returns "IMEI:"+imei or "MACW:"+mac_without_colons.

This script finds every such site by its `stm r2!, {r0}` marker, reads the eight
pc-relative literals that follow, and prints both constant sets. The real (B) set
is stored in literal-pool order [+8, +4, +12, +0].

Usage:  extract_store_keys.py <bootstrap.elf>

If the input is still `35 21 14 14`-wrapped, unwrap it first:
    p = data[8:]
    lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(p[:5]+b'\\xff'*8+p[5:])
"""
import struct
import sys

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM, ARM_REG_PC


def sections(data):
    e_shoff, = struct.unpack_from('<I', data, 32)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', data, 46)
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        nm, ty, fl, ad, off, sz = struct.unpack_from('<IIIIII', data, o)
        secs.append(dict(nameoff=nm, addr=ad, off=off, size=sz))
    stroff = secs[e_shstrndx]['off']
    for s in secs:
        end = data.index(b'\0', stroff + s['nameoff'])
        s['name'] = data[stroff + s['nameoff']:end].decode()
    return secs


def main():
    data = open(sys.argv[1], 'rb').read()
    if data[:4] != b'\x7fELF':
        raise SystemExit('not an ELF - unwrap the 35 21 14 14 + LZMA container first')
    text = next(s for s in sections(data) if s['name'] == '.text')
    buf = data[text['off']:text['off'] + text['size']]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True

    seen = {}
    for i in range(0, len(buf) - 2, 2):
        if buf[i] != 0x01 or buf[i + 1] != 0xc2:      # stm r2!, {r0}
            continue
        site = text['addr'] + i
        lits = []
        for ins in md.disasm(buf[i - 8:i + 0x58], site - 8):
            if not (ins.mnemonic.startswith('ldr') and '[pc' in ins.op_str):
                continue
            for op in ins.operands:
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    la = ((ins.address + 4) & ~3) + op.mem.disp
                    fo = la - text['addr'] + text['off']
                    lits.append(struct.unpack_from('<I', data, fo)[0])
        if len(lits) < 8:
            continue
        decoy = (lits[0], lits[2], lits[3], lits[1])          # +0 +4 +8 +12
        real = (lits[7], lits[5], lits[4], lits[6])           # +0 +4 +8 +12
        seen.setdefault(real, []).append((site, decoy))

    for real, uses in seen.items():
        key = struct.pack('<4I', *real)
        print('constant  %s' % key.hex())
        print('  words   ' + ' '.join('0x%08x' % w for w in real))
        print('  decoy   ' + ' '.join('0x%08x' % w for w in uses[0][1]))
        print('  sites   ' + ' '.join('0x%06x' % s for s, _ in uses))
    if not seen:
        print('no key-construction sites found')


if __name__ == '__main__':
    main()
