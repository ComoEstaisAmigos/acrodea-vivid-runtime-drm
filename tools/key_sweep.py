#!/usr/bin/env python3
"""Test candidate AES keys against a VIVID package using a known-plaintext oracle.

The first encrypted bytes of a package are the ZIP local file header of the
first entry, and every field in it is recoverable from the central directory
(which sits in the plaintext tail). That gives ~40 bytes of known plaintext at
plaintext offset 0, so any key/mode guess is verifiable instantly.

Two sweeps are provided:
  * metadata  - keys derived from package/title strings and their hashes
  * embedded  - every byte-aligned 16/32-byte window in a binary (bootstrap.exe,
                libacrodea_runtime.so), i.e. "is the key hiding in the code?"

Both use an IV-independent CBC test in addition to ECB/CBC/CTR/OFB/CFB, so the
right key is found regardless of the IV:  AES_dec_K(C1) ^ C0 == P1

Requires: pycryptodome

Usage:
    python key_sweep.py <package.obb> metadata
    python key_sweep.py <package.obb> embedded <binary> [<binary> ...]
"""
import hashlib
import itertools
import os
import struct
import sys

from Crypto.Cipher import AES
from Crypto.Util import Counter

SHIFT = 0x20


def load_oracle(path):
    """Return (known_plaintext, header32, C0, C1)."""
    d = open(path, 'rb').read()
    eocd = d.rfind(b'PK\x05\x06')
    cd_off, = struct.unpack('<I', d[eocd + 16:eocd + 20])
    off = cd_off + SHIFT
    (_, _, vne, flag, method, mtime, mdate, crc, csize, usize,
     nlen, elen, clen, _, _, _, lho) = struct.unpack('<IHHHHHHIIIHHHHHII', d[off:off + 46])
    name = d[off + 46:off + 46 + nlen]
    kp = struct.pack('<IHHHHHIIIHH', 0x04034b50, vne, flag, method, mtime, mdate,
                     crc, csize, usize, nlen, 0) + name
    return kp, d[:SHIFT], d[SHIFT:SHIFT + 16], d[SHIFT + 16:SHIFT + 32]


def make_tests(kp, header, c0, c1):
    p0, p1 = kp[:16], kp[16:32]
    ivs = {'hdr0': header[:16], 'hdr16': header[16:32], 'zero': b'\x00' * 16}
    cbc_target = bytes(a ^ b for a, b in zip(p1, c0))   # == AES_dec_K(C1)

    def test(key):
        hits = []
        try:
            ecb = AES.new(key, AES.MODE_ECB)
            if ecb.decrypt(c0) == p0:
                hits.append('ECB')
            if ecb.decrypt(c1) == cbc_target:
                hits.append('CBC(iv-independent)')
        except Exception:
            return hits
        for name, iv in ivs.items():
            for build, label in (
                (lambda k: AES.new(k, AES.MODE_CBC, iv), 'CBC'),
                (lambda k: AES.new(k, AES.MODE_OFB, iv), 'OFB'),
                (lambda k: AES.new(k, AES.MODE_CFB, iv, segment_size=128), 'CFB'),
                (lambda k: AES.new(k, AES.MODE_CTR, counter=Counter.new(
                    128, initial_value=int.from_bytes(iv, 'big'))), 'CTR'),
            ):
                try:
                    if build(key).decrypt(c0) == p0:
                        hits.append('%s:%s' % (label, name))
                except Exception:
                    pass
        return hits
    return test


def metadata_candidates(extra_strings=()):
    cands = set()

    def add(kb):
        if len(kb) in (16, 24, 32):
            cands.add(bytes(kb))

    base = ['res.pak', 'config.xml', 'lib4_6_3', 'lib4_5_0', 'gamecenter',
            'vividruntime', 'acrodea', 'Acrodea', 'VIVID', 'ggee', '']
    base += list(extra_strings)
    for s in base:
        b = s.encode()
        add(b)
        add(hashlib.md5(b).digest())
        add(hashlib.sha256(b).digest())
        add(hashlib.sha1(b).digest()[:16])
        add(hashlib.md5(hashlib.md5(b).digest()).digest())
    for a, b in itertools.product(base, base):
        for sep in ('', '_', ':', '/', '-', '.'):
            s = (a + sep + b).encode()
            add(hashlib.md5(s).digest())
            add(hashlib.sha256(s).digest())
    add(b'\x00' * 16)
    add(b'\x00' * 32)
    add(b'\xff' * 16)
    return cands


def sweep_binary(path, test):
    """Every byte-aligned 16/32-byte window with enough distinct bytes."""
    blob = open(path, 'rb').read()
    seen = set()
    tested = 0
    hits = []
    for klen in (16, 32):
        for i in range(len(blob) - klen):
            kb = blob[i:i + klen]
            if len(set(kb)) < klen * 0.5 or kb in seen:
                continue
            seen.add(kb)
            tested += 1
            r = test(kb)
            if r:
                hits.append((hex(i), klen, kb.hex(), r))
    return tested, hits


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    kp, header, c0, c1 = load_oracle(sys.argv[1])
    print('known plaintext: %s' % kp[:32].hex())
    print('header (32B)   : %s' % header.hex())
    test = make_tests(kp, header, c0, c1)

    mode = sys.argv[2]
    total = 0
    all_hits = []
    if mode == 'metadata':
        extra = [os.path.basename(sys.argv[1])]
        cands = metadata_candidates(extra)
        for k in cands:
            r = test(k)
            if r:
                all_hits.append((k.hex(), r))
        total = len(cands)
        print('metadata candidates tested: %d' % total)
    elif mode == 'embedded':
        for path in sys.argv[3:]:
            n, hits = sweep_binary(path, test)
            total += n
            all_hits += [(path,) + h for h in hits]
            print('%-40s windows tested: %d' % (path.split('/')[-1], n))
    else:
        print(__doc__)
        return 1

    print()
    print('total tests: %d' % total)
    print('HITS: %s' % (all_hits if all_hits else 'NONE'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
