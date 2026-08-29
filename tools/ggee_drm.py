#!/usr/bin/env python3
"""
Acrodea VIVID Runtime / G-Gee DRM - offline rights-object recovery.

Recovers a title's content encryption key (CEK) from a preserved device install,
with no server contact, and decrypts the DRM-protected content with it.

Chain (every step is verified by an AES-GCM authentication tag):

  1. device identity   "MACW:" + wifi_mac_without_colons     (or "IMEI:" + imei)
                       -> the MAC is recoverable from shared_prefs/PREF_MAC_ADDR
  2. keystore.dat      AES-256-GCM, key = KS_CONST xor identity (cyclic, 16 B),
                       zero-padded to 32 B; IV = first 16 B; tag = last 16 B
  3. keystore entry 0x5d66a128, xor identity (cyclic) -> PKCS#8 RSA private key
  4. datastore.dat     same GCM scheme with DS_CONST -> <ro_response> XML
  5. <key>             RSA-OAEP(SHA-1) with the device key -> 32-byte session key
  6. <payload>         AES-256-GCM with the session key    -> <ro> XML -> <cek>
  7. content           AES-256-GCM with the CEK; IV = first 16 B; tag = last 16 B

The two 16-byte constants are lifted from bootstrap.exe and are shared by every
title (the same values appear in the lib4_5_0 bootstrap and in the older
unwrapped one), so only the per-device identity varies.

Usage:
  ggee_drm.py ro       <runtime_dir> --mac 00:11:22:33:44:55 [--out DIR]
  ggee_drm.py ro       <runtime_dir> --prefs <shared_prefs.xml> [--out DIR]
  ggee_drm.py decrypt  <cek_b64> <infile> <outfile>
  ggee_drm.py prefs    <shared_prefs.xml>
"""
import argparse
import base64
import os
import re
import struct

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1

# 16-byte constants from bootstrap.exe (little-endian words, in memory order)
KS_CONST = struct.pack('<4I', 0x544917fd, 0xb45ad25e, 0xc9c69866, 0x91e83cf4)
DS_CONST = struct.pack('<4I', 0xb1cf189a, 0x63eaa6ba, 0x03923066, 0x4178a15b)
KS_PRIVKEY_ENTRY = 0x5d66a128
# AES/ECB/PKCS5 keys hardcoded in classes.dex, used for SharedPreferences
PREF_KEYS = [b'j5d!sf%w08gfy#tf', b'nvme0oda4tyu3gjs']


def xor_cyclic(data, pad):
    return bytes(b ^ pad[i % len(pad)] for i, b in enumerate(data))


def gcm_open(blob, key16):
    """AES-256-GCM: key = key16 || 16 zero bytes, IV = blob[:16], tag = blob[-16:]."""
    key = key16 + b'\0' * 16
    return AES.new(key, AES.MODE_GCM, nonce=blob[:16], mac_len=16) \
              .decrypt_and_verify(blob[16:-16], blob[-16:])


def parse_store(plain):
    """u32 count, then count * (u32 type, u32 id, u32 len, u8 data[len])."""
    count, = struct.unpack_from('<I', plain, 0)
    off, out = 4, []
    for _ in range(count):
        typ, eid, ln = struct.unpack_from('<III', plain, off)
        off += 12
        out.append((typ, eid, plain[off:off + ln]))
        off += ln
    return out


def read_prefs(path):
    """Decrypt an app SharedPreferences XML; returns {name: plaintext}."""
    xml = open(path, 'r', encoding='utf-8', errors='replace').read()
    out = {}
    for m in re.finditer(r'name="([^"]+)"[^>]*>([^<]*)<', xml):
        name, val = m.group(1), m.group(2)
        for k in PREF_KEYS:
            try:
                raw = base64.b64decode(''.join(val.split()))
                if not raw or len(raw) % 16:
                    continue
                dec = AES.new(k, AES.MODE_ECB).decrypt(raw)
                pad = dec[-1]
                if 1 <= pad <= 16 and dec[-pad:] == bytes([pad]) * pad:
                    dec = dec[:-pad]
                if all(9 <= c < 127 for c in dec):
                    out[name] = dec.decode('latin1')
                    break
            except Exception:
                pass
    return out


def identities(mac=None, imei=None):
    """Candidate device-identity strings, in the order the runtime would pick."""
    out = []
    if imei:
        out.append('IMEI:' + imei)
    if mac:
        bare = mac.replace(':', '').replace('-', '')
        out += ['MACW:' + bare, 'MACW:' + bare.lower(), 'MACW:' + bare.upper()]
    return list(dict.fromkeys(out))


def recover(runtime_dir, ident_list, outdir=None):
    ks_blob = open(os.path.join(runtime_dir, 'keystore.dat'), 'rb').read()
    ds_blob = open(os.path.join(runtime_dir, 'datastore.dat'), 'rb').read()

    ident = ks = None
    for cand in ident_list:
        try:
            ks = gcm_open(ks_blob, xor_cyclic(KS_CONST, cand.encode()))
            ident = cand
            break
        except ValueError:
            continue
    if ks is None:
        raise SystemExit('keystore.dat did not open with any candidate identity: %r'
                         % (ident_list,))
    print('[+] device identity : %r' % ident)
    print('[+] keystore.dat    : opened, %d bytes' % len(ks))

    pad = ident.encode()
    priv_der = pub_der = None
    for typ, eid, val in parse_store(ks):
        if eid == KS_PRIVKEY_ENTRY:
            priv_der = xor_cyclic(val, pad)
        elif val[:1] == b'\x30':
            pub_der = val
    key = RSA.import_key(priv_der)
    print('[+] device RSA key  : %d bits, e=%d' % (key.size_in_bits(), key.e))
    if pub_der:
        assert RSA.import_key(pub_der).n == key.n, 'public/private mismatch'

    ds = gcm_open(ds_blob, xor_cyclic(DS_CONST, pad))
    resp = ds[16:].decode('utf-8', 'replace')
    print('[+] datastore.dat   : opened, %d bytes' % len(ds))

    sess = PKCS1_OAEP.new(key, hashAlgo=SHA1).decrypt(
        base64.b64decode(re.search(r'<key>(.*?)</key>', resp, re.S).group(1)))
    print('[+] session key     : %s' % sess.hex())

    payload = base64.b64decode(re.search(r'<payload>(.*?)</payload>', resp, re.S).group(1))
    ro = AES.new(sess, AES.MODE_GCM, nonce=payload[:16], mac_len=16) \
            .decrypt_and_verify(payload[16:-16], payload[-16:]).decode('utf-8', 'replace')
    print('[+] rights object   :\n' + ro)

    cek = re.search(r'<cek[^>]*>(.*?)</cek>', ro, re.S)
    if cek:
        b64 = cek.group(1).strip()
        print('[+] CEK (base64)    : %s' % b64)
        print('[+] CEK (hex)       : %s' % base64.b64decode(b64).hex())

    if outdir:
        os.makedirs(outdir, exist_ok=True)
        for n, b in (('keystore_plain.bin', ks), ('datastore_plain.bin', ds),
                     ('device_private.der', priv_der), ('ro.xml', ro.encode()),
                     ('ro_response.xml', resp.encode()),
                     ('device_private.pem', key.export_key())):
            open(os.path.join(outdir, n), 'wb').write(b)
        print('[+] written to      : %s' % outdir)
    return ro


def decrypt_content(cek_b64, src, dst):
    cek = base64.b64decode(cek_b64)
    blob = open(src, 'rb').read()
    pt = AES.new(cek, AES.MODE_GCM, nonce=blob[:16], mac_len=16) \
            .decrypt_and_verify(blob[16:-16], blob[-16:])
    open(dst, 'wb').write(pt)
    print('[+] %s -> %s (%d bytes, GCM tag verified)' % (src, dst, len(pt)))
    print('[+] magic: %s' % pt[:8].hex(' '))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('ro', help='recover the rights object / CEK from a device install')
    p.add_argument('runtime_dir', help='dir holding keystore.dat and datastore.dat')
    p.add_argument('--mac', help='device wifi MAC, e.g. 00:11:22:33:44:55')
    p.add_argument('--imei', help='device IMEI (used instead of MAC when present)')
    p.add_argument('--prefs', help='shared_prefs xml to read PREF_MAC_ADDR from')
    p.add_argument('--out', help='write decrypted artefacts here')

    p = sub.add_parser('decrypt', help='decrypt DRM content with a CEK')
    p.add_argument('cek')
    p.add_argument('src')
    p.add_argument('dst')

    p = sub.add_parser('prefs', help='decrypt an app SharedPreferences xml')
    p.add_argument('xml')

    a = ap.parse_args()
    if a.cmd == 'prefs':
        for k, v in read_prefs(a.xml).items():
            print('%-20s %s' % (k, v))
    elif a.cmd == 'decrypt':
        decrypt_content(a.cek, a.src, a.dst)
    else:
        mac, imei = a.mac, a.imei
        if a.prefs:
            pr = read_prefs(a.prefs)
            mac = mac or pr.get('PREF_MAC_ADDR')
            print('[i] PREF_MAC_ADDR from shared_prefs: %s' % mac)
        if not (mac or imei):
            raise SystemExit('need --mac, --imei or --prefs')
        recover(a.runtime_dir, identities(mac, imei), a.out)


if __name__ == '__main__':
    main()
