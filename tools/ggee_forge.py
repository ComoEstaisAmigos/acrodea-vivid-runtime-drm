#!/usr/bin/env python3
"""
Re-issue an Acrodea VIVID / G-Gee rights object for a different device.

Takes a decrypted `<ro>` XML (as produced by `ggee_drm.py ro --out`) and mints a
fresh `keystore.dat` + `datastore.dat` pair bound to a *chosen* device identity,
carrying the same CEK/PEK. Nothing from the original device is reused: a new
RSA-1024 keypair (e=17) is generated, a new session key is drawn, and
`<device_id>` is recomputed for the target.

This is possible because the rights object carries **no server signature**. Its
only integrity check is the AES-GCM tag over `<payload>`, computed with a session
key that the issuer chooses and wraps to the device's own public key - and that
public key lives in the device's own keystore. Once the CEK is known, the whole
envelope is reproducible.

Usage:
  ggee_forge.py --ro ro.xml --mac 00:11:22:33:44:55 --out DIR
  ggee_forge.py --ro ro.xml --imei 350000000000000  --out DIR

Verify the result with:
  ggee_drm.py ro DIR --mac 00:11:22:33:44:55
"""
import argparse
import base64
import hashlib
import os
import re
import struct
import time
import uuid

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1

from ggee_drm import (KS_CONST, DS_CONST, KS_PRIVKEY_ENTRY, xor_cyclic, identities)

PUBKEY_ENTRY = 0x046cc7f6
RO_RESPONSE_TMPL = (
    '<?xml version="1.0" encoding="utf-8"?>\r\n'
    '<ro_response xmlns="http://www.acrodea.com/ns/ro_response/1.0">\n'
    '<status>0</status>\n'
    '<key>%s</key>\n'
    '<payload>%s</payload>\n'
    '</ro_response>\n'
)


def b64_wrapped(raw, width=64):
    b = base64.b64encode(raw).decode()
    return '\n'.join(b[i:i + width] for i in range(0, len(b), width))


def gcm_seal(plain, key16):
    """Inverse of ggee_drm.gcm_open: IV || ciphertext || tag."""
    iv = os.urandom(16)
    c = AES.new(key16 + b'\0' * 16, AES.MODE_GCM, nonce=iv, mac_len=16)
    ct, tag = c.encrypt_and_digest(plain)
    return iv + ct + tag


def build_store(entries):
    """entries = [(type, id, data)] -> the plaintext store container."""
    out = struct.pack('<I', len(entries))
    for typ, eid, data in entries:
        out += struct.pack('<III', typ, eid, len(data)) + data
    return out


def forge(ro_xml, identity, outdir):
    pad = identity.encode()
    dev_id = base64.b64encode(hashlib.sha256(pad).digest()).decode()

    # 1. fresh device keypair - the same shape the runtime generates itself
    key = RSA.generate(1024, e=17)
    priv_der = key.export_key(format='DER', pkcs=8)
    pub_der = key.publickey().export_key(format='DER')
    print('[+] new device key  : %d bits, e=%d, PKCS#8 %d B' %
          (key.size_in_bits(), key.e, len(priv_der)))

    # 2. keystore.dat - private key blob is XOR-obfuscated with the identity
    ks_plain = build_store([(4, KS_PRIVKEY_ENTRY, xor_cyclic(priv_der, pad)),
                            (4, PUBKEY_ENTRY, pub_der)])
    ks = gcm_seal(ks_plain, xor_cyclic(KS_CONST, pad))

    # 3. rewrite <device_id> so the RO names the target device
    ro = re.sub(r'<device_id>.*?</device_id>', '<device_id>%s</device_id>' % dev_id,
                ro_xml, flags=re.S)
    if '<device_id>' not in ro:
        raise SystemExit('input ro.xml has no <device_id> element')
    ro = re.sub(r'<pub_time>.*?</pub_time>',
                '<pub_time>%d</pub_time>' % int(time.time() * 1000), ro, flags=re.S)
    ro = re.sub(r'<uuid>.*?</uuid>', '<uuid>%s</uuid>' % uuid.uuid4(), ro, flags=re.S)
    app_id = re.search(r'<app_id>(\d+)</app_id>', ro).group(1)

    # 4. hybrid envelope: random session key, wrapped to the new public key
    sess = os.urandom(32)
    wrapped = PKCS1_OAEP.new(key.publickey(), hashAlgo=SHA1).encrypt(sess)
    iv = os.urandom(16)
    c = AES.new(sess, AES.MODE_GCM, nonce=iv, mac_len=16)
    ct, tag = c.encrypt_and_digest(ro.encode())
    payload = iv + ct + tag
    resp = RO_RESPONSE_TMPL % (b64_wrapped(wrapped), b64_wrapped(payload))

    # 5. datastore.dat - one entry, keyed by the app id as four ASCII bytes
    eid = int.from_bytes(app_id.encode()[:4].ljust(4, b'\0'), 'little')
    ds_plain = build_store([(4, eid, resp.encode())])
    ds = gcm_seal(ds_plain, xor_cyclic(DS_CONST, pad))

    os.makedirs(outdir, exist_ok=True)
    open(os.path.join(outdir, 'keystore.dat'), 'wb').write(ks)
    open(os.path.join(outdir, 'datastore.dat'), 'wb').write(ds)
    print('[+] identity        : %r' % identity)
    print('[+] device_id       : %s' % dev_id)
    print('[+] app_id          : %s (entry id 0x%08x)' % (app_id, eid))
    print('[+] session key     : %s' % sess.hex())
    print('[+] keystore.dat    : %d bytes' % len(ks))
    print('[+] datastore.dat   : %d bytes' % len(ds))
    print('[+] written to      : %s' % outdir)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ro', required=True, help='decrypted <ro> XML to re-issue')
    ap.add_argument('--mac', help='target device wifi MAC')
    ap.add_argument('--imei', help='target device IMEI')
    ap.add_argument('--out', required=True, help='directory to write the .dat pair into')
    a = ap.parse_args()
    if not (a.mac or a.imei):
        raise SystemExit('need --mac or --imei')
    ident = identities(a.mac, a.imei)[0]
    forge(open(a.ro, encoding='utf-8').read(), ident, a.out)


if __name__ == '__main__':
    main()
