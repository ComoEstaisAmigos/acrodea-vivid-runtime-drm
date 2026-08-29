# Acrodea VIVID Runtime - DRM analysis & format documentation

Reverse-engineering notes on **Acrodea VIVID Runtime**, the portable-binary game platform behind
the Japanese **G-Gee (Gゲー)** store (GMO Internet / Acrodea, ~2010-2017). It documents the
package formats and the rights-object key model, and it contains one negative and one positive
result:

* **Negative:** the content key (CEK) is a server-generated random AES-256 value that never
  existed in client code, so it cannot be recovered from the package alone.
* **Positive ([§5](#5-the-local-key-stores-open-offline)):** the *rights object that carries the
  CEK* is stored on the device, and its protection is recoverable offline. Given a preserved
  install's `runtime/{keystore,datastore}.dat`, about 2 kB, that title's CEK falls out with no
  server contact, and its content decrypts with a verified authentication tag.

Worked example throughout: `com.ggee.vividruntime.gg_1642` (*Dead Shot Zombies 2*, v13.09.00).
The runtime, the container format and the DRM are shared across titles, so most of this applies
to the rest of the G-Gee catalogue.

**No copyrighted binaries or game assets are distributed here.** This is analysis, plus tooling
that only operates on files you already have. The G-Gee servers have been offline since ~2017;
this is preservation research on an abandoned platform.

---

## TL;DR

| Layer | Status |
|---|---|
| `35 21 14 14` LZMA wrapper (libraries, bootstrap, rpk members) | **Fully documented, no DRM** |
| Package/zip container + signature manifest | **Fully documented** |
| Rights-object key model (`/ro/cek`, RSA wrapping, device binding) | **Fully documented** |
| `fsPacked` inner scramble (keyless `rand()` LCG) | **Fully reversed, constants below** |
| **On-device key stores** (`keystore.dat`, `datastore.dat`) | **Broken offline** ([§5](#5-the-local-key-stores-open-offline)) |
| **Outer AES over the content region** | Key not in the package; **recoverable from a device dump** |

Nothing here breaks AES. What it breaks is the *envelope*: the CEK is delivered inside a rights
object cached on the device, and that object's protection turns out to be a hardcoded 16-byte
constant XORed with the device's own identity string. So:

* From a **package alone** → still nothing. ~2.84 million key candidates tested against a
  known-plaintext oracle, all negative ([§7](#7-key-recovery-attempts-all-negative)).
* From a **preserved install** (`runtime/{keystore,datastore}.dat`, ~2 kB) → the device RSA key,
  the rights object and the CEK all come out offline, each step verified by a GCM tag.

So the artifact worth hunting for is no longer a several-hundred-megabyte decrypted `res.pak`.
It is two small files that ordinary app-data backups preserve.

---

## 1. Platform overview

VIVID Runtime is a **portable-binary execution environment**: games ship as architecture-neutral
`.exe` / `.so` objects that the runtime relocates and executes itself, rather than as native
Android code. Acrodea's own description is in the TDC2013 Tizen conference deck,
[*VIVID Runtime and Secured Content Delivery System on Tizen*](https://cdn.download.tizen.org/misc/media/conference2013/slides/TDC2013-Acrodeas_Vivid_Runtime_solution_on_Tizen.pdf)
(slides 16-17 cover the DRM).

On Android the stack is:

```
APK  ├─ classes.dex                 Java launcher, store/billing, Play expansion downloader
     ├─ lib/armeabi/libacrodea_runtime.so   JNI bridge + object loader + fs_packed
     └─ assets/lib4_5_0/            bootstrap.exe + libc/libm/libstdc++/... (LZMA-wrapped)

expansion package (.obb)  ├─ config.xml, <Title>.exe, res.pak, lib*.so   ← encrypted region
                          ├─ rpk/lib4_6_3.rpk                            ← plaintext
                          └─ signature.xml                               ← plaintext
```

`bootstrap.exe` is the portable loader, `res.pak` is the game content archive, and
`lib4_6_3.rpk` is the (unprotected) runtime library bundle.

### JNI surface

The Java layer drives the native runtime through `com.acrodea.vividruntime.launcher.Runtime`:

| Native method | Role |
|---|---|
| `install(...)` | Decrypt + install a package into app storage |
| `rorequest(...)` / `roinstall(...)` | Fetch / store a rights object |
| `verify(...)` | **Integrity only.** Checks SHA-256 against the signed manifest, offline |
| `getPackData` / `getPackDataSize` | Read an entry out of `res.pak` |

`verify` takes no device identity and contacts nothing, since the certificate is inside the
package. Only `install` needs the rights object.

---

## 2. The `35 21 14 14` LZMA wrapper

Every VIVID library, `bootstrap.exe`, and each `.rpk` member uses one wrapper:

```
magic  35 21 14 14      (4 bytes)
size   uint32 LE        (uncompressed size)
body   raw LZMA1 (alone) stream
```

```python
import lzma

def unwrap(data: bytes) -> bytes:
    assert data[:4] == b'\x35\x21\x14\x14'
    p = data[8:]
    # size field must be replaced with 0xFF*8 ("unknown"): the stream carries an
    # end-of-stream marker, and liblzma rejects a known size together with a marker.
    return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(
        p[:5] + b'\xff' * 8 + p[5:]
    )
```

Unwrapping `assets/lib4_5_0/bootstrap.exe` yields a **32-bit ARM ELF** (~1.58 MB). Load *that*
in Ghidra/IDA; the raw `.exe` is just the wrapper and disassembles to garbage. Suggested
language: `ARM:LE:32:v7`.

`.rpk` files are plain ZIPs whose members are individually wrapped, with hashed member names
plus a `config.xml`, `icon.png`, and `signature.xml`.

---

## 3. Package container and signature manifest

The expansion package is a ZIP with a **32-byte header prepended**, so every offset in the ZIP
structures is shifted by `0x20` relative to the file. Parse the central directory at its real
location and add `0x20` to each local-header offset.

For the worked example (37,393,698 bytes total):

* Encrypted region: `[0x00000000, 0x0231ea11)`, the 32-byte header plus the first 12 entries
  (`config.xml`, `DSZv2.exe`, `icon.png`, all `lib*.so`, `res.pak`), **local headers included**.
  A full `PK\x03\x04` scan finds no local headers below `0x231ea11`.
* Plaintext tail: `rpk/lib4_6_3.rpk` and `signature.xml`.
* Plaintext length is `0x231e9f1`, **not** a multiple of 16, and ciphertext is exactly 32 bytes
  longer, so there is no block padding. Consistent with CTR-family or CBC-CTS plus a 32-byte
  IV/nonce header.

### `signature.xml`

Standard XMLDSig, `rsa-sha256`, one `<Reference>` per entry, signed by a per-title certificate
(`CN=<title id>`) chained to an **"Acrodea Root CA"** (Acrodea Inc., Europe Branch, Helsinki).

The digests are computed over the **as-shipped form of each entry**, i.e. over the *encrypted*
bytes for entries that ship encrypted.

> [!WARNING]
> **Correction.** An earlier revision of this document claimed the digests covered the
> **plaintext**, and offered them as a decryption oracle. That is wrong. Measured on the publicly
> archived **Shantae: Risky's Revenge** (`gs_1277`) install: its `signature.xml` lists the SHA-256
> of the **encrypted** executable, and the digest of the decrypted ELF appears in none of that
> manifest's 1,329 `<Reference>` entries. Treat these digests as packaging checksums, not as a way
> to validate a candidate decryption.
>
> The real oracle is the cipher itself: content is `IV(16) ‖ ciphertext ‖ GCM tag(16)`, so a
> correct CEK authenticates itself ([§5](#5-the-local-key-stores-open-offline)).

Content still being **universal** (not per-device) does not depend on that retracted claim. It
follows from the package being a static Google Play expansion file served byte-identically to
every user. See [§5](#5-the-local-key-stores-open-offline).

---

## 4. The DRM key model

Extracted from the unwrapped `bootstrap.exe`, which statically links **Crypto++**: Rijndael with
**GCM / CTR / CBC-CTS**, plus RSA-OAEP and a DL/ECIES-style hybrid (`P1363_KDF2<SHA1>`,
`DL_EncryptionAlgorithm_Xor<HMAC<SHA1>>`). The runtime `.so` carries only libtomcrypt
`rsa_verify_hash_ex` + `sha256_desc` and **no symmetric cipher**, so content decryption happens
in `bootstrap.exe`.

Its string table exposes the whole schema:

```
/ro/cek                      content encryption key   ← the AES key for the content region
/ro/pek                      package encryption key
/ro/device_id                binds the RO to one device
/ro/uuid, /ro/cont_uuid, /ro/app_id, /ro/build, /ro/pub_time
/ro/constraint/{count,duration,interval,total,option}   trial / rental limits
/ro_request/{device_id,public_key}     device → server
/ro_response/{key,payload}             server → device
/data/keystore.dat           device's OWN generated RSA private key
/data/datastore.dat          cached rights object
drm_ro_request.xsd,  "DRM Failure: ",  Security::Errors::DRMError
```

Driver: `Security::ExeDRMHandler::postLoadHook` plus a statically-linked `LDValidator` engine and
`Security::ROConstraintChecker` (`s_isValid`, `s_getRemainCount`, `s_getRemainTime`, …).

### Provisioning flow

1. Device generates **its own RSA keypair**, 1024-bit, public exponent **17** (not 65537),
   stored in `/data/keystore.dat`.
2. Device sends `device_id` + its **public key** (`/ro_request`). `device_id` is
   **`base64(SHA-256(identity))`**, where `identity` is the string described in
   [§5](#5-the-local-key-stores-open-offline).
3. Server returns a rights object whose payload is **hybrid-encrypted to that public key**
   (`/ro_response/key` + `/ro_response/payload`), carrying the **CEK**.
4. `bootstrap.exe` unwraps with the device private key → CEK → decrypts the content region.
   The RO is cached in `datastore.dat`, so launches work offline afterwards.

> [!WARNING]
> **Correction.** An earlier revision described `device_id` as an HMAC-SHA256 of IMEI/IMSI/MAC
> keyed with an app constant. Measured against a real rights object, it is a **plain SHA-256** of
> the identity string, base64-encoded, no HMAC and no secret key involved.

**The client reads the CEK from `/ro/cek`. It never derives it.** There is no KDF from device
identity to content key anywhere in the binaries. Device identity protects the *envelope*, which
is a different thing and is what [§5](#5-the-local-key-stores-open-offline) attacks.

---

## 5. The local key stores open offline

The TDC2013 slides say the key is "generated on the basis of User ID (IMSI, IMEI, etc.)", which
reads as if content were encrypted per-device. It isn't, but device identity is not decorative
either. It is the XOR pad protecting the local key stores, and that is the way in.

Two separate keys, as before:

* **CEK** - encrypts the content. Random, server-generated, **global** for the title.
* **Device binding** - wraps the CEK for one device. This is what identity selects.

Content cannot be per-device: on Android these titles ship as a **Google Play expansion file**
(the APK bundles `com.google.android.vending.expansion.downloader`, standard
`main.<versionCode>.<package>.obb` naming), served **byte-identical to every user**. One static
blob cannot be encrypted under billions of different IMEIs. So a decrypted package from any one
device is valid for everyone: *the encryption was the binding*.

### The identity string

`bootstrap.exe` obtains it through OpenKODE, always with the same attribute:

```
kdQueryAttribcv(0x24d)
  → __kdExtensionAttribcv → __kdExtensionDeviceAttribcv        (libacrodea_runtime.so)
      switch: 0x24d → IMEI, 0x24e → IMSI, 0x29 → platform info
  → __acbDeviceGetIMEI → ExtensionACR::DeviceGetIMEI → JNI
  → MyDevice.getImei()                                          (classes.dex)
```

and `MyDevice.getImei()` returns a **prefix plus an identifier**:

```
"IMEI:" + TelephonyManager.getDeviceId()          when telephony reports one
"MACW:" + wifiMac.replaceAll(":", "")             otherwise (tablets, Wi-Fi-only devices)
```

On the Wi-Fi path the app caches that MAC in its own `SharedPreferences` under `PREF_MAC_ADDR`
(AES/ECB/PKCS5 with an app-embedded key), so **a dump that includes `shared_prefs/` carries its
own identity**, nothing needs to be known about the device from outside.

### Store encryption

Both stores use the same construction:

```
key16  = CONST16 XOR identity          # cyclic over identity, first 16 bytes only
key    = key16 ‖ 16 zero bytes         # AES-256
file   = IV(16) ‖ AES-256-GCM(plaintext) ‖ tag(16)
```

with two constants lifted from `bootstrap.exe`:

```
keystore.dat   fd 17 49 54 5e d2 5a b4 66 98 c6 c9 f4 3c e8 91
datastore.dat  9a 18 cf b1 ba a6 ea 63 66 30 92 03 5b a1 78 41
```

These are **identical across runtime builds and titles** (verified byte-for-byte in two
independently sourced `bootstrap.exe` binaries, years apart), so only the identity varies.
`tools/extract_store_keys.py` re-derives them from any build.

**Decoy.** The constants are built on top of an ASCII string, `oYga9NQJHQqbnZhe`, that sits in
`.rodata` immediately before `/data/keystore.dat` and is referenced from all the store handling.
It is never used: all 16 of its bytes are overwritten before use, twice, once with a dead decoy
word set and once with the real one. Any effort spent deriving keys from that string is wasted.

```cpp
std::string k("oYga9NQJHQqbnZhe", 16);      // only sizes the buffer
*(u32*)&k[0] = A0; … *(u32*)&k[12] = A3;    // decoy, immediately overwritten
*(u32*)&k[8] = B2; *(u32*)&k[4]  = B1;      // the real constant
*(u32*)&k[12]= B3; *(u32*)&k[0]  = B0;
for (i = 0, p = id.begin(); i < k.size(); ++i, ++p) {
    if (p == id.end()) p = id.begin();
    k[i] ^= *p;                              // id = kdQueryAttribcv(0x24d)
}
```

### Store container format

```
u32 count
count × { u32 type; u32 id; u32 length; u8 data[length] }
```

`keystore.dat` holds two entries: the device **RSA private key** under id `0x5d66a128`, and its
matching public key as a plain X.509 `SubjectPublicKeyInfo` under id `0x046cc7f6`. The private
key entry is additionally **XOR-obfuscated with the same identity string**; undo that and it is a
textbook PKCS#8 `PrivateKeyInfo`. `datastore.dat` holds one entry, keyed by the four ASCII bytes
of the app id, containing the verbatim `ro_response` XML the server sent.

### The full chain

Every step is checked by a GCM authentication tag, so nothing here is guesswork:

| # | Input | Operation | Output |
|---|---|---|---|
| 1 | wifi MAC or IMEI | `"MACW:"+mac` / `"IMEI:"+imei` | identity |
| 2 | `keystore.dat` | AES-256-GCM, key = `KS_CONST xor identity` | key store |
| 3 | entry `0x5d66a128` | XOR identity | PKCS#8 RSA-1024 private key |
| 4 | `datastore.dat` | AES-256-GCM, key = `DS_CONST xor identity` | `<ro_response>` |
| 5 | `<key>` | RSA-**OAEP(SHA-1)** with the device key | 32-byte session key |
| 6 | `<payload>` | AES-256-GCM with the session key | `<ro>` → `<cek>`, `<pek>` |
| 7 | content file | AES-256-GCM with the CEK | plaintext |

`tools/ggee_drm.py` runs the whole thing. Verified end to end on the publicly archived
**Shantae: Risky's Revenge** (`com.ggee.vividruntime.gs_1277`, v12.04.03) install: the CEK came out, and
`iShantae.exe` decrypted - GCM tag verified - to a valid ARM ELF (`e_machine=40`,
`e_flags=0x5000002`, ARMv5TE soft-float). The same CEK applied to Ghost Trick's `.exe` fails the
tag, as it must: **the CEK is per title**. (No key material from that dump is reproduced here,
only that the method works on it.)

### The rights object can be re-issued for another device

The RO carries **no server signature**. Its only integrity check is the GCM tag over `<payload>`,
computed with a session key the *issuer* chooses and wraps to the device's own public key, and
that public key lives in the device's own keystore. So once a title's CEK is known, a valid
`keystore.dat` + `datastore.dat` pair can be minted for **any** identity: generate a fresh RSA
keypair, draw a session key, recompute `device_id`, re-seal. `tools/ggee_forge.py` does this.

Round-trip check: forging for an invented MAC, then re-reading with `ggee_drm.py`, recovers the
same CEK, and decrypting the title's executable with it produces a **byte-identical** result to
decrypting via the genuine device's rights object.

This proves the *format* is fully understood. Whether a live `bootstrap.exe` accepts a forged RO
has not been tested, and it is moot for preservation: the practical path decrypts on a PC and
ships plaintext content, which never involves an on-device rights object at all.

### Limits

* **Identity must be recoverable.** The brute-force fallback below only helps when the identity
  derives from something readable off the device. Observed counter-example: on a rooted
  BlueStacks 0.7.3.766 (Android 2.3.4) image, a freshly installed title generated a valid
  `keystore.dat` on demand, but wrote no `PREF_MAC_ADDR`, exposed no telephony service, and the
  file opened under **none** of the readable identifiers (emulated Wi-Fi MAC, eth0 MAC, serial,
  android_id, prefix-only, empty) in any case or format. Real-device dumps behave correctly; that
  emulator's `getImei()` returns something not externally observable.
* **Brute force, when applicable.** `keystore.dat`'s GCM tag authenticates the whole derived key,
  so identity guesses are individually verifiable, and a correct one additionally yields the
  tell-tale store header (`count=2, type=4, id=0x5d66a128`). Measured ≈24,000 guesses/s
  single-threaded, unoptimised. With a `"MACW:"` identity whose first three bytes are a known
  vendor OUI, the remaining `16^6 ≈ 16.7 M` space is a ~12-minute sweep. A locally administered or
  randomised MAC breaks that assumption.
* **Only 16 of the identity's bytes protect the container**, because the key is 16 bytes and the
  pad is applied cyclically from the start. A 17-character identity therefore has its last
  character unused for the container key, two identities differing only in that character open
  the same `keystore.dat`. The private-key entry XOR *does* cover the full string, so a wrong last
  character still yields an unparsable PKCS#8 blob; validate the RSA key, not just the GCM tag.

---

## 6. `res.pak` has two layers

### Outer: AES over the whole content region

Key = `/ro/cek`. The cipher itself is not attackable, and the key is not in the package, but it
is in the *rights object*, which is recoverable from a preserved install
([§5](#5-the-local-key-stores-open-offline)). So this layer falls to a device dump, never to the
package alone.

### Inner: a keyless `rand()` LCG scramble

Each entry inside `res.pak` is XOR-scrambled by `fs_packed::fsPacked_randomize` in
`libacrodea_runtime.so`, using the **classic ANSI-C `rand()` constants**, with no key at all:

```c
/* MULT = 0x41c64e6d, INC = 0x3039  (glibc/ANSI C rand()) */
seed = (pos & 0x7fffffff) * MULT + INC;
for (i = 0; i + 1 < len; i += 2) {
    seed = seed * MULT + INC;
    *(uint16_t *)(buf + i) ^= (uint16_t)(seed >> 8);
}
if (i < len)
    buf[i] ^= (uint8_t)(((seed * MULT + INC) >> 8) & 0xff);
```

Read path:

```
JNI Runtime.getPackData
  → RuntimeContext::getPackData
    → __fsPackedLoadEntries / __fsPackedGetFileSize / __fsPackedReadFile
      → fs_packed::fsPacked::readFile
        → fs_packed::fsPacked_randomize      (unscramble)
```

It is weak, but it sits **behind** the AES layer, so it protects nothing in practice. It was
explicitly ruled out as the outer layer: 4M+ LCG seeds × 7 candidate header offsets were brute
forced against the known plaintext with zero hits.

This still matters for one reason. Once an AES-decrypted package surfaces, its entries are fully
recoverable with the constants above, with no server, key or rights object involved.

### What an installed (decrypted) `res.pak` looks like

Verified against a real installed package from a preserved device dump:

* Magic `4F 49` (`"OI"`) followed by a structured entry table.
* Entropy **2.05-6.92** bits/byte across the file (structure + compressed assets), *not* the flat
  ~8.0 of an encrypted blob.

That is the signature of the artifact worth hunting for. The `res.pak` inside an installed game
directory, on a device that installed the title while the servers were alive, is the
**already-decrypted** form. See
[Where installed titles live on disk](#where-installed-titles-live-on-disk) for the two possible
locations.

---

## 7. Key-recovery attempts, all negative

### The oracle

A package's first encrypted bytes are the ZIP local file header of the first entry, and every
field in it (signature, version, flags, method, mtime, CRC-32, sizes, name length, name) is
recoverable from the **central directory**, which sits in the plaintext tail. So ~40 bytes of
known plaintext at plaintext offset 0 are free, and any key/mode guess is verifiable instantly.

```python
import struct
# from the central-directory record of the first entry:
lfh = struct.pack('<IHHHHHIIIHH', 0x04034b50, vne, flag, method, mtime, mdate,
                  crc32, csize, usize, len(name), 0) + name
```

### What the ciphertext looks like

| Measurement | Result |
|---|---|
| Shannon entropy over the region | **7.99999** bits/byte |
| Repeated 16-byte blocks (ECB leak) | **0** out of 2,301,601 |
| χ² over 256 bins | 404 |

No structure, no block reuse, no ECB. Consistent with a correct stream/CTR-family cipher.

### Sweeps run

| Candidate set | Tests | Hits |
|---|---|---|
| Metadata-derived keys (title id, package, uuids, filenames, MD5/SHA/double-hash variants, all keys embedded in `classes.dex`) | 516 | 0 |
| Exhaustive byte-aligned 16/32-byte windows in `bootstrap.exe` (`.text/.rodata/.data/.data.rel.ro`) | 1,743,286 | 0 |
| Same sweep over `libacrodea_runtime.so` | 1,093,673 | 0 |
| LCG seeds × header offsets (is the outer layer just the weak scramble?) | 4M+ | 0 |

Modes covered: ECB, CBC, CTR, OFB, CFB, across three IV candidates, **plus an IV-independent CBC
test** (`AES_dec_K(C₁) ⊕ C₀ == P₁`) that would find the right key regardless of IV.

**~2.84 million tests, zero hits**, which is what a properly random server-side key looks like.
All AES keys embedded in `classes.dex` are also demonstrably local-use (SharedPreferences,
in-app-billing payload, ad session, Google LVL obfuscator) and none relate to content.

> [!NOTE]
> **Caveat on the mode.** These sweeps modelled the region as CTR-family with the leading bytes
> used directly as the counter block. The cipher is actually **AES-GCM**
> ([§5](#5-the-local-key-stores-open-offline)), and with a 16-byte IV, GCM derives its starting
> counter through GHASH, which depends on the key, so that keystream model does not describe
> the real construction. The *conclusion* is unaffected (the key is not embedded anywhere in the
> client, and no sweep of client binaries can find it), but any future sweep should test GCM
> rather than raw CTR.
>
> One loose end, recorded rather than resolved: the encrypted region begins with exactly 32 bytes
> before the first entry's local header, which is suggestively equal to GCM's IV + tag overhead,
> yet the region is length-preserving in place, and all six `AuthenticatedDecryptionFilter`
> constructions in `bootstrap.exe` pass `flags = 0x10` (`THROW_EXCEPTION` only, i.e. **MAC at
> end**), `truncatedDigestSize = -1`. Those two facts do not yet reconcile. It does not matter
> until a CEK is in hand, at which point the tag settles it immediately.

---

## 8. Compatibility notes (for anyone booting the runtime)

Measured from `.ARM.attributes`:

| Binary | `Tag_CPU_arch` | `e_flags` |
|---|---|---|
| `libacrodea_runtime.so` | **6** (ARM v6) | `0x5000000` (soft-float) |
| `bootstrap.exe` (unwrapped) | **4** (ARMv5TE) | `0x5000002` |

Shipping APKs contain **`lib/armeabi` only**, with no `armeabi-v7a` and no `arm64-v8a`. That ABI
was removed from the NDK in r17 (2018) and modern devices report `Build.SUPPORTED_ABIS` as
`[arm64-v8a, armeabi-v7a]` or `[armeabi-v7a]`, so `armeabi`-only natives are never loaded today.
Re-homing the same v6/v5TE binaries under `armeabi-v7a` is enough, since ARM is backwards
compatible and the directory name selects the loader path, not the ISA.

**Hard requirement: a device that still has 32-bit (AArch32) execution.** The whole stack
(loader, runtime, game executable) is closed-source 32-bit ARM with no source available, so it
can't be rebuilt for arm64. Any device retaining AArch32 works, which covers most phones through
~2023 whether 64-bit or not. **64-bit-only** devices and images cannot run it, and no
compatibility shim changes that; it would take a full ARM32→ARM64 translation layer.

Two runtime notes worth knowing if you're bringing this up on a modern OS:

* The runtime resolves `ZipFileRO` symbols out of `libutils.so` via `dlopen`/`dlsym`. Modern
  Android removed `ZipFileRO` from `libutils.so` entirely.
* `ZipFileRO::open` is called as a **non-static member** (`open(this, path)`, Android 2.3 style),
  with the object allocated and hand-initialised by the caller. A static factory mangles to the
  same symbol and links silently while shifting every argument by one register.

### `config.xml`: what it is, and how to substitute it

A title's own `config.xml` is the **first entry of the encrypted region**, so it cannot be
recovered without the CEK. On a package where the region is encrypted it sits at offset `0x20`
and reads as ciphertext instead of `PK\x03\x04`; inflating it fails.

Two usable substitutes exist, and they behave differently.

**1. The library config, in plaintext, inside the runtime `.rpk`.** Every `.rpk` carries its
own `config.xml`, and the `.rpk` lives in the package's *unencrypted* tail, so this one is
always readable:

```xml
<?xml version="1.0" encoding="utf-8" ?>
<application xmlns="http://www.acrodea.com/ns/application/1.0"
             id="lib4_6_3" build="4631" version="1.0.0" lib="lib4_6_3">
  <name>lib4.6.3 armv5</name>
  <icons><icon width="90" height="90">icon.png</icon></icons>
</application>
```

It describes the *library bundle*, not the game: `id` is the library name, and there is no
`<executable>` and no `<libraries>`. Useful as a schema reference, and it independently
corroborates the ABI measurement above, Acrodea's own label for the bundle is **`armv5`**.

**2. A reconstructed app config**, same namespace and attribute layout, with the app-specific
fields filled in: the title `id`, `<executable>`, and `<libraries>` (replacing the library
file's `lib=` attribute). For the worked example of this document,
`com.ggee.vividruntime.gg_1642`, that is:

```xml
<?xml version="1.0" encoding="utf-8"?>
<application xmlns="http://www.acrodea.com/ns/application/1.0"
             build="20130903" id="1642" platformversion="130900" version="13.09.00">
  <executable>DSZv2.exe</executable>
  <libraries>lib4_6_3</libraries>
  <orientation>landscape</orientation>
  <profile><in_app_billing>true</in_app_billing></profile>
</application>
```

`id` and `<executable>` are the fields that matter, and both are readable without the CEK:
the entry names sit in the ZIP central directory, which is in the plaintext tail. `build`,
`version` and `platformversion` here are invented and were verified not to affect behaviour.

For comparison, a **genuine** app config, recovered intact from a preserved (decrypted)
package of a different title. Note the icon list, which a reconstruction has no way to know:

```xml
<?xml version="1.0" encoding="utf-8"?>
<application xmlns="http://www.acrodea.com/ns/application/1.0"
             build="20121030" id="1761" platformversion="120700" version="1.0">
  <executable>GhostTrick.exe</executable>
  <libraries>lib4_6_3</libraries>
  <orientation>landscape</orientation>
  <icons>
    <icon height="90" width="90">icon_large.png</icon>
    <icon height="90" width="90">icon_middle.png</icon>
    <icon height="90" width="90">icon_small.png</icon>
  </icons>
  <profile><in_app_billing>true</in_app_billing></profile>
</application>
```

### Loader error codes, and what actually drives them

Measured on an Android 12 device against a title whose content region is still encrypted, with
the genuine runtime `.rpk` in place (its SHA-256 verified against the digest signed in
`signature.xml`). **The error you get is decided by `config.xml`, not by the content archive:**

| `config.xml` supplied | Code | Dialog |
|---|---|---|
| none | `0xffffffff` | - |
| the library config from the `.rpk` (no `<executable>`) | `0x0e030300` | "Unexpected error has occurred… load error" |
| a reconstructed app config naming `<Title>.exe` | `0x0e030700` | "Required game data is either deleted or broken" |

* `0xffffffff` - `bootstrap.exe`'s entry point returns -1; with no config it does not know what
  to load at all.
* `0x0e030300` - short read. The config declares no `<executable>`, `fs_packed` falls back to
  loose-directory mode and the loader ends up `fopen`-ing a *directory*, whose `fread` returns 0.
* `0x0e030700` - module file could not be opened. The config names an executable, the loader
  goes looking for that module, and it is not there. This is the furthest a deployment gets
  without decrypted content.

**The content archive is not what the loader trips on first.** Walking `res.pak` through
absent, zero-length, and a real `OI` header with zero padding produced *no change* in the error
code in any combination, with or without the runtime `.rpk` present. Nor did `build`,
`version` or `platformversion` values matter. The blocker is the missing executable module,
which is inside the encrypted region; the content archive only becomes relevant once a module
exists to load.

Corollary for anyone testing: **a synthetic content archive teaches nothing.** The next gate is
a real `<Title>.exe`, so the experiment ladder stops there.

---

## 9. DRM-as-gate vs DRM-as-encryption

The platform's **online gates** (license/entitlement checks, ticket and login flows,
connectivity tests) are ordinary policy checks: a boolean, a branch, a server round-trip. Each
one dies to a one-line patch, and historically they did.

The **content encryption** is a different category. It isn't asking a question you can answer
wrongly, it's withholding information you don't have. You can branch past a license test; you
cannot branch past a cipher, and no amount of patching or compute substitutes for the random
AES key. Attacking that key *cryptographically* remains hopeless.

But "withholding information" cuts both ways: the information was **cached on the device**. The
key rides inside a rights object stored in `datastore.dat`, and that object's protection is a
program constant plus the device's own identity, not a server secret
([§5](#5-the-local-key-stores-open-offline)). So the honest statement is narrower than "closed":
the cipher is unbreakable, but the key survives in any preserved install and comes back out
offline. What is permanently gone is only the ability to *provision a new* device, not the
ability to read a device that was provisioned while the servers lived.

*(This repository documents the concept rather than publishing a step-by-step bypass recipe for
the store/licensing checks.)*

---

## 10. Can this ever be recovered?

**By breaking the crypto: no.**

* AI doesn't help. A random key has no pattern to learn; this is an absence of information, not
  a hard puzzle.
* Classical brute force is 2¹²⁸.
* Quantum (Grover) halves the exponent to ~2⁶⁴ for AES-128, still infeasible, irrelevant for
  AES-256, and nobody is aiming a quantum computer at a defunct mobile game.

**By the artifact resurfacing: yes**, and the artifact is now much smaller than it used to be.
This is data archaeology, not cryptanalysis. Either of these works:

1. the installed game directory from a device (or backup) that installed the title while the
   servers were alive (~2013-2017), containing the **already-decrypted** `res.pak`,
   `<Title>.exe`, and `config.xml`; or
2. **that device's `runtime/keystore.dat` + `runtime/datastore.dat`** (plus `shared_prefs/`, or
   the device's Wi-Fi MAC / IMEI), from which the CEK is recovered offline by
   `tools/ggee_drm.py`, see [§5](#5-the-local-key-stores-open-offline).

Option 2 is the realistic one. Those files live under
`/data/data/<package>/` and total **about 2 kB**, which is exactly what
Titanium Backup, `adb backup` and rooted `/data/data` copies preserve, and exactly the kind of
thing that survives in old phone backups when a several-hundred-megabyte game directory does not.
Reading them off a device needs root; restoring an old backup image does not.

Because the CEK is global, **a decrypted package from any one device is valid for everyone**: the
encryption *was* the device binding, and once removed the plaintext is universal.

Verify a candidate decryption by its **GCM tag**, not by `signature.xml`, those digests cover the
as-shipped (encrypted) form, see the correction in [§3](#signaturexml).

### Where installed titles live on disk

Two different roots exist, and which one a title uses depends on how it was installed. Both
constants appear in the same codebase, because the same runtime library serves both modes:

| Install route | Content root |
|---|---|
| G-Gee launcher / store app (`com.acrodea.gamecenter`) | `/sdcard/RuntimeApps/<id>/` |
| Standalone per-title APK (Google Play) | `/sdcard/Android/data/<package>/files/<id>/` |

Under either root the layout is the same: `config.xml`, `<Title>.exe`, `res.pak`, `res/`,
`rpk/<runtime lib>.rpk`, `signature.xml`, plus `data/` and `secure/` for save data. **Check both
locations** when searching a device or backup.

### Preservation status

Community dumps of installed G-Gee game directories exist on the Internet Archive, covering at
least Devil May Cry 4 Refrain (1760), Ghost Trick (1761), Disgaea (705) and
Shantae: Risky's Revenge (1277).
These appear as `RuntimeApps/<id>/` trees with `res.pak` present as a normal file.

Scope of what has actually been checked here: **one** `res.pak` from such a dump was inspected
and is definitively **not encrypted** (magic `4F 49`, entropy 2.05-6.92 bits/byte across the
file, versus the flat ~7.9999 of the encrypted region). One of these uploads is additionally
labelled "tested and working" by its uploader. The remaining titles have *not* been individually
verified as complete or playable, so treat the list as "dumps exist and at least one is
genuinely decrypted", not as a guarantee for each title. Sizes in the hundreds of MB are
expected, since that is the full decrypted asset archive.

No decrypted copy is known for many other titles, including the one used as the worked example
in this document.

If you have an old Android device or backup with G-Gee games installed, that game directory is
the thing worth saving, and so, now, is the **app-data directory**, even on its own:

```
/data/data/com.ggee.vividruntime.<id>/runtime/keystore.dat     ~850 B
/data/data/com.ggee.vividruntime.<id>/runtime/datastore.dat    ~1.1 kB
/data/data/com.ggee.vividruntime.<id>/shared_prefs/*.xml       ~700 B
```

Those three files are enough to recover that title's CEK, and the package itself is still
downloadable from public APK mirrors. Once the servers died, the rights object became
unreproducible, but it was *cached*, and that cache is what survives in backups.

---

## Repository scope

* Analysis and format documentation (this file).
* Tooling that operates on files you supply: LZMA unwrapper, container/central-directory parser,
  known-plaintext oracle, embedded-key sweeper, `fsPacked` LCG descrambler, offline rights-object
  recovery, rights-object re-issuing, and a store-constant extractor.
* **Not included:** any APK, expansion package, `res.pak`, game asset, or other copyrighted
  binary; no signing keys; and **no rights objects, device keys, content keys or device
  identifiers** from any real install. The constants published here are program constants read
  out of the runtime's own binaries, not anyone's key material.

This is preservation research on a platform whose servers have been offline since ~2017. The
tooling only operates on files a user already possesses, and recovering a rights object requires
that device's own DRM material, it grants no access to anything a device owner could not already
read from their own install.

## Credits

Parts of the analysis, tooling and documentation in this repository were produced
with the help of [Claude](https://claude.com/claude-code) (Anthropic): the
known-plaintext oracle and key sweeps, the ARM disassembly of the store-key derivation
in `bootstrap.exe`, the tracing of the DRM path and the `fs_packed` scramble, the offline
rights-object recovery / re-issue tooling, and this write-up.

## License

Code: MIT. Documentation: CC BY 4.0. Trademarks and game content belong to their respective
owners; this project is unaffiliated with Acrodea, GMO Internet, or any publisher.
