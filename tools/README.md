# tools

Small, dependency-light scripts for the formats described in the top-level README.
They operate only on files you supply; nothing here ships game data.

| Script | Purpose |
|---|---|
| `unwrap_lzma.py` | Unwrap the `35 21 14 14` LZMA container (libraries, `bootstrap.exe`, `.rpk` members). Produces the ARM ELF you should open in Ghidra/IDA. |
| `parse_package.py` | Parse an expansion package: central directory, the `0x20` offset shift, which entries are encrypted, and the exact encrypted region. Also rebuilds the known plaintext. |
| `key_sweep.py` | Known-plaintext oracle plus two sweeps (metadata-derived keys, and every byte-aligned window inside a binary). This is the tooling behind the negative result. |
| `fspacked_descramble.py` | Reverse `fs_packed::fsPacked_randomize`, the keyless LCG scramble inside `res.pak`. |
| `elf_arm_info.py` | Read `.ARM.attributes` to show `Tag_CPU_arch` / `e_flags`. |
| `extract_store_keys.py` | Lift the `keystore.dat` / `datastore.dat` key constants out of a `bootstrap.exe` by locating the store-key derivation sites (the `oYga9NQJHQqbnZhe` decoy build). |
| `ggee_drm.py` | Recover a title's CEK **offline** from a preserved install's `runtime/{keystore,datastore}.dat` (+ `shared_prefs/`, or a supplied MAC/IMEI), and decrypt DRM content with it. Every step is GCM-tag verified. See top-level README §5. |
| `ggee_forge.py` | Re-issue a rights object: given a decrypted `<ro>` and a target device identity, mint a fresh `keystore.dat` + `datastore.dat` pair carrying the same CEK. Demonstrates that the RO carries no server signature. |

`key_sweep.py`, `ggee_drm.py` and `ggee_forge.py` need `pycryptodome`; `extract_store_keys.py`
needs `capstone`; the rest are standard library only. None of these tools contains or downloads
any game data, key or device identifier — you supply the files.

The `embedded` sweep is deliberately exhaustive (every byte-aligned window), so a
full-size binary takes several minutes. `metadata` runs in seconds.

```
pip install pycryptodome capstone
```

## Typical session

Analysing a package (the negative result):

```
python unwrap_lzma.py bootstrap.exe bootstrap.elf
python elf_arm_info.py bootstrap.elf
python parse_package.py main.<versionCode>.<package>.obb
python key_sweep.py main.<versionCode>.<package>.obb metadata
python key_sweep.py main.<versionCode>.<package>.obb embedded bootstrap.elf libacrodea_runtime.so
```

Recovering a CEK from a preserved install (the positive result):

```
python unwrap_lzma.py bootstrap.exe bootstrap.elf
python extract_store_keys.py bootstrap.elf          # confirm the two constants for this build
python ggee_drm.py ro <runtime_dir> --prefs <shared_prefs.xml> --out out
python ggee_drm.py decrypt <cek_b64> <Title>.exe <Title>.elf
```
