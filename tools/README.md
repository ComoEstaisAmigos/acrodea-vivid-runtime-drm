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

`key_sweep.py` needs `pycryptodome`; the rest are standard library only.

The `embedded` sweep is deliberately exhaustive (every byte-aligned window), so a
full-size binary takes several minutes. `metadata` runs in seconds.

```
pip install pycryptodome
```

## Typical session

```
python unwrap_lzma.py bootstrap.exe bootstrap.elf
python elf_arm_info.py bootstrap.elf
python parse_package.py main.<versionCode>.<package>.obb
python key_sweep.py main.<versionCode>.<package>.obb metadata
python key_sweep.py main.<versionCode>.<package>.obb embedded bootstrap.elf libacrodea_runtime.so
```
