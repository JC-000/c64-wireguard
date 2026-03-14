# c64-wireguard

WireGuard Noise protocol implementation for the Commodore 64, written in 6502 assembly.

## Status

**Phase 1 complete**: core cryptographic primitives — BLAKE2s-256, HMAC-BLAKE2s, and WireGuard KDF (HKDF).

## Building

Requires the [ACME](https://sourceforge.net/projects/acme-crossass/) cross-assembler.

```bash
make            # build/wireguard.prg + build/labels.txt
make run        # build and launch in VICE (x64sc)
make clean
```

## Source Files

| File | Description |
|---|---|
| `src/main.asm` | Top-level includes |
| `src/constants.asm` | Zero page variables, hardware equates, constants |
| `src/boot.asm` | BASIC stub, startup, screen utilities |
| `src/word32.asm` | 32-bit arithmetic: add, xor, rotate (7/8/12/16), copy, zero |
| `src/blake2s.asm` | BLAKE2s-256: init, update, final, compress, G function, keyed hashing |
| `src/blake2s_kdf.asm` | HMAC-BLAKE2s and WireGuard KDF (kdf_1, kdf_2, kdf_3) |
| `src/data.asm` | Mutable buffers for BLAKE2s state, HMAC, KDF |
| `src/strings.asm` | Display strings |

## Zero Page Layout

| Address | Name | Purpose |
|---|---|---|
| $02-$03 | zp_tmp1/2 | Temporary bytes |
| $04-$09 | w32_src1/src2/dst | Word32 operand pointers |
| $0A-$13 | b2s_* | BLAKE2s working variables |
| $FB-$FE | zp_ptr1/2 | General-purpose pointers |

## Testing

Tests use the [c64-test-harness](https://github.com/JC-000/c64-test-harness) package with VICE emulator.

```bash
pip install c64-test-harness
python3 tools/test_blake2s.py              # 64 tests: word32, BLAKE2s, HMAC, KDF
python3 tools/test_write_bytes_limit.py    # VICE memory write chunking validation
```

### Test Coverage (64 tests)

- **word32** (28): add32, xor32, rotr32 variants, copy32, zero32
- **BLAKE2s** (19): unkeyed (2), keyed (4), random inputs (5), boundary cases (8)
- **HMAC-BLAKE2s** (8): RFC vectors and random inputs
- **WireGuard KDF** (9): kdf_1, kdf_2, kdf_3 with known vectors

All tests use the direct-memory `jsr()` pattern for fast execution.
