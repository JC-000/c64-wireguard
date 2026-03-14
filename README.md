# c64-wireguard

WireGuard Noise protocol implementation for the Commodore 64, written in 6502 assembly.

## Status

**Phase 3 complete**: full WireGuard IKpsk2 Noise handshake initiator with all cryptographic primitives.

| Phase | Components | Tests |
|-------|-----------|-------|
| 1 | BLAKE2s-256, HMAC-BLAKE2s, WireGuard KDF | 64 |
| 2 | ChaCha20, Poly1305 MAC, ChaCha20-Poly1305 AEAD | 55 |
| 3 | Field arithmetic mod 2^255-19, X25519, Noise handshake | 87 |
| **Total** | | **206** |

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
| `src/chacha20.asm` | ChaCha20 stream cipher (RFC 7539) |
| `src/poly1305.asm` | Poly1305 MAC (130-bit modular arithmetic, quarter-square multiply) |
| `src/aead.asm` | ChaCha20-Poly1305 AEAD encrypt/decrypt |
| `src/fe25519.asm` | Field arithmetic mod 2^255-19 (add, sub, mul, sqr, inv, cswap) |
| `src/x25519.asm` | X25519 scalar multiplication (Montgomery ladder, RFC 7748) |
| `src/tai64n.asm` | TAI64N timestamp increment |
| `src/handshake.asm` | WireGuard IKpsk2 Noise handshake (Type 1/Type 2 packets) |
| `src/data.asm` | Mutable buffers |
| `src/strings.asm` | Display strings |

## Zero Page Layout

| Address | Name | Purpose |
|---|---|---|
| $02-$03 | zp_tmp1/2 | Temporary bytes |
| $04-$09 | w32_src1/src2/dst | Word32 operand pointers |
| $0A-$13 | b2s_* | BLAKE2s working variables |
| $14-$1D | cc20_*/poly_* | ChaCha20 and Poly1305 |
| $1E-$29 | fe_* | Field element arithmetic |
| $2A-$2D | x25_* | X25519 ladder state |
| $FB-$FE | zp_ptr1/2 | General-purpose pointers |

## Testing

Tests use the [c64-test-harness](https://github.com/JC-000/c64-test-harness) package with VICE emulator.

```bash
pip install c64-test-harness

# Phase 1: BLAKE2s, HMAC, KDF
python3 tools/test_blake2s.py                    # 64 tests

# Phase 2: ChaCha20, Poly1305, AEAD
python3 tools/test_chacha20_poly1305.py          # 55 tests

# Phase 3: Field arithmetic, X25519, handshake
python3 tools/test_fe25519.py                    # 64 tests
python3 tools/test_x25519.py                     # 4 tests (--slow for scalarmult)
python3 tools/test_handshake.py                  # 19 tests

# VICE write chunking validation
python3 tools/test_write_bytes_limit.py
```

All tests use the direct-memory `jsr()` pattern. Use `--seed N` to reproduce specific runs.

### Performance

On real C64 hardware (~1 MHz):
- BLAKE2s compress: ~22 ms
- ChaCha20 block: ~65 ms
- Poly1305 block: ~110 ms
- Field multiply (fe_mul): ~170 ms
- X25519 scalar multiply: ~7-8 minutes (255 ladder steps)
- Full handshake (3 X25519 ops): ~25 minutes

## Architecture

The WireGuard handshake follows the IKpsk2 Noise pattern:

1. **Initiator** generates a 148-byte Type 1 packet containing:
   - Ephemeral public key (X25519)
   - Encrypted static public key (ChaCha20-Poly1305 AEAD)
   - Encrypted timestamp (ChaCha20-Poly1305 AEAD)
   - MAC1 (BLAKE2s-128 keyed hash)

2. **Responder** replies with a 92-byte Type 2 packet. The initiator processes it to derive symmetric transport keys for data encryption.

Key derivation uses HMAC-BLAKE2s based HKDF. All field arithmetic operates mod 2^255-19 in little-endian representation, matching the 6502's native carry propagation direction.
