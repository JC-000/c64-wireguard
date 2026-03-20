# c64-wireguard

WireGuard Noise protocol implementation for the Commodore 64, written in 6502 assembly.

## Status

**Phase 8 complete**: Pre-Shared Key (PSK) support — IKpsk2 protocol compliance, optional PSK in disk config, backward-compatible with zero PSK.

| Phase | Components | Tests |
|-------|-----------|-------|
| 1 | BLAKE2s-256, HMAC-BLAKE2s, WireGuard KDF | 64 |
| 2 | ChaCha20, Poly1305 MAC, ChaCha20-Poly1305 AEAD | 55 |
| 3 | Field arithmetic mod 2^255-19, X25519, Noise handshake | 87 |
| 4 | UDP networking (ip65, RR-Net, DHCP, ZP time-sharing) | 64 |
| 5 | Transport data packets (Type 4 encrypt/decrypt, replay protection) | 54 |
| 6 | Session state machine (entropy, config, handshake, packet dispatch) | 49 |
| 7 | Application layer (IP packets, disk config, cookies, timers) | 116 |
| 8 | Pre-Shared Key support (IKpsk2 compliance, config, disk parsing) | 24 |
| MTU | 16-bit payload transport encrypt/decrypt/round-trip (0–1468 bytes) | 37 |
| **Total** | | **546** |

## Building

Requires:
- [ACME](https://sourceforge.net/projects/acme-crossass/) cross-assembler
- [cc65](https://cc65.github.io/) toolchain (ca65 + ld65) — for building the ip65 binary blob
- [ip65](https://github.com/cc65/ip65) source tree — symlinked at `ip65/`

```bash
make            # build ip65 blob + build/wireguard.prg + build/labels.txt
make run        # build and launch in VICE (x64sc)
make clean
```

## Memory Layout

```
$0801-$0A72  Boot stub, main loop, network wrapper (net.asm)
$2000-$32EF  ip65 binary blob (UDP-only, 4,847 bytes)
$32F0-$65BF  Crypto + transport + session + application + data buffers + strings
$7800-$7BFF  Quarter-square multiply tables (page-aligned)
```

ip65 uses zero page $02-$1B (cc65 standard). These overlap our crypto ZP variables. The `net.asm` wrapper saves and restores $02-$1B around every ip65 call (~60 cycles overhead, negligible vs network latency).

## Source Files

| File | Description |
|---|---|
| `src/main.asm` | Top-level includes, memory layout with ip65 blob |
| `src/constants.asm` | Zero page variables, hardware equates, ip65 jump table |
| `src/boot.asm` | BASIC stub, startup, main loop, network init UI |
| `src/net.asm` | ip65 wrapper: ZP save/restore, init, DHCP, UDP listen/send/recv |
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
| `src/transport.asm` | Transport data packets: Type 4 encrypt/decrypt, replay protection |
| `src/entropy.asm` | Hardware RNG: SID voice 3 noise XOR CIA1 timer |
| `src/config.asm` | Peer configuration: copy config buffers to handshake state |
| `src/session.asm` | Session state machine: initiate, handle packet, reset, display |
| `src/ip_build.asm` | IP/ICMP/UDP packet construction for tunnel payloads |
| `src/disk_config.asm` | KERNAL SEQ file reader for WG.CFG (hex, IP, port parsing) |
| `src/cookie.asm` | Type 3 cookie handling (HChaCha20, XChaCha20-Poly1305) |
| `src/timer.asm` | Session timers: keepalive (10s), rekey (120s), expire (180s) |
| `src/data.asm` | Mutable buffers (crypto state, transport state, session config, network buffers) |
| `src/strings.asm` | Display strings |

### ip65 Build

| File | Description |
|---|---|
| `ip65-build/ip65_stub.s` | Jump table with 10 UDP-focused entry points |
| `ip65-build/ip65.cfg` | ld65 linker config (raw binary at $2000) |

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

Note: $02-$1B overlaps with ip65's cc65 ZP usage. The `net.asm` wrapper handles time-sharing via save/restore.

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

# Phase 4: Networking infrastructure
python3 tools/test_networking.py                 # 64 tests

# Phase 5: Transport data packets
python3 tools/test_transport.py                  # 54 tests

# Phase 6: Session state machine
python3 tools/test_session.py                    # 49 tests

# Phase 7: Application layer
python3 tools/test_phase7.py                     # 85 tests
python3 tools/test_disk_config.py                # 31 tests

# Phase 8: Pre-Shared Key support
python3 tools/test_phase8_psk.py                 # 24 tests

# MTU: Large payload transport (16-bit lengths)
python3 tools/test_mtu.py                        # 37 tests

# All suites in parallel (builds once, staggered launch)
python3 tools/run_regression.py

# VICE write chunking validation
python3 tools/test_write_bytes_limit.py
```

All tests use the direct-memory `jsr()` pattern. Use `--seed N` to reproduce specific runs. The MTU suite uses a flag-based `jsr_flag()` that polls a completion flag instead of relying on VICE breakpoints, which become unreliable during long warp-mode computations (>~1000 byte payloads).

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

### Transport

After the handshake, data is exchanged using Type 4 transport packets:

```
[0-3]   type = 4 (LE u32)
[4-7]   receiver_index (from handshake)
[8-15]  counter (64-bit LE, per-packet nonce)
[16+]   encrypted payload + 16-byte Poly1305 tag
```

Each packet is encrypted with ChaCha20-Poly1305 AEAD using the transport key derived from the handshake. The 12-byte AEAD nonce is 4 zero bytes followed by the 8-byte counter. Replay protection rejects packets with counters below the highest successfully decrypted counter.

### Networking

UDP packets are sent and received via [ip65](https://github.com/cc65/ip65), driving the RR-Net CS8900a ethernet adapter. The ip65 library is built as a standalone binary blob (ca65/ld65) and included at $2000 via ACME's `!binary` directive. A 10-entry jump table provides: init, process, DHCP, DNS, UDP add/remove listener, UDP send, and helper wrappers.

The UDP receive callback fires during `ip65_process` while ip65 owns the zero page. It copies incoming packet data to `udp_recv_buf` and sets a flag for the main loop — no crypto ZP is touched.

### Session State Machine

The session module connects all components into a working WireGuard client:

```
STATE_IDLE (0) → session_initiate → STATE_HS_SENT (1)
STATE_HS_SENT (1) → Type 2 received → STATE_ACTIVE (2)
STATE_ACTIVE (2) → session_reset → STATE_IDLE (0)
```

- **session_initiate**: Loads peer config, generates ephemeral key (SID+CIA hardware entropy), creates Type 1 handshake packet, sends via UDP
- **session_handle_packet**: Dispatches by type — Type 2 (handshake response) derives transport keys, Type 3 (cookie) decrypts and stores cookie for next handshake, Type 4 (data) decrypts and routes by IP protocol
- **Payload routing**: Decrypted Type 4 payloads are routed by IP protocol — ICMP echo replies are validated, UDP packets matching the message port are displayed as text, other payloads are shown as hex

State guards ensure Type 2 packets are only accepted during STATE_HS_SENT and Type 4 packets only during STATE_ACTIVE.

### Application Layer

The tunnel carries standard IPv4 packets. The C64 constructs outgoing IP packets from templates:

- **ICMP ping**: 20-byte IPv4 header + 8-byte ICMP echo request, with RFC 1071 checksum
- **UDP messaging**: 20-byte IPv4 header + 8-byte UDP header + text payload

User commands: `L` loads config from disk, `H` initiates handshake, `P` sends ping, `M` opens message prompt, `S` sends test payload, `Q` quits.

### Configuration

Peer configuration is loaded from a `WG.CFG` sequential file on disk (device 8). The file contains 7 or 8 CR-terminated lines:

1. Static private key (64 hex chars)
2. Static public key (64 hex chars)
3. Peer public key (64 hex chars)
4. Endpoint IP (dotted decimal)
5. Endpoint port (decimal)
6. Tunnel IP (dotted decimal)
7. Ping target IP (dotted decimal)
8. Pre-shared key (64 hex chars) — *optional, defaults to zeros if omitted*

### Cookies and Timers

**Type 3 cookies**: When the server is under load, it replies with a cookie instead of completing the handshake. The cookie is decrypted using XChaCha20-Poly1305 (HChaCha20 subkey derivation) and included as MAC2 in the next handshake initiation.

**Session timers** use the C64's jiffy clock ($A0-$A2, 60 Hz):
- **Keepalive**: Empty Type 4 packet after 10 seconds of silence
- **Rekey**: Re-initiate handshake after 120 seconds
- **Expire**: Reset session after 180 seconds
