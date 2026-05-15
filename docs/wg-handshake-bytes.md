# WireGuard IKpsk2 Handshake — Byte-Level Reference

> Sources: WireGuard whitepaper §5–§6 (Donenfeld, 2017) <https://www.wireguard.com/papers/wireguard.pdf>;
> protocol page <https://www.wireguard.com/protocol/>

---

## 1. Construction Strings

| Name | ASCII value | Role |
|------|-------------|------|
| `CONSTRUCTION` | `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (37 bytes) | Noise protocol name; seeds `h` and `c` at session start |
| `IDENTIFIER` | `WireGuard v1 zx2c4 Jason@zx2c4.com` (34 bytes) | Mixed into `h` after CONSTRUCTION; binds handshake to WireGuard |
| `LABEL_MAC1` | `mac1----` (8 bytes) | Key derivation prefix for mac1 key |
| `LABEL_COOKIE` | `cookie--` (8 bytes) | Key derivation prefix for cookie key |

Initialization (whitepaper §5.4.2):

```
c₀ = HASH(CONSTRUCTION)
h₀ = HASH(c₀ || IDENTIFIER)
h₁ = HASH(h₀ || Sᵣ.public)   ; mixed at session start with responder's static pubkey
```

---

## 2. Type 1 — Handshake Initiation (Initiator → Responder, 148 bytes)

Whitepaper §5.4.2

| Offset | Length | Field | Content |
|--------|--------|-------|---------|
| 0 | 1 | `message_type` | `0x01` |
| 1 | 3 | `reserved` | `0x00 0x00 0x00` |
| 4 | 4 | `sender_index` | Initiator's session index, **little-endian** |
| 8 | 32 | `unencrypted_ephemeral` | Initiator ephemeral pubkey `Eᵢ.public` |
| 40 | 48 | `encrypted_static` | AEAD(k, 0, Sᵢ.public, h) → 32-byte plaintext + 16-byte Poly1305 tag |
| 88 | 28 | `encrypted_timestamp` | AEAD(k, 0, TAI64N, h) → 12-byte plaintext + 16-byte Poly1305 tag |
| 116 | 16 | `mac1` | See §7 |
| 132 | 16 | `mac2` | See §7 |
| **148** | | **total** | |

All AEAD calls use ChaCha20-Poly1305. Nonce is 96-bit: 32-bit zero salt + 64-bit counter (both LE). The counter is `0` for both encrypted fields in Type 1.

---

## 3. Type 2 — Handshake Response (Responder → Initiator, 92 bytes)

Whitepaper §5.4.3

| Offset | Length | Field | Content |
|--------|--------|-------|---------|
| 0 | 1 | `message_type` | `0x02` |
| 1 | 3 | `reserved` | `0x00 0x00 0x00` |
| 4 | 4 | `sender_index` | Responder's session index, **little-endian** |
| 8 | 4 | `receiver_index` | Echoes initiator's `sender_index`, **little-endian** |
| 12 | 32 | `unencrypted_ephemeral` | Responder ephemeral pubkey `Eᵣ.public` |
| 44 | 16 | `encrypted_nothing` | AEAD(k, 0, ε, h) → 0-byte plaintext + 16-byte tag only |
| 60 | 16 | `mac1` | See §7 |
| 76 | 16 | `mac2` | See §7 |
| **92** | | **total** | |

The `encrypted_nothing` field is 16 bytes of tag with zero bytes of ciphertext. PSK (`Q`) is mixed in during Type 2 derivation — not Type 1.

---

## 4. Type 3 — Cookie Reply (64 bytes)

Whitepaper §5.4.7 — only sent when responder is under load.

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 1 | `message_type` = `0x03` |
| 1 | 3 | `reserved` |
| 4 | 4 | `receiver_index` |
| 8 | 24 | `nonce` (XChaCha20 nonce, random) |
| 32 | 32 | `encrypted_cookie` = XChaCha20Poly1305(key, nonce, cookie, mac1_of_received_msg) → 16 bytes plaintext + 16-byte tag |
| **64** | | **total** |

---

## 5. Key Derivation Chain

Notation follows whitepaper §5.4. `HASH` = BLAKE2s-256; `MAC` = BLAKE2s keyed; `HKDF₁`/`HKDF₂` = BLAKE2s-HKDF with 1 or 2 outputs.

### Type 1 steps (Initiator side, §5.4.2)

```
; --- seed ---
c = HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
h = HASH(c || "WireGuard v1 zx2c4 Jason@zx2c4.com")
h = HASH(h || Sᵣ.public)

; --- ephemeral ---
c = HKDF₁(c, Eᵢ.public)         ; MixHash into c
h = HASH(h || Eᵢ.public)         ; MixHash into h

; --- DH(Eᵢ, Sᵣ) ---
(c, k) = HKDF₂(c, DH(Eᵢ.priv, Sᵣ.public))   ; MixKey

; --- encrypt static ---
encrypted_static = AEAD(k, 0, Sᵢ.public, h)
h = HASH(h || encrypted_static)

; --- DH(Sᵢ, Sᵣ) ---
(c, k) = HKDF₂(c, DH(Sᵢ.priv, Sᵣ.public))   ; MixKey

; --- encrypt timestamp ---
encrypted_timestamp = AEAD(k, 0, TAI64N, h)
h = HASH(h || encrypted_timestamp)
```

### Type 2 steps (Responder side, §5.4.3)

```
; --- responder ephemeral ---
c = HKDF₁(c, Eᵣ.public)
h = HASH(h || Eᵣ.public)

; --- DH(Eᵣ, Eᵢ) ---
(c, k) = HKDF₂(c, DH(Eᵣ.priv, Eᵢ.public))

; --- DH(Eᵣ, Sᵢ) ---
(c, k) = HKDF₂(c, DH(Eᵣ.priv, Sᵢ.public))

; --- PSK mix (psk2 = Q, zero if no PSK) ---
(c, τ, k) = HKDF₃(c, Q)
h = HASH(h || τ)

; --- encrypt nothing ---
encrypted_nothing = AEAD(k, 0, ε, h)
h = HASH(h || encrypted_nothing)

; --- session keys ---
(T_send, T_recv) = HKDF₂(c, ε)   ; transport keys
```

---

## 6. TAI64N Timestamp (12 bytes)

Whitepaper §5.1, appendix

| Bytes | Endian | Content |
|-------|--------|---------|
| 0–7 | **Big-endian** | Seconds since 1970-01-01 00:00:00 TAI, with `0x4000000000000000` added (TAI64 label) |
| 8–11 | **Big-endian** | Nanoseconds within the second |

TAI (not Unix) is used to avoid ambiguity during leap seconds — a replayed packet with a manipulated timestamp that crosses a leap-second boundary cannot be disguised as a newer timestamp. The 8-byte field is **big-endian**, unlike nearly everything else in WireGuard which is little-endian.

A typical value: seconds ≈ `0x400000000` + TAI seconds ≈ `0x4000000061A00000`; nanoseconds ≈ `0x00000000`.

---

## 7. MAC1 / MAC2 Computation

Whitepaper §5.4.4

```
mac1_key = HASH(LABEL_MAC1 || Sᵣ.public)   ; 32-byte key, pre-computable

mac1 = MAC(mac1_key, msg[0 .. mac1_offset-1])   ; msg bytes up to (not including) mac1 field

mac2_key = cookie                               ; 16-byte cookie from Type 3 (or zero)
mac2 = MAC(mac2_key, msg[0 .. mac2_offset-1])   ; msg bytes up to (not including) mac2 field
       ; i.e. includes mac1
```

`MAC` here is BLAKE2s keyed, 16-byte output. `mac2` is all zeros when no cookie has been received. MAC1 is computed first; its bytes are part of the input to MAC2.

---

## 8. Common Implementation Pitfalls

- **ChaCha20-Poly1305 nonce layout**: 96-bit nonce = 4 zero bytes (salt) || 8-byte counter, counter is **little-endian**. Counter is `0` for all handshake AEAD calls.
- **Sender/receiver indexes**: 4 bytes each, **little-endian**. Do not confuse sender vs. receiver when echoing back in Type 2.
- **TAI64N endianness**: seconds and nanoseconds are both **big-endian** — this is the one big-endian multi-byte field in the protocol.
- **PSK placement**: `Q` (the pre-shared key) is mixed into the chain in **Type 2**, not Type 1. Absent PSK = 32 zero bytes; do not skip the HKDF₃ step.
- **MAC keys differ in size**: mac1 key = 32 bytes (BLAKE2s output); mac2 key = 16 bytes (cookie). They use the same keyed-MAC primitive but different key lengths.
- **`encrypted_nothing` is not absent**: the Type 2 field at offset 44 is always exactly 16 bytes (the Poly1305 authentication tag); there is no plaintext, but the tag is always transmitted.
