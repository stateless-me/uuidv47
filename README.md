UUIDv47 - UUIDv7-in / UUIDv4-out (SipHash-masked timestamp)
==================================================================

uuidv47 lets you store sortable UUIDv7 in your database while emitting a
UUIDv4-looking façade at your API boundary. It does this by XOR-masking
only the UUIDv7 timestamp field with a keyed SipHash-2-4 stream tied to
the UUID’s own random bits.

- Header-only C (C89) · zero deps
- Deterministic, invertible mapping (exact round-trip)
- RFC-compatible version/variant bits (v7 in DB, v4 on the wire)
- Key-recovery resistant (SipHash-2-4, 128-bit key)
- Full tests provided

------------------------------------------------------------------

Table of contents
-----------------
- Why
- Quick start
- Public API
- Specification
  - UUIDv7 bit layout
  - Façade mapping (v7 ↔ v4)
  - SipHash message derived from random
  - Invertibility
  - Collision analysis
- Security model
- Build, test, coverage
- Integration tips
- Performance notes
- Benchmarks
- FAQ
- License

------------------------------------------------------------------

Why
---
- DB-friendly: UUIDv7 is time-ordered → better index locality & pagination.
- Externally neutral: The façade hides timing patterns and looks like v4 to clients/systems.
- Secret safety: Uses a PRF (SipHash-2-4). Non-crypto hashes are not suitable when the key must not leak.

------------------------------------------------------------------

Quick start
-----------
```c
#include <stdio.h>
#include "uuidv47.h"

int main(void){
  const char* s = "00000000-0000-7000-8000-000000000000";
  uuid128_t v7;
  if (!uuid_parse(s, &v7)) return 1;
  uuidv47_key_t key = { .k0 = 0x0123456789abcdefULL, .k1 = 0xfedcba9876543210ULL };
  uuid128_t facade = uuidv47_encode_v4facade(v7, key);
  uuid128_t back = uuidv47_decode_v4facade(facade, key);

  char a[37], b[37], c[37];
  uuid_format(&v7, a);
  uuid_format(&facade, b);
  uuid_format(&back, c);
  printf("v7 (DB) : %s\n", a);
  printf("v4 (API): %s\n", b);
  printf("back    : %s\n", c);
}
```

Build & run with the provided Makefile:
  make test
  make coverage
  sudo make install

------------------------------------------------------------------

Public API
----------

```c
typedef struct { uint8_t  b[16]; } uuid128_t;
typedef struct { uint64_t k0, k1; } uuidv47_key_t;

uuid128_t uuidv47_encode_v4facade(uuid128_t v7, uuidv47_key_t key);
uuid128_t uuidv47_decode_v4facade(uuid128_t v4_facade, uuidv47_key_t key);
int  uuid_version(const uuid128_t* u);
void set_version(uuid128_t* u, int ver);
void set_variant_rfc4122(uuid128_t* u);
bool uuid_parse (const char* str, uuid128_t* out);
void uuid_format(const uuid128_t* u, char out[37]);
```

------------------------------------------------------------------

Specification
-------------
UUIDv7 bit layout:
- ts_ms_be: 48-bit big-endian timestamp
- ver:      high nibble of byte 6 = 0x7 (v7) or 0x4 (façade)
- rand_a:   12 random bits
- var:      RFC variant (0b10)
- rand_b:   62 random bits

Façade mapping:
- Encode: ts48 ^ mask48(R), set version=4
- Decode: encTS ^ mask48(R), set version=7
- Random bits unchanged

SipHash input: 10 bytes from random field:
  msg[0] = (byte6 & 0x0F)
  msg[1] = byte7
  msg[2] = (byte8 & 0x3F)
  msg[3..9] = bytes9..15

Invertibility: XOR mask is reversible with known key.

Collision analysis: Injective mapping. Only risk is duplicate randoms per ms.

------------------------------------------------------------------

Security model
--------------
- Goal: Secret key unrecoverable even with chosen inputs.
- Achieved: SipHash-2-4 is a keyed PRF.
- Keys: 128-bit. Derive via HKDF.
- Rotation: store small key ID outside UUID.

------------------------------------------------------------------

Build, test, coverage
---------------------
```
make test
make coverage
make debug
sudo make install
# optional
make bench && ./bench
```

------------------------------------------------------------------

Integration tips
----------------
- Do encode/decode at API boundary.
- For Postgres, write tiny C extension.
- For sharding, hash v4 façade with xxh3 or SipHash.

------------------------------------------------------------------

Performance
-----------
SipHash-2-4 on 10-byte message is extremely fast. No allocations.

------------------------------------------------------------------

Benchmarks
-----------

**Command:** `./bench` (2,000,000 iters, 1 warmup + 3 rounds)  

**Example run on M1:**
```bash
iters=2000000, warmup=1, rounds=3
[warmup] 34.89 ns/op
[encode+decode] round 1: 33.80 ns/op, 29.6 Mops/s
[encode+decode] round 2: 38.16 ns/op, 26.2 Mops/s
[encode+decode] round 3: 33.33 ns/op, 30.0 Mops/s
[warmup] 14.83 ns/op
[siphash(10B)] round 1: 14.88 ns/op, 67.2 Mops/s
[siphash(10B)] round 2: 15.45 ns/op, 64.7 Mops/s
[siphash(10B)] round 3: 15.00 ns/op, 66.7 Mops/s
== best results ==
encode+decode : 33.00 ns/op (30.3 Mops/s)
siphash(10B)  : 14.00 ns/op (71.4 Mops/s)
```

**What it measures**
- `encode+decode`: full v7 → façade → v7 round-trip.  
- `siphash(10B)`: SipHash-2-4 on the 10-byte mask message.  

*Notes: build with `-O3 -march=native` for best results.*  

------------------------------------------------------------------
FAQ
---
Q: Why not xxHash with a secret?
A: Not a PRF; secret can leak. Use SipHash.

Q: Is façade indistinguishable from v4?
A: Yes, variable bits uniform, version/variant set to v4.

------------------------------------------------------------------

License
-------
MIT, Copyright (c) 2025 Stateless Limited
