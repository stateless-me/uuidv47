UUIDv47 — UUIDv7-in / UUIDv4-out (SipHash‑masked timestamp)
===========================================================

`uuidv47` lets you store sortable UUIDv7 in your database while emitting a
UUIDv4‑looking façade at your API boundary. It XOR‑masks *only* the UUIDv7
timestamp field with a keyed SipHash‑2‑4 stream derived from the UUID’s own
random bits. The mapping is deterministic and exactly invertible.

- Header‑only C (C89) · zero deps
- Deterministic, invertible mapping (exact round‑trip)
- RFC‑compatible version/variant bits (v7 in DB, v4 on the wire)
- Key‑recovery resistant (SipHash‑2‑4, 128‑bit key)
- Full tests provided
- Optional PostgreSQL extension (UUID type + operators/opclasses)

------------------------------------------------------------------

Table of contents
-----------------
- Why
- Quick start (C)
- Public C API
- Specification
  - UUIDv7 bit layout
  - Façade mapping (v7 ↔ v4)
  - SipHash message derived from random
  - Invertibility
  - Collision analysis
- Security model
- Build, test, coverage
- PostgreSQL extension
  - Build & install
  - Tests
  - Gotchas & performance tips
- Integration tips
- Performance notes
- Benchmarks (C)
- Ports in other languages
- Production recommendations
- FAQ
- License

------------------------------------------------------------------

Why
---
- **DB‑friendly**: UUIDv7 is time‑ordered → better index locality & pagination.
- **Externally neutral**: The façade hides timing patterns and looks like v4 to clients/systems.
- **Secret safety**: Uses a PRF (SipHash‑2‑4). Non‑crypto hashes are not suitable when the key must not leak.

------------------------------------------------------------------

Quick start (C)
---------------
```c
#include <stdio.h>
#include "uuidv47.h"

int main(void){
  const char* s = "00000000-0000-7000-8000-000000000000";
  uuid128_t v7;
  if (!uuid_parse(s, &v7)) return 1;

  uuidv47_key_t key = { .k0 = 0x0123456789abcdefULL, .k1 = 0xfedcba9876543210ULL };

  uuid128_t facade = uuidv47_encode_v4facade(v7, key);
  uuid128_t back   = uuidv47_decode_v4facade(facade, key);

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

```
make test
make coverage
sudo make install     # installs header into $(PREFIX)/include
```

------------------------------------------------------------------

Public C API
------------

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

### UUIDv7 bit layout
- **ts_ms_be**: 48‑bit big‑endian timestamp
- **ver**: high nibble of byte 6 = 0x7 (v7) or 0x4 (façade)
- **rand_a**: 12 random bits
- **var**: RFC variant (0b10)
- **rand_b**: 62 random bits

### Façade mapping
- **Encode**: `ts48 ^ mask48(R)`, then set version = 4
- **Decode**: `encTS ^ mask48(R)`, then set version = 7
- Random bits remain unchanged.

### SipHash message
10 bytes derived from the v7 random field:
```
msg[0] = (byte6 & 0x0F)
msg[1] = byte7
msg[2] = (byte8 & 0x3F)
msg[3..9] = bytes9..15
```

### Invertibility
The mask is XOR with a keyed PRF → perfectly invertible when the key is known.

### Collision analysis
Mapping is injective; collisions reduce to duplicate randoms within the same ms.

------------------------------------------------------------------

Security model
--------------
- **Goal**: Secret key unrecoverable even with chosen inputs.
- **Achieved**: SipHash‑2‑4 is a keyed PRF.
- **Keys**: 128‑bit. Recommend deriving via HKDF.
- **Rotation**: Store a small key ID alongside UUIDs (out‑of‑band).

------------------------------------------------------------------

Build, test, coverage
---------------------
```
make test
make coverage
make debug
sudo make install
# optional microbench
make bench && ./bench
```

------------------------------------------------------------------

PostgreSQL extension
--------------------

This repo includes an optional Postgres extension that defines a `uuid47` base
type, casts to/from core `uuid`, operators, B‑tree/hash opclasses, and a BRIN
(minmax‑multi) distance support function.

### Build & install
```
# From repo root (uses PGXS via pg_config)
make pginstall
```

Enable in a database:
```sql
CREATE EXTENSION uuid47;          -- installs type and functions
-- (If you installed into a custom schema, add it to search_path.)
```

### Tests
Run the SQL test suite end‑to‑end:
```
make pgtest   PG_CONFIG=/opt/homebrew/opt/postgresql@17/bin/pg_config   PSQL="/opt/homebrew/opt/postgresql@17/bin/psql"   DBNAME=postgres
```

### Gotchas & performance tips
- **Use the native column type**: store `uuid47_generate()` into a `uuid47`
  column. Inserting into `uuid` triggers an assignment cast every row and can be
  ~2–3 µs/row slower.
- **Type alignment**: `uuid47` uses `ALIGNMENT = int4` (like core `uuid`) for
  better tuple formation speed.
- **Key GUC**: some transforms (e.g., façade output) require a session key:
  ```sql
  SET uuid47.key = '0011223344556677:8899aabbccddeeff';
  ```
  Parse happens once via a GUC assign hook and is cached per backend.

------------------------------------------------------------------

Integration tips
----------------

- Store only the UUIDv7, not the facade ID.
- Manage the secret through a Key Management Service (KMS).

**Frontend/client-facing entities**

→ Use **UUIDv47** with a B-Tree index. Users aren’t expected to persist this ID and can tolerate cache resets. Secure the secret with an HSM and inject it safely into the process.

**External service–facing entities**

→ If the service is **secure** (e.g., financial), provide **UUID7 (UUIDv47)**.

→ If the service is **not secure**, provide a **secondary ID of type UUIDv4** with a hashmap index.
  
If the master key leaks, it’s almost certain your consumer data and systems have leaked as well—which is ultimately a **legal problem**, not a technical one. Data leaks will cause far greater issues than the compromise of an ID master key, which can be rotated safely since only the frontend depends on it.

------------------------------------------------------------------

Performance notes
-----------------
- SipHash‑2‑4 on a 10‑byte message is extremely fast and allocation‑free.
- The provided implementation avoids per‑row GUC parsing and minimizes copies.
- Monotonic generator uses per‑backend state; ordering is stable within a session.

------------------------------------------------------------------

Benchmarks (C)
--------------

**Command:** `./bench` (2,000,000 iters, 1 warmup + 3 rounds)

**Example (Apple M‑series):**
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

What it measures
- `encode+decode`: full v7 → façade → v7 round‑trip.
- `siphash(10B)`: SipHash‑2‑4 on the 10‑byte mask message.

> Build with `-O3 -march=native` for best results.

------------------------------------------------------------------

Ports in other languages
------------------------
- **Go:** [n2p5/uuid47](https://github.com/n2p5/uuid47) — Go port of UUIDv47
- **JavaScript:** [sh1kxrv/node_uuidv47](https://github.com/sh1kxrv/node_uuidv47) — JavaScript port of UUIDv47 with native bindings
- **C#/.NET:** [taiseiue/UUIDv47Sharp](https://github.com/taiseiue/UUIDv47Sharp) - C#/.NET ecosystem port of UUIDv47
- **Ruby:** [sylph01/uuid47](https://github.com/sylph01/uuid47) - Ruby port of UUIDv47

------------------------------------------------------------------

FAQ
---
**Q: Why not xxHash with a secret?**  
A: Not a PRF; secret can leak. Use SipHash.

**Q: Is the façade indistinguishable from v4?**  
A: Version/variant bits are v4; variable bits are uniformly distributed under the PRF.

------------------------------------------------------------------

License
-------
MIT, Copyright (c) 2025 Stateless Limited
