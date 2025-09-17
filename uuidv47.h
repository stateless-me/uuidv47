// Copyright (c) 2025 Stateless Limited
// SPDX-License-Identifier: MIT

#ifndef UUIDV47_H
#define UUIDV47_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>

typedef struct uuid128
{
  uint8_t b[16];
} uuid128_t;
typedef struct uuidv47_key
{
  uint64_t k0, k1; // SipHash 128-bit key
} uuidv47_key_t;


static inline uint64_t rd64le(const void *p)
{
  const uint8_t *x = (const uint8_t *)p;
  return (uint64_t)x[0] | ((uint64_t)x[1] << 8) | ((uint64_t)x[2] << 16) |
         ((uint64_t)x[3] << 24) | ((uint64_t)x[4] << 32) | ((uint64_t)x[5] << 40) |
         ((uint64_t)x[6] << 48) | ((uint64_t)x[7] << 56);
}
static inline void wr48be(uint8_t dst[6], uint64_t v48)
{
  dst[0] = (uint8_t)(v48 >> 40);
  dst[1] = (uint8_t)(v48 >> 32);
  dst[2] = (uint8_t)(v48 >> 24);
  dst[3] = (uint8_t)(v48 >> 16);
  dst[4] = (uint8_t)(v48 >> 8);
  dst[5] = (uint8_t)(v48 >> 0);
}
static inline uint64_t rd48be(const uint8_t src[6])
{
  return ((uint64_t)src[0] << 40) | ((uint64_t)src[1] << 32) | ((uint64_t)src[2] << 24) |
         ((uint64_t)src[3] << 16) | ((uint64_t)src[4] << 8) | ((uint64_t)src[5] << 0);
}

// SipHash-2-4 (reference)
#define ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))
static inline uint64_t siphash24(const uint8_t *in, size_t inlen, uint64_t k0, uint64_t k1)
{
  uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
  uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
  uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
  uint64_t v3 = 0x7465646279746573ULL ^ k1;

  const uint8_t *end = in + (inlen & ~7u);
  uint64_t m, b = ((uint64_t)inlen) << 56;

  for (; in != end; in += 8)
  {
    m = rd64le(in);
    v3 ^= m;
    // 2 compression rounds
    for (int i = 0; i < 2; i++)
    {
      v0 += v1;
      v2 += v3;
      v1 = ROTL64(v1, 13);
      v3 = ROTL64(v3, 16);
      v1 ^= v0;
      v3 ^= v2;
      v0 = ROTL64(v0, 32);
      v2 += v1;
      v0 += v3;
      v1 = ROTL64(v1, 17);
      v3 = ROTL64(v3, 21);
      v1 ^= v2;
      v3 ^= v0;
      v2 = ROTL64(v2, 32);
    }
    v0 ^= m;
  }

  // last 0..7 bytes
  uint64_t t = 0;
  switch (inlen & 7u)
  {
  case 7:
    t |= ((uint64_t)in[6]) << 48; // fallthrough
  case 6:
    t |= ((uint64_t)in[5]) << 40;
  case 5:
    t |= ((uint64_t)in[4]) << 32;
  case 4:
    t |= ((uint64_t)in[3]) << 24;
  case 3:
    t |= ((uint64_t)in[2]) << 16;
  case 2:
    t |= ((uint64_t)in[1]) << 8;
  case 1:
    t |= ((uint64_t)in[0]) << 0;
  }
  b |= t;

  v3 ^= b;
  for (int i = 0; i < 2; i++)
  {
    v0 += v1;
    v2 += v3;
    v1 = ROTL64(v1, 13);
    v3 = ROTL64(v3, 16);
    v1 ^= v0;
    v3 ^= v2;
    v0 = ROTL64(v0, 32);
    v2 += v1;
    v0 += v3;
    v1 = ROTL64(v1, 17);
    v3 = ROTL64(v3, 21);
    v1 ^= v2;
    v3 ^= v0;
    v2 = ROTL64(v2, 32);
  }
  v0 ^= b;

  v2 ^= 0xff;
  for (int i = 0; i < 4; i++)
  {
    v0 += v1;
    v2 += v3;
    v1 = ROTL64(v1, 13);
    v3 = ROTL64(v3, 16);
    v1 ^= v0;
    v3 ^= v2;
    v0 = ROTL64(v0, 32);
    v2 += v1;
    v0 += v3;
    v1 = ROTL64(v1, 17);
    v3 = ROTL64(v3, 21);
    v1 ^= v2;
    v3 ^= v0;
    v2 = ROTL64(v2, 32);
  }
  return v0 ^ v1 ^ v2 ^ v3;
}
#undef ROTL64

// Version/variant helpers
static inline int uuid_version(const uuid128_t *u) { return (u->b[6] >> 4) & 0x0F; }
static inline void set_version(uuid128_t *u, int ver) { u->b[6] = (uint8_t)((u->b[6] & 0x0F) | ((ver & 0x0F) << 4)); }
static inline void set_variant_rfc4122(uuid128_t *u) { u->b[8] = (uint8_t)((u->b[8] & 0x3F) | 0x80); } // 10xxxxxx

// Sip input (stable across v7<->v4)
static inline void build_sip_input_from_v7(const uuid128_t *u, uint8_t msg[10])
{
  // Take exactly the random bits of v7 (rand_a 12b + rand_b 62b) but
  // as easy full bytes: [low-nibble of b6][b7][b8&0x3F][b9..b15]
  msg[0] = (uint8_t)(u->b[6] & 0x0F);
  msg[1] = u->b[7];
  msg[2] = (uint8_t)(u->b[8] & 0x3F);
  memcpy(&msg[3], &u->b[9], 7);
}
// The same function works for the façade, because fields at [6] low nibble,
// [7], [8]&0x3F and [9..15] are identical before/after the transform.

// Core encode/decode
static inline uuid128_t uuidv47_encode_v4facade(uuid128_t v7, uuidv47_key_t key)
{
  // 1) mask = SipHash24(key, v7.random74bits) -> take low 48 bits
  uint8_t sipmsg[10];
  build_sip_input_from_v7(&v7, sipmsg);
  uint64_t mask48 = siphash24(sipmsg, sizeof(sipmsg), key.k0, key.k1) & 0x0000FFFFFFFFFFFFULL;

  // 2) encTS = ts ^ mask
  uint64_t ts48 = rd48be(&v7.b[0]);
  uint64_t encTS = ts48 ^ mask48;

  // 3) build v4 façade: write encTS, set ver=4, keep rand bytes identical, set variant
  uuid128_t out = v7;
  wr48be(&out.b[0], encTS);
  set_version(&out, 4);      // façade v4
  set_variant_rfc4122(&out); // ensure RFC variant bits
  return out;
}

static inline uuid128_t uuidv47_decode_v4facade(uuid128_t v4facade, uuidv47_key_t key)
{
  // 1) rebuild same Sip input from façade (identical bytes)
  uint8_t sipmsg[10];
  build_sip_input_from_v7(&v4facade, sipmsg);
  uint64_t mask48 = siphash24(sipmsg, sizeof(sipmsg), key.k0, key.k1) & 0x0000FFFFFFFFFFFFULL;

  // 2) ts = encTS ^ mask
  uint64_t encTS = rd48be(&v4facade.b[0]);
  uint64_t ts48 = encTS ^ mask48;

  // 3) restore v7: write ts, set ver=7, set variant
  uuid128_t out = v4facade;
  wr48be(&out.b[0], ts48);
  set_version(&out, 7);
  set_variant_rfc4122(&out);
  return out;
}

// String I/O (canonical 8-4-4-4-12)
static inline int hexval(int c)
{
  if ('0' <= c && c <= '9')
    return c - '0';
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static inline bool uuid_parse(const char *s, uuid128_t *out)
{
  // expects xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  int idxs[32] = {0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 14, 15, 16, 17, 19, 20, 21, 22, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35};
  uint8_t b[16] = {0};
  for (int i = 0; i < 16; i++)
  {
    int h = hexval(s[idxs[i * 2]]);
    int l = hexval(s[idxs[i * 2 + 1]]);
    if (h < 0 || l < 0)
      return false;
    b[i] = (uint8_t)((h << 4) | l);
  }
  memcpy(out->b, b, 16);
  return true;
}

static inline void uuid_format(const uuid128_t *u, char out[37])
{
  static const char *hexd = "0123456789abcdef";
  int dpos[4] = {4, 6, 8, 10};
  int j = 0;
  for (int i = 0; i < 16; i++)
  {
    if (i == dpos[0] || i == dpos[1] || i == dpos[2] || i == dpos[3])
      out[j++] = '-';
    out[j++] = hexd[(u->b[i] >> 4) & 0xF];
    out[j++] = hexd[u->b[i] & 0xF];
  }
  out[36] = '\0';
}

#endif // UUIDV47_H
