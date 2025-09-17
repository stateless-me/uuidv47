// Copyright (c) 2025 Stateless Limited
// SPDX-License-Identifier: MIT

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "uuidv47.h"

static uint64_t le_bytes_to_u64(const uint8_t b[8])
{
  return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
         ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) |
         ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) |
         ((uint64_t)b[7] << 56);
}

static void test_rd_wr_48(void)
{
  uint8_t buf[6] = {0};
  const uint64_t v = 0x0123456789ABULL & 0x0000FFFFFFFFFFFFULL;
  wr48be(buf, v);
  uint64_t r = rd48be(buf);
  assert(r == v);
}

static void test_uuid_parse_format_roundtrip(void)
{
  // Correct 8-4-4-4-12 layout; version nibble '7' at start of 3rd group; RFC variant '8' in 4th.
  const char *s = "00000000-0000-7000-8000-000000000000";
  uuid128_t u = (uuid128_t){{0}};
  assert(uuid_parse(s, &u));
  assert(uuid_version(&u) == 7);

  char out[37];
  uuid_format(&u, out);
  uuid128_t u2 = (uuid128_t){{0}};
  assert(uuid_parse(out, &u2));
  assert(memcmp(&u, &u2, sizeof(u)) == 0);

  const char *bad = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz";
  uuid128_t t = (uuid128_t){{0}};
  assert(!uuid_parse(bad, &t));
}

static void test_version_variant(void)
{
  uuid128_t u = (uuid128_t){{0}};
  set_version(&u, 7);
  assert(uuid_version(&u) == 7);
  set_variant_rfc4122(&u);
  assert((u.b[8] & 0xC0) == 0x80);
}

static void test_siphash_switch_and_vectors_subset(void)
{
  const uint64_t k0 = 0x0706050403020100ULL;
  const uint64_t k1 = 0x0f0e0d0c0b0a0908ULL;

  const uint8_t vbytes[13][8] = {
      {0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72}, // len 0
      {0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74}, // len 1
      {0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d}, // len 2
      {0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85}, // len 3
      {0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf}, // len 4
      {0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18}, // len 5
      {0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb}, // len 6
      {0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab}, // len 7
      {0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93}, // len 8
      {0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e}, // len 9
      {0xf3, 0xb9, 0xdd, 0x94, 0xc5, 0xbb, 0x5d, 0x7a}, // len 10
      {0xa7, 0xad, 0x6b, 0x22, 0x46, 0x2f, 0xb3, 0xf4}, // len 11
      {0xfb, 0xe5, 0x0e, 0x86, 0xbc, 0x8f, 0x1e, 0x75}, // len 12
  };

  uint8_t msg[64];
  for (int i = 0; i < 64; i++)
    msg[i] = (uint8_t)i;

  for (int len = 0; len < 13; len++)
  {
    uint64_t got = siphash24(msg, (size_t)len, k0, k1);
    uint64_t exp = le_bytes_to_u64(vbytes[len]);
    assert(got == exp);
  }

  (void)siphash24(msg, 15, k0, k1); // exercise extra tail paths
}

static void craft_v7(uuid128_t *u, uint64_t ts_ms_48, uint16_t rand_a_12, uint64_t rand_b_62)
{
  memset(u, 0, sizeof(*u));
  wr48be(&u->b[0], ts_ms_48 & 0x0000FFFFFFFFFFFFULL);
  set_version(u, 7);
  u->b[6] = (uint8_t)((u->b[6] & 0xF0) | ((rand_a_12 >> 8) & 0x0F));
  u->b[7] = (uint8_t)(rand_a_12 & 0xFF);
  set_variant_rfc4122(u);
  u->b[8] = (uint8_t)((u->b[8] & 0xC0) | ((rand_b_62 >> 56) & 0x3F));
  for (int i = 0; i < 7; i++)
    u->b[9 + i] = (uint8_t)((rand_b_62 >> (8 * (6 - i))) & 0xFF);
}

static void test_build_sip_input_stability(void)
{
  uuid128_t u7;
  craft_v7(&u7, 0x123456789ABCLL, 0x0ABC, 0x0123456789ABCDEFULL & ((1ULL << 62) - 1));
  uuidv47_key_t key = {.k0 = 0x0123456789abcdefULL, .k1 = 0xfedcba9876543210ULL};
  uuid128_t facade = uuidv47_encode_v4facade(u7, key);

  uint8_t m1[10], m2[10];
  build_sip_input_from_v7(&u7, m1);
  build_sip_input_from_v7(&facade, m2);
  assert(memcmp(m1, m2, 10) == 0);
}

static void test_encode_decode_roundtrip(void)
{
  uuidv47_key_t key = {.k0 = 0x0123456789abcdefULL, .k1 = 0xfedcba9876543210ULL};

  for (int i = 0; i < 16; i++)
  {
    uuid128_t u7;
    uint64_t ts = (uint64_t)((0x100000ULL * (uint64_t)i) + 123ULL);
    uint16_t ra = (uint16_t)((0x0AAA ^ (uint32_t)(i * 7)) & 0x0FFF);
    uint64_t rb = (0x0123456789ABCDEFULL ^ (0x1111111111111111ULL * (uint64_t)i)) & ((1ULL << 62) - 1);
    craft_v7(&u7, ts, ra, rb);

    uuid128_t facade = uuidv47_encode_v4facade(u7, key);
    assert(uuid_version(&facade) == 4);
    assert((facade.b[8] & 0xC0) == 0x80);

    uuid128_t back = uuidv47_decode_v4facade(facade, key);
    assert(memcmp(&u7, &back, sizeof(u7)) == 0);

    uuidv47_key_t wrong = {.k0 = key.k0 ^ 0xdeadbeefULL, .k1 = key.k1 ^ 0x1337ULL};
    uuid128_t bad = uuidv47_decode_v4facade(facade, wrong);
    assert(memcmp(&u7, &bad, sizeof(u7)) != 0);
  }
}

int main(void)
{
  test_rd_wr_48();
  test_uuid_parse_format_roundtrip();
  test_version_variant();
  test_siphash_switch_and_vectors_subset();
  test_build_sip_input_stability();
  test_encode_decode_roundtrip();
  puts("All tests passed.");
  return 0;
}
