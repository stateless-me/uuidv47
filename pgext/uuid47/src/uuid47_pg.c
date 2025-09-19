// Copyright (c) 2025 Stateless Limited
// SPDX-License-Identifier: MIT

#include "postgres.h"
#include "fmgr.h"

#include "access/hash.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "common/hashfn.h"
#include "funcapi.h"
#include "libpq/pqformat.h"
#include "miscadmin.h"
#include "port.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/timestamp.h"
#include "utils/uuid.h"

#include "../../uuidv47.h"

PG_MODULE_MAGIC;

/* ----------------------------------------------------------- */
/* GUC: session/cluster key                                    */
/* ----------------------------------------------------------- */

static char *uuid47_key_guc = NULL;

static bool parse_hex64(const char *p, uint64_t *out);
static bool parse_key_from_guc(uuidv47_key_t *key);
static inline void require_len(bytea *b, int expected);
static inline uuidv47_key_t key_from_bytea(bytea *b);
static inline uuidv47_key_t key_from_guc_or_error(void);

void _PG_init(void);

/* ----------------------------------------------------------- */
/* Tiny helpers                                                */
/* ----------------------------------------------------------- */

typedef struct
{
  uint8_t data[16];
} u16;

static inline void
ptr16_to_uuid128(const void *p, uuid128_t *u)
{
  memcpy(u->b, p, 16);
}

static inline void
uuid128_to_ptr16(const uuid128_t *u, void *p)
{
  memcpy(p, u->b, 16);
}

static inline int
uuid_version_from_bytes(const uint8_t *b)
{
  return (b[6] >> 4) & 0x0F;
}

/* ----------------------------------------------------------- */
/* Timestamp conversions (PG <-> Unix ms)                       */
/* ----------------------------------------------------------- */

#define UNIX_EPOCH_SECS_FROM_Y2000 946684800LL

static inline uint64_t
current_unix_ms(void)
{
  int64 us;
  int64 unix_us;

  us = GetCurrentTimestamp(); /* µs since 2000-01-01 */
  unix_us = us + (UNIX_EPOCH_SECS_FROM_Y2000 * 1000000LL);
  if (unix_us < 0)
    unix_us = 0;
  return (uint64_t)(unix_us / 1000LL);
}

static inline TimestampTz
unix_ms_to_timestamptz(uint64_t ms)
{
  int64 unix_us;
  int64 pg_us;

  unix_us = (int64)(ms * 1000ULL);
  pg_us = unix_us - (UNIX_EPOCH_SECS_FROM_Y2000 * 1000000LL);
  return (TimestampTz)pg_us;
}

static inline uint64_t
timestamptz_to_unix_ms(TimestampTz ts)
{
  int64 pg_us;
  int64 unix_us;

  pg_us = (int64)ts;
  unix_us = pg_us + (UNIX_EPOCH_SECS_FROM_Y2000 * 1000000LL);
  if (unix_us < 0)
    unix_us = 0;
  return (uint64_t)(unix_us / 1000ULL);
}

/* ----------------------------------------------------------- */
/* GUC parsing                                                  */
/* ----------------------------------------------------------- */

/* --- helpers for LE hex parsing --- */
static int hex_nibble(int c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* parse exactly 2*n hex chars into out[n] bytes; returns false on error */
static bool parse_hex_bytes_exact(const char *s, size_t n, uint8_t *out)
{
  size_t i;
  for (i = 0; i < n; i++)
  {
    int h = hex_nibble((unsigned char)s[2 * i + 0]);
    int l = hex_nibble((unsigned char)s[2 * i + 1]);
    if (h < 0 || l < 0)
      return false;
    out[i] = (uint8_t)((h << 4) | l);
  }
  return true;
}

/* Accepts:
 *   - "k0:k1" where each is 16 hex digits (8 bytes), interpreted as **little-endian** u64
 *   - 32 hex digits "k0||k1" (16 bytes), first 8 are k0 LE, next 8 are k1 LE
 *   (Spaces ignored; optional 0x prefix on each side is allowed.)
 */
static bool
parse_key_from_guc(uuidv47_key_t *key)
{
  const char *s;
  const char *colon;
  char lhs[65], rhs[65], compact[129];
  size_t n0, n1, L;
  uint8_t buf[16];

  if (!uuid47_key_guc || uuid47_key_guc[0] == '\0')
    return false;

  /* strip spaces into compact[] */
  s = uuid47_key_guc;
  L = 0;
  for (const char *p = s; *p; p++)
    if (!isspace((unsigned char)*p))
      compact[L++] = *p;
  compact[L] = 0;

  colon = strchr(compact, ':');
  if (colon)
  {
    /* split lhs / rhs */
    n0 = (size_t)(colon - compact);
    n1 = strlen(colon + 1);

    /* drop optional 0x */
    const char *p0 = compact;
    const char *p1 = colon + 1;
    if (n0 >= 2 && p0[0] == '0' && (p0[1] == 'x' || p0[1] == 'X'))
    {
      p0 += 2;
      n0 -= 2;
    }
    if (n1 >= 2 && p1[0] == '0' && (p1[1] == 'x' || p1[1] == 'X'))
    {
      p1 += 2;
      n1 -= 2;
    }

    if (n0 != 16 || n1 != 16)
      return false;

    /* parse each side as 8 bytes, then read LE */
    if (!parse_hex_bytes_exact(p0, 8, buf))
      return false;
    key->k0 = rd64le(buf);

    if (!parse_hex_bytes_exact(p1, 8, buf))
      return false;
    key->k1 = rd64le(buf);

    return true;
  }

  /* no colon: expect 32 hex digits total */
  if (L >= 2 && compact[0] == '0' && (compact[1] == 'x' || compact[1] == 'X'))
  {
    memmove(compact, compact + 2, L - 2);
    L -= 2;
    compact[L] = 0;
  }
  if (L != 32)
    return false;

  /* first 16 hex => k0 LE, next 16 => k1 LE */
  if (!parse_hex_bytes_exact(compact, 8, buf))
    return false;
  key->k0 = rd64le(buf);

  if (!parse_hex_bytes_exact(compact + 16, 8, buf))
    return false;
  key->k1 = rd64le(buf);

  return true;
}

static inline void
require_len(bytea *b, int expected)
{
  if (VARSIZE_ANY_EXHDR(b) != expected)
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("key must be %d bytes, got %d", expected, (int)VARSIZE_ANY_EXHDR(b))));
}

/* interpret bytea as k0||k1 (LE) */
static inline uuidv47_key_t
key_from_bytea(bytea *b)
{
  const uint8_t *p;
  uuidv47_key_t k;

  require_len(b, 16);
  p = (const uint8_t *)VARDATA_ANY(b);

  k.k0 = ((uint64_t)p[0]) | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
         ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
  k.k1 = ((uint64_t)p[8]) | ((uint64_t)p[9] << 8) | ((uint64_t)p[10] << 16) | ((uint64_t)p[11] << 24) |
         ((uint64_t)p[12] << 32) | ((uint64_t)p[13] << 40) | ((uint64_t)p[14] << 48) | ((uint64_t)p[15] << 56);
  return k;
}

static inline uuidv47_key_t
key_from_guc_or_error(void)
{
  uuidv47_key_t k;
  if (!parse_key_from_guc(&k))
    ereport(ERROR,
            (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
             errmsg("uuid47.key GUC is not set or invalid"),
             errdetail("Set e.g. SET uuid47.key = '0011223344556677:8899aabbccddeeff' or 'k0:k1'.")));
  return k;
}

/* ----------------------------------------------------------- */
/* Module init                                                  */
/* ----------------------------------------------------------- */

void _PG_init(void)
{
  DefineCustomStringVariable(
      "uuid47.key",
      "128-bit key for uuid47 transforms ('k0:k1' hex or 32-hex k0||k1 LE).",
      "Example: 0011223344556677:8899aabbccddeeff",
      &uuid47_key_guc,
      NULL,
      PGC_USERSET, 0,
      NULL, NULL, NULL);
}

/* ----------------------------------------------------------- */
/* Type I/O                                                     */
/* ----------------------------------------------------------- */

PG_FUNCTION_INFO_V1(uuid47_in);
Datum uuid47_in(PG_FUNCTION_ARGS)
{
  /* Parse once using core uuid_in (it palloc's a pg_uuid_t) */
  const char *str = PG_GETARG_CSTRING(0);
  pg_uuid_t *parsed = (pg_uuid_t *)DatumGetPointer(
      DirectFunctionCall1(uuid_in, CStringGetDatum(str)));

  int ver = (parsed->data[6] >> 4) & 0x0F;

  if (ver == 7)
  {
    /* Already a UUIDv7 byte layout compatible with uuid47 -> reuse buffer */
    PG_RETURN_POINTER(parsed);
  }
  else if (ver == 4)
  {
    /* Decode facade -> write back into the same 16B buffer */
    uuidv47_key_t key = key_from_guc_or_error();
    uuid128_t in, out;
    ptr16_to_uuid128(parsed->data, &in);
    out = uuidv47_decode_v4facade(in, key);
    uuid128_to_ptr16(&out, parsed->data); /* in-place */
    PG_RETURN_POINTER(parsed);
  }
  else
  {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
             errmsg("uuid47_in expects UUIDv7 or UUIDv4-looking text (got version %d)", ver)));
  }
}

PG_FUNCTION_INFO_V1(uuid47_out);
Datum uuid47_out(PG_FUNCTION_ARGS)
{
  const u16 *in;
  uuidv47_key_t key;
  uuid128_t v7;
  uuid128_t v4;
  pg_uuid_t tmp;
  char *res;

  in = (const u16 *)PG_GETARG_POINTER(0);
  key = key_from_guc_or_error();

  ptr16_to_uuid128(in->data, &v7);
  v4 = uuidv47_encode_v4facade(v7, key);

  uuid128_to_ptr16(&v4, tmp.data);
  res = DatumGetCString(DirectFunctionCall1(uuid_out, UUIDPGetDatum(&tmp)));
  PG_RETURN_CSTRING(res);
}

/* Binary I/O */

PG_FUNCTION_INFO_V1(uuid47_recv);
Datum uuid47_recv(PG_FUNCTION_ARGS)
{
  StringInfo buf;
  u16 *ret;
  int ver;

  buf = (StringInfo)PG_GETARG_POINTER(0);
  ret = (u16 *)palloc(sizeof(u16));
  pq_copymsgbytes(buf, (char *)ret->data, 16);

  ver = uuid_version_from_bytes(ret->data);
  if (ver == 4)
  {
    uuid128_t in;
    uuid128_t v7;
    uuidv47_key_t key = key_from_guc_or_error();

    ptr16_to_uuid128(ret->data, &in);
    v7 = uuidv47_decode_v4facade(in, key);
    uuid128_to_ptr16(&v7, ret->data);
  }
  else if (ver != 7)
  {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_BINARY_REPRESENTATION),
             errmsg("uuid47_recv expects UUIDv7 or UUIDv4-looking binary (got version %d)", ver)));
  }

  PG_RETURN_POINTER(ret);
}

PG_FUNCTION_INFO_V1(uuid47_send);
Datum uuid47_send(PG_FUNCTION_ARGS)
{
  const u16 *in;
  StringInfoData buf;

  in = (const u16 *)PG_GETARG_POINTER(0);
  pq_begintypsend(&buf);
  pq_sendbytes(&buf, (const char *)in->data, 16);
  PG_RETURN_BYTEA_P(pq_endtypsend(&buf));
}

/* ----------------------------------------------------------- */
/* Directional transforms                                       */
/* ----------------------------------------------------------- */

PG_FUNCTION_INFO_V1(uuid47_to_uuid);
Datum uuid47_to_uuid(PG_FUNCTION_ARGS)
{
  const u16 *in;
  uuidv47_key_t key;
  uuid128_t v7;
  uuid128_t v4;
  pg_uuid_t *ret;

  in = (const u16 *)PG_GETARG_POINTER(0);
  key = key_from_guc_or_error();

  ptr16_to_uuid128(in->data, &v7);
  v4 = uuidv47_encode_v4facade(v7, key);

  ret = (pg_uuid_t *)palloc(sizeof(pg_uuid_t));
  uuid128_to_ptr16(&v4, ret->data);
  PG_RETURN_UUID_P(ret);
}

PG_FUNCTION_INFO_V1(uuid_to_uuid47);
Datum uuid_to_uuid47(PG_FUNCTION_ARGS)
{
  const pg_uuid_t *in;
  int ver;
  uuid128_t uin;
  uuid128_t out;
  u16 *ret;

  in = PG_GETARG_UUID_P(0);
  ver = (in->data[6] >> 4) & 0x0F;
  ptr16_to_uuid128(in->data, &uin);

  if (ver == 7)
  {
    out = uin;
  }
  else if (ver == 4)
  {
    uuidv47_key_t key = key_from_guc_or_error();
    out = uuidv47_decode_v4facade(uin, key);
  }
  else
  {
    ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                    errmsg("uuid_to_uuid47 expects v7 or v4-looking")));
  }

  ret = (u16 *)palloc(sizeof(u16));
  uuid128_to_ptr16(&out, ret->data);
  PG_RETURN_POINTER(ret);
}

PG_FUNCTION_INFO_V1(uuid47_to_uuid_with_key);
Datum uuid47_to_uuid_with_key(PG_FUNCTION_ARGS)
{
  const u16 *in;
  bytea *keyb;
  uuidv47_key_t key;
  uuid128_t v7;
  uuid128_t v4;
  pg_uuid_t *ret;

  in = (const u16 *)PG_GETARG_POINTER(0);
  keyb = PG_GETARG_BYTEA_P(1);
  key = key_from_bytea(keyb);

  ptr16_to_uuid128(in->data, &v7);
  v4 = uuidv47_encode_v4facade(v7, key);

  ret = (pg_uuid_t *)palloc(sizeof(pg_uuid_t));
  uuid128_to_ptr16(&v4, ret->data);
  PG_RETURN_UUID_P(ret);
}

PG_FUNCTION_INFO_V1(uuid_to_uuid47_with_key);
Datum uuid_to_uuid47_with_key(PG_FUNCTION_ARGS)
{
  const pg_uuid_t *in;
  bytea *keyb;
  uuidv47_key_t key;
  int ver;
  uuid128_t uin;
  uuid128_t out;
  u16 *ret;

  in = PG_GETARG_UUID_P(0);
  keyb = PG_GETARG_BYTEA_P(1);
  key = key_from_bytea(keyb);
  ver = (in->data[6] >> 4) & 0x0F;

  ptr16_to_uuid128(in->data, &uin);

  if (ver == 7)
    out = uin;
  else if (ver == 4)
    out = uuidv47_decode_v4facade(uin, key);
  else
    ereport(ERROR, (errcode(ERRCODE_DATA_EXCEPTION),
                    errmsg("uuid_to_uuid47_with_key expects v7 or v4-looking")));

  ret = (u16 *)palloc(sizeof(u16));
  uuid128_to_ptr16(&out, ret->data);
  PG_RETURN_POINTER(ret);
}

/* ----------------------------------------------------------- */
/* Generators (v7)                                              */
/* ----------------------------------------------------------- */

static uint64_t gen_state_last_ms = 0;
static uint32 gen_state_ctr = 0;  /* 32-bit counter */
static uint64_t gen_state_hi = 0; /* 42 random high bits (74 - 32) */

static inline void
fill_rand(void *dst, size_t n)
{
  if (!pg_strong_random(dst, n))
  {
    /* fallback (should be rare) */
    uint8_t *p = (uint8_t *)dst;
    size_t i;
    for (i = 0; i < n; i++)
      p[i] = (uint8_t)(random() & 0xFF);
  }
}

static inline void
uuidv7_build_from_suffix(const uint64_t unix_ms, const uint8_t suffix[10], uuid128_t *out)
{
  /* Bytes 0-5: 48-bit timestamp */
  wr48be(&out->b[0], unix_ms & 0x0000FFFFFFFFFFFFULL);

  /* Byte 6: version (0111) and 4 random bits */
  out->b[6] = (7 << 4) | (suffix[0] & 0x0F);

  /* Byte 7: 8 random bits */
  out->b[7] = suffix[1];

  /* Byte 8: variant (10) and 6 random bits */
  out->b[8] = (0x80) | (suffix[2] & 0x3F);

  /* Bytes 9-15: 56 random bits */
  memcpy(&out->b[9], &suffix[3], 7);
}

PG_FUNCTION_INFO_V1(uuid47_generate);
Datum uuid47_generate(PG_FUNCTION_ARGS)
{
  uint64_t ms;
  uint8_t suffix[10];
  uuid128_t out;
  u16 *ret;

  ms = current_unix_ms();

  /* Fill 74 random bits directly */
  fill_rand(suffix, sizeof(suffix));
  suffix[0] &= 0x0F; /* 4 bits */
  /* suffix[1] full 8 bits */
  suffix[2] &= 0x3F; /* 6 bits */
  /* suffix[3..9] full bytes */

  uuidv7_build_from_suffix(ms, suffix, &out);

  ret = (u16 *)palloc(sizeof(u16));
  uuid128_to_ptr16(&out, ret->data);
  PG_RETURN_POINTER(ret);
}

PG_FUNCTION_INFO_V1(uuid47_generate_monotonic);
Datum uuid47_generate_monotonic(PG_FUNCTION_ARGS)
{
  const int K = 32; /* counter bits */
  uint64_t ms;
  uint8_t suffix[10];
  uuid128_t out;
  u16 *ret;

  ms = current_unix_ms();

  if (ms > gen_state_last_ms)
  {
    uint8_t r[8];
    uint64_t rv;

    gen_state_last_ms = ms;
    gen_state_ctr = 0;

    /* new 42-bit hi */
    fill_rand(r, sizeof(r));
    rv = ((uint64_t)r[0] << 56) | ((uint64_t)r[1] << 48) | ((uint64_t)r[2] << 40) |
         ((uint64_t)r[3] << 32) | ((uint64_t)r[4] << 24) | ((uint64_t)r[5] << 16) |
         ((uint64_t)r[6] << 8) | ((uint64_t)r[7]);
    gen_state_hi = rv & ((1ULL << 42) - 1ULL);
  }
  else if (ms < gen_state_last_ms)
  {
    /* clamp backwards clock */
    ms = gen_state_last_ms;
  }
  else
  {
    gen_state_ctr++;
    if (gen_state_ctr == 0)
    {
      /* overflow (practically impossible); wait next ms */
      do
      {
        pg_usleep(100);
        ms = current_unix_ms();
      } while (ms <= gen_state_last_ms);

      gen_state_last_ms = ms;
      gen_state_ctr = 0;

      {
        uint8_t r[8];
        uint64_t rv;

        fill_rand(r, sizeof(r));
        rv = ((uint64_t)r[0] << 56) | ((uint64_t)r[1] << 48) | ((uint64_t)r[2] << 40) |
             ((uint64_t)r[3] << 32) | ((uint64_t)r[4] << 24) | ((uint64_t)r[5] << 16) |
             ((uint64_t)r[6] << 8) | ((uint64_t)r[7]);
        gen_state_hi = rv & ((1ULL << 42) - 1ULL);
      }
    }
  }

  /* Pack (hi<<K | ctr) into the 74-bit suffix layout */
  {
    /* Build a 74-bit big-endian value using 128-bit math */
    __uint128_t v = (((__uint128_t)gen_state_hi) << K) | (__uint128_t)gen_state_ctr;

    suffix[0] = (uint8_t)((v >> 70) & 0x0F); /* top 4 bits */
    suffix[1] = (uint8_t)((v >> 62) & 0xFF); /* next 8 bits */
    suffix[2] = (uint8_t)((v >> 56) & 0x3F); /* next 6 bits */

    suffix[3] = (uint8_t)((v >> 48) & 0xFF);
    suffix[4] = (uint8_t)((v >> 40) & 0xFF);
    suffix[5] = (uint8_t)((v >> 32) & 0xFF);
    suffix[6] = (uint8_t)((v >> 24) & 0xFF);
    suffix[7] = (uint8_t)((v >> 16) & 0xFF);
    suffix[8] = (uint8_t)((v >> 8) & 0xFF);
    suffix[9] = (uint8_t)((v >> 0) & 0xFF);
  }

  uuidv7_build_from_suffix(ms, suffix, &out);

  ret = (u16 *)palloc(sizeof(u16));
  uuid128_to_ptr16(&out, ret->data);
  PG_RETURN_POINTER(ret);
}

PG_FUNCTION_INFO_V1(uuid47_generate_at);
Datum uuid47_generate_at(PG_FUNCTION_ARGS)
{
  TimestampTz ts;
  uint64_t ms;
  uint8_t suffix[10];
  uuid128_t out;
  u16 *ret;

  ts = PG_GETARG_TIMESTAMPTZ(0);
  ms = timestamptz_to_unix_ms(ts);

  /* random suffix */
  fill_rand(suffix, sizeof(suffix));
  suffix[0] &= 0x0F;
  suffix[2] &= 0x3F;

  uuidv7_build_from_suffix(ms, suffix, &out);

  ret = (u16 *)palloc(sizeof(u16));
  uuid128_to_ptr16(&out, ret->data);
  PG_RETURN_POINTER(ret);
}

/* ----------------------------------------------------------- */
/* Introspection                                                */
/* ----------------------------------------------------------- */

PG_FUNCTION_INFO_V1(uuid47_timestamp);
Datum uuid47_timestamp(PG_FUNCTION_ARGS)
{
  const u16 *in;
  uint64_t ts48;
  TimestampTz ts;

  in = (const u16 *)PG_GETARG_POINTER(0);
  ts48 = rd48be(in->data);
  ts = unix_ms_to_timestamptz(ts48);
  PG_RETURN_TIMESTAMPTZ(ts);
}

PG_FUNCTION_INFO_V1(uuid47_as_v7);
Datum uuid47_as_v7(PG_FUNCTION_ARGS)
{
  const u16 *in;
  pg_uuid_t *ret;

  in = (const u16 *)PG_GETARG_POINTER(0);
  ret = (pg_uuid_t *)palloc(sizeof(pg_uuid_t));
  memcpy(ret->data, in->data, 16);
  PG_RETURN_UUID_P(ret);
}

PG_FUNCTION_INFO_V1(uuid47_explain);
Datum uuid47_explain(PG_FUNCTION_ARGS)
{
  const u16 *in;
  uuidv47_key_t key;
  int32 version;
  uint64_t ts48;
  TimestampTz ts;
  int64 ts_ms;
  uint8_t rand10[10];
  bytea *rand_out;
  uuid128_t v7;
  uuid128_t v4;
  pg_uuid_t facade;
  TupleDesc tupdesc;
  bool tupdesc_is_valid;
  Datum values[5];
  bool nulls[5];
  HeapTuple tup;

  in = (const u16 *)PG_GETARG_POINTER(0);
  key = key_from_guc_or_error();

  version = 7;

  ts48 = rd48be(in->data);
  ts = unix_ms_to_timestamptz(ts48);
  ts_ms = (int64)ts48;

  /* rand10 is exactly the 10-byte message used by SipHash (stable over v7<->facade) */
  ptr16_to_uuid128(in->data, &v7);
  build_sip_input_from_v7(&v7, rand10);
  rand_out = (bytea *)palloc(VARHDRSZ + 10);
  SET_VARSIZE(rand_out, VARHDRSZ + 10);
  memcpy(VARDATA(rand_out), rand10, 10);

  /* facade */
  v4 = uuidv47_encode_v4facade(v7, key);
  uuid128_to_ptr16(&v4, facade.data);

  tupdesc_is_valid = (get_call_result_type(fcinfo, NULL, &tupdesc) == TYPEFUNC_COMPOSITE);
  if (!tupdesc_is_valid)
    ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                    errmsg("uuid47_info type not resolved")));
  BlessTupleDesc(tupdesc);

  nulls[0] = nulls[1] = nulls[2] = nulls[3] = nulls[4] = false;
  values[0] = Int32GetDatum(version);
  values[1] = TimestampTzGetDatum(ts);
  values[2] = Int64GetDatum(ts_ms);
  values[3] = PointerGetDatum(rand_out);
  values[4] = UUIDPGetDatum(&facade);

  tup = heap_form_tuple(tupdesc, values, nulls);
  PG_RETURN_DATUM(HeapTupleGetDatum(tup));
}

/* ----------------------------------------------------------- */
/* Admin                                                        */
/* ----------------------------------------------------------- */

PG_FUNCTION_INFO_V1(uuid47_key_fingerprint);
Datum uuid47_key_fingerprint(PG_FUNCTION_ARGS)
{
  uuidv47_key_t k;
  uint32 hash;
  char buf[32];

  if (!parse_key_from_guc(&k))
    ereport(ERROR,
            (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
             errmsg("uuid47.key GUC is not set or invalid")));

  hash = 2166136261u;
  hash ^= (uint32)(k.k0);
  hash *= 16777619u;
  hash ^= (uint32)(k.k0 >> 32);
  hash *= 16777619u;
  hash ^= (uint32)(k.k1);
  hash *= 16777619u;
  hash ^= (uint32)(k.k1 >> 32);
  hash *= 16777619u;

  snprintf(buf, sizeof(buf), "v1-%08x", hash);
  PG_RETURN_TEXT_P(cstring_to_text(buf));
}

/* ----------------------------------------------------------- */
/* Operators / opclasses                                        */
/* ----------------------------------------------------------- */

static inline int
cmp16(const uint8_t *a, const uint8_t *b)
{
  int r = memcmp(a, b, 16);
  if (r > 0)
    return 1;
  if (r < 0)
    return -1;
  return 0;
}

PG_FUNCTION_INFO_V1(uuid47_cmp);
Datum uuid47_cmp(PG_FUNCTION_ARGS)
{
  const u16 *a;
  const u16 *b;

  a = (const u16 *)PG_GETARG_POINTER(0);
  b = (const u16 *)PG_GETARG_POINTER(1);
  PG_RETURN_INT32(cmp16(a->data, b->data));
}

PG_FUNCTION_INFO_V1(uuid47_eq);
Datum uuid47_eq(PG_FUNCTION_ARGS)
{
  const u16 *a;
  const u16 *b;

  a = (const u16 *)PG_GETARG_POINTER(0);
  b = (const u16 *)PG_GETARG_POINTER(1);
  PG_RETURN_BOOL(memcmp(a->data, b->data, 16) == 0);
}

PG_FUNCTION_INFO_V1(uuid47_ne);
Datum uuid47_ne(PG_FUNCTION_ARGS)
{
  const u16 *a;
  const u16 *b;

  a = (const u16 *)PG_GETARG_POINTER(0);
  b = (const u16 *)PG_GETARG_POINTER(1);
  PG_RETURN_BOOL(memcmp(a->data, b->data, 16) != 0);
}

PG_FUNCTION_INFO_V1(uuid47_lt);
Datum uuid47_lt(PG_FUNCTION_ARGS)
{
  const u16 *a;
  const u16 *b;

  a = (const u16 *)PG_GETARG_POINTER(0);
  b = (const u16 *)PG_GETARG_POINTER(1);
  PG_RETURN_BOOL(cmp16(a->data, b->data) < 0);
}

PG_FUNCTION_INFO_V1(uuid47_le);
Datum uuid47_le(PG_FUNCTION_ARGS)
{
  const u16 *a;
  const u16 *b;

  a = (const u16 *)PG_GETARG_POINTER(0);
  b = (const u16 *)PG_GETARG_POINTER(1);
  PG_RETURN_BOOL(cmp16(a->data, b->data) <= 0);
}

PG_FUNCTION_INFO_V1(uuid47_gt);
Datum uuid47_gt(PG_FUNCTION_ARGS)
{
  const u16 *a;
  const u16 *b;

  a = (const u16 *)PG_GETARG_POINTER(0);
  b = (const u16 *)PG_GETARG_POINTER(1);
  PG_RETURN_BOOL(cmp16(a->data, b->data) > 0);
}

PG_FUNCTION_INFO_V1(uuid47_ge);
Datum uuid47_ge(PG_FUNCTION_ARGS)
{
  const u16 *a;
  const u16 *b;

  a = (const u16 *)PG_GETARG_POINTER(0);
  b = (const u16 *)PG_GETARG_POINTER(1);
  PG_RETURN_BOOL(cmp16(a->data, b->data) >= 0);
}

PG_FUNCTION_INFO_V1(uuid47_hash);
Datum uuid47_hash(PG_FUNCTION_ARGS)
{
  const u16 *a;
  uint32 h;

  a = (const u16 *)PG_GETARG_POINTER(0);
  h = hash_bytes((const unsigned char *)a->data, 16);
  PG_RETURN_INT32((int32)h);
}

/* ---------- BRIN minmax-multi distance (support proc 11) ---------- */
/* Convert uuid47 (big-endian bytewise order) into a u128 and
 * return |a - b| as a float8.  Good enough for BRIN range heuristics.
 */

static inline uint64_t rd64be_local(const uint8_t *p)
{
  return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
         ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
         ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
         ((uint64_t)p[6] << 8) | ((uint64_t)p[7] << 0);
}

PG_FUNCTION_INFO_V1(uuid47_brin_distance);
Datum uuid47_brin_distance(PG_FUNCTION_ARGS)
{
  const u16 *a = (const u16 *)PG_GETARG_POINTER(0);
  const u16 *b = (const u16 *)PG_GETARG_POINTER(1);

  uint64_t ahi = rd64be_local(&a->data[0]);
  uint64_t alo = rd64be_local(&a->data[8]);
  uint64_t bhi = rd64be_local(&b->data[0]);
  uint64_t blo = rd64be_local(&b->data[8]);

  __uint128_t A = (((__uint128_t)ahi) << 64) | (__uint128_t)alo;
  __uint128_t B = (((__uint128_t)bhi) << 64) | (__uint128_t)blo;
  __uint128_t D = (A >= B) ? (A - B) : (B - A);

  /* Convert 128-bit magnitude to float8: hi*2^64 + lo */
  double d = (double)((uint64_t)(D >> 64)) * 18446744073709551616.0 /* 2^64 */
             + (double)((uint64_t)D);

  PG_RETURN_FLOAT8(d);
}