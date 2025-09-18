// Copyright (c) 2025 Stateless Limited
// SPDX-License-Identifier: MIT

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include "uuidv47.h"

#ifndef BENCH_DEFAULT_ITERS
#define BENCH_DEFAULT_ITERS 2000000u
#endif

static inline uint64_t ns_now(void)
{
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#else
  // Fallback, less precise
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

// simple xorshift64* PRNG
static inline uint64_t xorshift64star(uint64_t *s)
{
  uint64_t x = *s;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *s = x;
  return x * 2685821657736338717ULL;
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

static void build_sipmsg_from_v7(const uuid128_t *u, uint8_t msg[10])
{
  msg[0] = (uint8_t)(u->b[6] & 0x0F);
  msg[1] = u->b[7];
  msg[2] = (uint8_t)(u->b[8] & 0x3F);
  memcpy(&msg[3], &u->b[9], 7);
}

typedef struct
{
  uint32_t iters;
  int warmup_rounds;
  int measured_rounds;
  bool quiet;
} cfg_t;

static void parse_args(int argc, char **argv, cfg_t *c)
{
  c->iters = BENCH_DEFAULT_ITERS;
  c->warmup_rounds = 1;
  c->measured_rounds = 3;
  c->quiet = false;
  for (int i = 1; i < argc; i++)
  {
    if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
    {
      c->iters = (uint32_t)strtoul(argv[++i], NULL, 10);
    }
    else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc)
    {
      c->warmup_rounds = atoi(argv[++i]);
    }
    else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
    {
      c->measured_rounds = atoi(argv[++i]);
    }
    else if (strcmp(argv[i], "-q") == 0)
    {
      c->quiet = true;
    }
    else if (strcmp(argv[i], "-h") == 0)
    {
      fprintf(stderr, "Usage: %s [-n iters] [-w warmup] [-r rounds] [-q]\n", argv[0]);
      exit(0);
    }
  }
}

static double bench_encode_decode(const cfg_t *c, uuidv47_key_t key, uint64_t *out_guard)
{
  uint64_t best_ns_per_op = UINT64_MAX;
  uint64_t guard = 0;

  for (int round = -(c->warmup_rounds); round < c->measured_rounds; round++)
  {
    uint64_t seed = (uint64_t)ns_now() ^ 0x9e3779b97f4a7c15ULL ^ (uint64_t)round;
    uint64_t start = ns_now();

    for (uint32_t i = 0; i < c->iters; i++)
    {
      uuid128_t u7, facade, back;
      // Spread timestamps and randoms a bit
      uint64_t ts = (xorshift64star(&seed) & 0x0000FFFFFFFFFFFFULL);
      uint16_t ra = (uint16_t)(xorshift64star(&seed) & 0x0FFFu);
      uint64_t rb = (xorshift64star(&seed) & ((1ULL << 62) - 1ULL));
      craft_v7(&u7, ts, ra, rb);

      facade = uuidv47_encode_v4facade(u7, key);
      back = uuidv47_decode_v4facade(facade, key);

      // correctness guard to avoid dead-code elimination
      guard ^= ((uint64_t)facade.b[0] << 0) ^
               ((uint64_t)facade.b[5] << 8) ^
               ((uint64_t)back.b[10] << 16);
      if ((i & 0x3FFu) == 0u)
      { // periodic exact check
        if (memcmp(&u7, &back, sizeof(u7)) != 0)
        {
          fprintf(stderr, "Round-trip mismatch at i=%u\n", i);
          exit(2);
        }
      }
    }
    uint64_t end = ns_now();
    uint64_t ns = end - start;
    double ns_per_op = (double)ns / (double)c->iters;

    if (round >= 0)
    {
      if (!c->quiet)
      {
        printf("[encode+decode] round %d: %.2f ns/op, %.1f Mops/s\n",
               round + 1, ns_per_op, 1000.0 / ns_per_op);
      }
      if ((uint64_t)ns_per_op < best_ns_per_op)
        best_ns_per_op = (uint64_t)ns_per_op;
    }
    else if (!c->quiet)
    {
      printf("[warmup] %.2f ns/op\n", ns_per_op);
    }
  }
  *out_guard ^= guard;
  return (double)best_ns_per_op;
}

static double bench_siphash_only(const cfg_t *c, uuidv47_key_t key, uint64_t *out_guard)
{
  uint64_t best_ns_per_op = UINT64_MAX;
  uint64_t guard = 0;

  for (int round = -(c->warmup_rounds); round < c->measured_rounds; round++)
  {
    uint64_t seed = (uint64_t)ns_now() ^ 0x7f4a7c159e3779b9ULL ^ (uint64_t)(round * 3 + 1);
    uint8_t msg[10];

    uint64_t start = ns_now();
    for (uint32_t i = 0; i < c->iters; i++)
    {
      // Synthesize the exact 10-byte message shape
      uuid128_t u7;
      uint64_t ts = (xorshift64star(&seed) & 0x0000FFFFFFFFFFFFULL);
      uint16_t ra = (uint16_t)(xorshift64star(&seed) & 0x0FFFu);
      uint64_t rb = (xorshift64star(&seed) & ((1ULL << 62) - 1ULL));
      craft_v7(&u7, ts, ra, rb);

      build_sipmsg_from_v7(&u7, msg);
      uint64_t out = siphash24(msg, sizeof msg, key.k0, key.k1);
      guard ^= out;
    }
    uint64_t end = ns_now();
    uint64_t ns = end - start;
    double ns_per_op = (double)ns / (double)c->iters;

    if (round >= 0)
    {
      if (!c->quiet)
      {
        printf("[siphash(10B)] round %d: %.2f ns/op, %.1f Mops/s\n",
               round + 1, ns_per_op, 1000.0 / ns_per_op);
      }
      if ((uint64_t)ns_per_op < best_ns_per_op)
        best_ns_per_op = (uint64_t)ns_per_op;
    }
    else if (!c->quiet)
    {
      printf("[warmup] %.2f ns/op\n", ns_per_op);
    }
  }
  *out_guard ^= guard;
  return (double)best_ns_per_op;
}

int main(int argc, char **argv)
{
  cfg_t cfg;
  parse_args(argc, argv, &cfg);

  // Fixed demo key (replace in prod)
  uuidv47_key_t key = {.k0 = 0x0123456789abcdefULL, .k1 = 0xfedcba9876543210ULL};

  if (!cfg.quiet)
  {
    printf("iters=%u, warmup=%d, rounds=%d\n", cfg.iters, cfg.warmup_rounds, cfg.measured_rounds);
  }

  uint64_t guard = 0;
  double ns_encode_decode = bench_encode_decode(&cfg, key, &guard);
  double ns_siphash = bench_siphash_only(&cfg, key, &guard);

  // prevent optimizing away
  volatile uint64_t sink = guard;
  (void)sink;

  printf("== best results ==\n");
  printf("encode+decode : %.2f ns/op (%.1f Mops/s)\n", ns_encode_decode, 1000.0 / ns_encode_decode);
  printf("siphash(10B)  : %.2f ns/op (%.1f Mops/s)\n", ns_siphash, 1000.0 / ns_siphash);
  return 0;
}
