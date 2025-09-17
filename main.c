// Copyright (c) 2025 Stateless Limited
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include "uuidv47.h"

int main(void)
{
  // Example: parse a v7 from DB, emit façade, then decode back.
  uuid128_t id_v7, facade, back;
  uuidv47_key_t key = {.k0 = 0x0123456789abcdefULL, .k1 = 0xfedcba9876543210ULL};

  // Example v7 string (any valid v7 will do):
  const char *s = "018f2d9f-9a2a-7def-8c3f-7b1a2c4d5e6f";
  if (!uuid_parse(s, &id_v7))
    return 1;

  facade = uuidv47_encode_v4facade(id_v7, key);
  back = uuidv47_decode_v4facade(facade, key);

  char a[37], b[37], c[37];
  uuid_format(&id_v7, a);
  uuid_format(&facade, b);
  uuid_format(&back, c);

  printf("v7 in : %s\n", a);
  printf("v4 out: %s\n", b);
  printf("back  : %s\n", c);
  return 0;
}
