EXTENSION  = uuid47
MODULE_big = uuid47
OBJS       = src/uuid47_pg.o

DATA       = sql/uuid47--1.0.sql
PGFILEDESC = "uuid47 - base type + v7<->v4 facade transforms (SipHash-masked ts)"

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

PG_CPPFLAGS += -I$(CURDIR)/../../

# Warnings & opts
CFLAGS += -std=c11 -O3 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -fno-strict-aliasing
