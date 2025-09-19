# Makefile for uuidv47 (header-only) + demo + bench + tests + PostgreSQL ext

CC              ?= cc
TARGET          ?= uuidv47_demo
SRC             ?= demo.c
TEST_SRC        ?= tests.c
HDR             ?= uuidv47.h

PREFIX          ?= /usr/local
INCLUDEDIR      ?= $(PREFIX)/include

CFLAGS_COMMON   := -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
                   -Wdouble-promotion -Wstrict-prototypes \
                   -Werror=implicit-function-declaration \
                   -fno-strict-aliasing
CFLAGS_RELEASE  := -O3 -DNDEBUG -fvisibility=hidden
CFLAGS_TEST     := -O2 -g -fno-omit-frame-pointer
CFLAGS_DEBUG    := -O0 -g3 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS_DEBUG   := -fsanitize=address,undefined

CFLAGS_COV      := -O0 -g --coverage -fprofile-arcs -ftest-coverage
LDFLAGS_COV     := --coverage

.PHONY: all release debug run test bench coverage clean install uninstall format \
        pgext pginstall pgclean pgtest

# ----------------------------------------
# C library / demo / tests
# ----------------------------------------

all: release

release: $(TARGET)
$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_RELEASE) $(SRC) -o $@

debug: $(SRC) $(HDR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_DEBUG) $(LDFLAGS_DEBUG) $(SRC) -o $(TARGET)-dbg

run: $(TARGET)
	./$(TARGET)

test: $(TEST_SRC) $(HDR)
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_TEST) $(TEST_SRC) -o tests
	./tests

bench: bench.c uuidv47.h
	$(CC) -O3 -march=native -std=c11 -Wall -Wextra bench.c -o bench

coverage: clean
	$(CC) $(CFLAGS_COMMON) $(CFLAGS_COV) $(TEST_SRC) -o tests_cov $(LDFLAGS_COV)
	./tests_cov
	@echo
	@echo "== gcov summary (from tests.c; headers are attributed here) =="
	@{ command -v gcov >/dev/null 2>&1 && gcov -b -c tests_cov-$(TEST_SRC) | sed -n '1,80p'; } || \
	  echo "gcov not found or no data; skipping gcov summary."
	@if command -v lcov >/dev/null 2>&1 && command -v genhtml >/dev/null; then \
	  echo; echo "== generating lcov report in coverage/ =="; \
	  rm -rf coverage && mkdir -p coverage; \
	  lcov --capture --directory . --output-file coverage/coverage.info >/dev/null 2>&1; \
	  genhtml coverage/coverage.info --output-directory coverage >/dev/null 2>&1; \
	  echo "Open coverage/index.html"; \
	fi

install: $(HDR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 0644 $(HDR) $(DESTDIR)$(INCLUDEDIR)/$(HDR)

uninstall:
	rm -f $(DESTDIR)$(INCLUDEDIR)/$(HDR)

format:
	@command -v clang-format >/dev/null 2>&1 && clang-format -i $(HDR) $(SRC) $(TEST_SRC) || true

clean:
	rm -f $(TARGET) $(TARGET)-dbg tests bench tests_cov *.gcno *.gcda *.gcov
	rm -rf coverage

# ----------------------------------------
# PostgreSQL extension helpers
# ----------------------------------------

PGEXTDIR   ?= pgext/uuid47
PG_CONFIG  ?= pg_config
PSQL       ?= psql
TEST_SQL   ?= $(PGEXTDIR)/test_uuid47.sql
DBNAME     ?= postgres

pgext:
	$(MAKE) -C $(PGEXTDIR) PG_CONFIG=$(PG_CONFIG)

pginstall: pgext
	$(MAKE) -C $(PGEXTDIR) PG_CONFIG=$(PG_CONFIG) install

pgclean:
	$(MAKE) -C $(PGEXTDIR) PG_CONFIG=$(PG_CONFIG) clean

pgtest: pginstall
	$(PSQL) -v ON_ERROR_STOP=1 -d $(DBNAME) -f $(TEST_SQL)
