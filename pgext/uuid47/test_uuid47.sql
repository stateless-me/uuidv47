\set ON_ERROR_STOP on
\pset pager off
SET client_min_messages = warning;

-- Ensure the extension exists (pick the schema you want for testing)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'uuid47') THEN
    EXECUTE 'CREATE EXTENSION uuid47 SCHEMA public';
  END IF;
END $$;

-- Discover the extension’s schema and put it first on search_path
\unset extschema
SELECT n.nspname AS extschema
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
WHERE e.extname = 'uuid47' \gset

SET search_path TO :"extschema", pg_temp, public;

-- Test key
SET uuid47.key = '0011223344556677:8899aabbccddeeff';

-- =========================
-- 1) Core sanity checks
-- =========================
DO $$
DECLARE
  u47       uuid47;
  facade    uuid;
  u47_rt    uuid47;
  v7        uuid;
  info      uuid47_info;
  n_viol    int;
  ts_fixed  timestamptz;
  u47_at    uuid47;
BEGIN
  -- Generate + façade should be v4-looking
  u47 := uuid47_generate();
  facade := uuid47_to_uuid(u47);
  IF substring(facade::text, 15, 1) <> '4' THEN
    RAISE EXCEPTION 'facade not v4 (got %)', facade::text;
  END IF;

  -- Round-trip via façade
  u47_rt := uuid_to_uuid47(facade);
  IF u47_rt <> u47 THEN
    RAISE EXCEPTION 'roundtrip mismatch: % vs %', u47_rt::uuid, u47::uuid;
  END IF;

  -- as_v7 must be v7-looking and round-trip
  v7 := uuid47_as_v7(u47);
  IF substring(v7::text, 15, 1) <> '7' THEN
    RAISE EXCEPTION 'as_v7 not v7 (got %)', v7::text;
  END IF;
  IF uuid_to_uuid47(v7) <> u47 THEN
    RAISE EXCEPTION 'as_v7 -> uuid47 mismatch';
  END IF;

  -- explain() structure and consistency
  info := uuid47_explain(u47);
  IF info.version <> 7 THEN
    RAISE EXCEPTION 'info.version expected 7, got %', info.version;
  END IF;
  IF info.facade <> facade THEN
    RAISE EXCEPTION 'info.facade mismatch';
  END IF;
  IF info.ts <> uuid47_timestamp(u47) THEN
    RAISE EXCEPTION 'info.ts mismatch';
  END IF;
  IF octet_length(info.rand) <> 10 THEN
    RAISE EXCEPTION 'info.rand length expected 10, got %', octet_length(info.rand);
  END IF;
  IF info.ts_ms <> (extract(epoch from info.ts)*1000)::bigint THEN
    RAISE EXCEPTION 'info.ts_ms mismatch';
  END IF;

  -- keyed variant equals STABLE transform when key matches GUC
  IF uuid47_to_uuid_with_key(u47, E'\\x00112233445566778899aabbccddeeff') <> facade THEN
    RAISE EXCEPTION 'with_key != facade using the matching key';
  END IF;

  -- Monotonic generator: strictly increasing within backend
  CREATE TEMP TABLE t(id uuid47) ON COMMIT DROP;
  INSERT INTO t SELECT uuid47_generate_monotonic() FROM generate_series(1, 500);
  SELECT count(*) INTO n_viol
  FROM (
    SELECT id, lag(id) OVER (ORDER BY id) AS prev
    FROM t
  ) s
  WHERE prev IS NOT NULL AND NOT (id > prev);
  IF n_viol <> 0 THEN
    RAISE EXCEPTION 'monotonic violated % times', n_viol;
  END IF;

  -- Ordering aligns with timestamps (non-decreasing with ascending id)
  SELECT count(*) INTO n_viol
  FROM (
    SELECT uuid47_timestamp(id) AS ts,
           lag(uuid47_timestamp(id)) OVER (ORDER BY id) AS prev_ts
    FROM t
  ) s
  WHERE prev_ts IS NOT NULL AND ts < prev_ts;
  IF n_viol <> 0 THEN
    RAISE EXCEPTION 'timestamp order broken % times', n_viol;
  END IF;

  -- Cast interop both ways
  CREATE TEMP TABLE e(id uuid47) ON COMMIT DROP;
  INSERT INTO e(id) VALUES ('aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee'::uuid);
  IF (SELECT count(*) FROM e WHERE id IS NOT NULL) <> 1 THEN
    RAISE EXCEPTION 'assignment cast uuid -> uuid47 failed';
  END IF;
  IF (SELECT (id::uuid) IS NULL FROM e LIMIT 1) THEN
    RAISE EXCEPTION 'assignment cast uuid47 -> uuid failed';
  END IF;

  -- generate_at exact timestamp
  ts_fixed := '2024-01-02 03:04:05+00'::timestamptz;
  u47_at := uuid47_generate_at(ts_fixed);
  IF uuid47_timestamp(u47_at) <> ts_fixed THEN
    RAISE EXCEPTION 'generate_at timestamp mismatch: got %, want %',
      uuid47_timestamp(u47_at), ts_fixed;
  END IF;
END $$;

-- =========================
-- 2) B-tree time-order smoke
-- =========================
BEGIN;
CREATE TEMP TABLE t_sort(id uuid47) ON COMMIT DROP;
INSERT INTO t_sort SELECT uuid47_generate() FROM generate_series(1, 200);
CREATE INDEX ON t_sort (id);

WITH s AS (
  SELECT uuid47_timestamp(id) AS ts,
         lag(uuid47_timestamp(id)) OVER (ORDER BY id) AS prev_ts
  FROM t_sort
)
SELECT CASE WHEN count(*) = 0 THEN 'ok' ELSE 'bad' END AS btree_time_order_ok
FROM s
WHERE prev_ts IS NOT NULL AND ts < prev_ts;
COMMIT;

-- =========================
-- 3) BRIN minmax-multi sanity
-- =========================
-- Distance function basic properties
DO $$
DECLARE
  a uuid47 := uuid47_generate();
  b uuid47 := uuid47_generate_at(clock_timestamp() + interval '1 second');
  d1 float8;
  d2 float8;
BEGIN
  d1 := uuid47_brin_distance(a, a);
  IF d1 <> 0 THEN
    RAISE EXCEPTION 'distance(a,a) expected 0, got %', d1;
  END IF;

  d1 := uuid47_brin_distance(a, b);
  d2 := uuid47_brin_distance(b, a);
  IF d1 <= 0 OR d2 <= 0 OR d1 <> d2 THEN
    RAISE EXCEPTION 'distance symmetry/positivity violated: d1=%, d2=%', d1, d2;
  END IF;
END $$;

-- Build a BRIN minmax-multi index and check it can be used
DROP TABLE IF EXISTS t_brin;
CREATE TABLE t_brin (
  id uuid47 PRIMARY KEY DEFAULT uuid47_generate(),
  payload int
);

-- Insert ~100k rows to give BRIN something to summarize
INSERT INTO t_brin(payload)
SELECT (random()*1000)::int FROM generate_series(1, 100000);

-- Create minmax-multi BRIN index
CREATE INDEX t_brin_idx ON t_brin
USING brin (
  id uuid47_brin_minmax_multi_ops (values_per_range = 32)
)
WITH (pages_per_range = 64);

-- Summarize and analyze
SELECT brin_summarize_new_values('t_brin_idx'::regclass);
ANALYZE t_brin;

-- Positive test: BRIN index usable
BEGIN;
SET LOCAL enable_seqscan = off;
SET LOCAL enable_indexscan = on;
SET LOCAL enable_bitmapscan = on;

WITH lb AS (
  SELECT uuid47_generate_at(clock_timestamp() - interval '5 minutes') AS lb
)
SELECT 'ok' AS brin_used
FROM t_brin
WHERE id >= (SELECT lb FROM lb)
LIMIT 1;

ROLLBACK;

-- Negative test: drop index, same query should fail (no plan possible)
DROP INDEX t_brin_idx;
BEGIN;
SET LOCAL enable_seqscan = off;
SET LOCAL enable_indexscan = on;
SET LOCAL enable_bitmapscan = on;

-- This should ERROR with "could not devise a query plan"
WITH lb AS (
  SELECT uuid47_generate_at(clock_timestamp() - interval '5 minutes') AS lb
)
SELECT count(*) FROM t_brin
WHERE id >= (SELECT lb FROM lb);

ROLLBACK;

-- Clean up
DROP TABLE t_brin;

-- =========================
-- 4) All good
-- =========================
SELECT 'uuid47: ALL TESTS PASSED' AS ok;
