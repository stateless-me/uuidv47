-- ---------- Composite used by uuid47_explain ----------
CREATE TYPE uuid47_info AS (
  version int4,
  ts timestamptz,
  ts_ms int8,
  rand bytea,
  facade uuid
);

-- ---------- Define shell type first ----------
CREATE TYPE uuid47;

-- ---------- I/O functions for the type ----------
CREATE FUNCTION uuid47_in(cstring)
RETURNS uuid47
AS '$libdir/uuid47', 'uuid47_in'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_out(uuid47)
RETURNS cstring
AS '$libdir/uuid47', 'uuid47_out'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_recv(internal)
RETURNS uuid47
AS '$libdir/uuid47', 'uuid47_recv'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_send(uuid47)
RETURNS bytea
AS '$libdir/uuid47', 'uuid47_send'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- ---------- Finalize the base type ----------
CREATE TYPE uuid47 (
  INPUT = uuid47_in,
  OUTPUT = uuid47_out,
  RECEIVE = uuid47_recv,
  SEND = uuid47_send,
  INTERNALLENGTH = 16,
  PASSEDBYVALUE = false,
  ALIGNMENT = int4,
  STORAGE = plain
);

-- =========================
-- Directional transforms (GUC-backed STABLE)
-- =========================
CREATE FUNCTION uuid47_to_uuid(u47 uuid47)
RETURNS uuid
AS '$libdir/uuid47', 'uuid47_to_uuid'
LANGUAGE C STRICT STABLE PARALLEL SAFE;

CREATE FUNCTION uuid_to_uuid47(u uuid)
RETURNS uuid47
AS '$libdir/uuid47', 'uuid_to_uuid47'
LANGUAGE C STRICT STABLE PARALLEL SAFE;

-- Immutable explicit-key variants (key = 16 bytes k0||k1 LE)
CREATE FUNCTION uuid47_to_uuid_with_key(u47 uuid47, key bytea)
RETURNS uuid
AS '$libdir/uuid47', 'uuid47_to_uuid_with_key'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid_to_uuid47_with_key(u uuid, key bytea)
RETURNS uuid47
AS '$libdir/uuid47', 'uuid_to_uuid47_with_key'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- =========================
-- Generators
-- =========================
CREATE FUNCTION uuid47_generate()
RETURNS uuid47
AS '$libdir/uuid47', 'uuid47_generate'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE FUNCTION uuid47_generate_monotonic()
RETURNS uuid47
AS '$libdir/uuid47', 'uuid47_generate_monotonic'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE FUNCTION uuid47_generate_at(ts timestamptz)
RETURNS uuid47
AS '$libdir/uuid47', 'uuid47_generate_at'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- =========================
-- Introspection / utilities
-- =========================
CREATE FUNCTION uuid47_timestamp(u47 uuid47)
RETURNS timestamptz
AS '$libdir/uuid47', 'uuid47_timestamp'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_explain(u47 uuid47)
RETURNS uuid47_info
AS '$libdir/uuid47', 'uuid47_explain'
LANGUAGE C STRICT STABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_as_v7(u47 uuid47)
RETURNS uuid
AS '$libdir/uuid47', 'uuid47_as_v7'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- =========================
-- Admin
-- =========================
CREATE FUNCTION uuid47_key_fingerprint()
RETURNS text
AS '$libdir/uuid47', 'uuid47_key_fingerprint'
LANGUAGE C STRICT STABLE PARALLEL SAFE;

-- =========================
-- Assignment casts
-- =========================
CREATE CAST (uuid AS uuid47)
  WITH FUNCTION uuid_to_uuid47(uuid)
  AS ASSIGNMENT;

CREATE CAST (uuid47 AS uuid)
  WITH FUNCTION uuid47_to_uuid(uuid47)
  AS ASSIGNMENT;

-- =========================
-- Operators / support funcs
-- =========================
CREATE FUNCTION uuid47_cmp(a uuid47, b uuid47)
RETURNS int4
AS '$libdir/uuid47', 'uuid47_cmp'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_eq(a uuid47, b uuid47)
RETURNS bool
AS '$libdir/uuid47', 'uuid47_eq'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_ne(a uuid47, b uuid47)
RETURNS bool
AS '$libdir/uuid47', 'uuid47_ne'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_lt(a uuid47, b uuid47)
RETURNS bool
AS '$libdir/uuid47', 'uuid47_lt'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_le(a uuid47, b uuid47)
RETURNS bool
AS '$libdir/uuid47', 'uuid47_le'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_gt(a uuid47, b uuid47)
RETURNS bool
AS '$libdir/uuid47', 'uuid47_gt'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_ge(a uuid47, b uuid47)
RETURNS bool
AS '$libdir/uuid47', 'uuid47_ge'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION uuid47_hash(a uuid47)
RETURNS int4
AS '$libdir/uuid47', 'uuid47_hash'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- Operators
CREATE OPERATOR =  (LEFTARG = uuid47, RIGHTARG = uuid47, PROCEDURE = uuid47_eq, COMMUTATOR = =, NEGATOR = <>, RESTRICT = eqsel, JOIN = eqjoinsel);
CREATE OPERATOR <> (LEFTARG = uuid47, RIGHTARG = uuid47, PROCEDURE = uuid47_ne, COMMUTATOR = <>, NEGATOR = =, RESTRICT = neqsel, JOIN = neqjoinsel);
CREATE OPERATOR <  (LEFTARG = uuid47, RIGHTARG = uuid47, PROCEDURE = uuid47_lt, RESTRICT = scalarltsel, JOIN = scalarltjoinsel);
CREATE OPERATOR <= (LEFTARG = uuid47, RIGHTARG = uuid47, PROCEDURE = uuid47_le, RESTRICT = scalarltsel, JOIN = scalarltjoinsel);
CREATE OPERATOR >  (LEFTARG = uuid47, RIGHTARG = uuid47, PROCEDURE = uuid47_gt, RESTRICT = scalargtsel, JOIN = scalargtjoinsel);
CREATE OPERATOR >= (LEFTARG = uuid47, RIGHTARG = uuid47, PROCEDURE = uuid47_ge, RESTRICT = scalargtsel, JOIN = scalargtjoinsel);

-- btree opclass
CREATE OPERATOR CLASS uuid47_ops
DEFAULT FOR TYPE uuid47 USING btree AS
  OPERATOR 1 <(uuid47, uuid47),
  OPERATOR 2 <=(uuid47, uuid47),
  OPERATOR 3 =(uuid47, uuid47),
  OPERATOR 4 >=(uuid47, uuid47),
  OPERATOR 5 >(uuid47, uuid47),
  FUNCTION 1 uuid47_cmp(uuid47, uuid47);

-- hash opclass
CREATE OPERATOR CLASS uuid47_hash_ops
DEFAULT FOR TYPE uuid47 USING hash AS
  OPERATOR 1 =(uuid47, uuid47),
  FUNCTION 1 uuid47_hash(uuid47);

-- Distance function (support proc 11)
CREATE FUNCTION uuid47_brin_distance(uuid47, uuid47)
RETURNS float8
AS '$libdir/uuid47', 'uuid47_brin_distance'
LANGUAGE C STRICT IMMUTABLE PARALLEL SAFE;

-- BRIN minmax-multi operator class (NOT default)
CREATE OPERATOR CLASS uuid47_brin_minmax_multi_ops
FOR TYPE uuid47 USING brin AS
  -- strategy operators
  OPERATOR 1 <  (uuid47, uuid47),
  OPERATOR 2 <= (uuid47, uuid47),
  OPERATOR 3 =  (uuid47, uuid47),
  OPERATOR 4 >= (uuid47, uuid47),
  OPERATOR 5 >  (uuid47, uuid47),

  -- built-in minmax-multi support functions
  FUNCTION 1  pg_catalog.brin_minmax_multi_opcinfo    (internal),
  FUNCTION 2  pg_catalog.brin_minmax_multi_add_value  (internal, internal, internal, internal),
  FUNCTION 3  pg_catalog.brin_minmax_multi_consistent (internal, internal, internal, integer),
  FUNCTION 4  pg_catalog.brin_minmax_multi_union      (internal, internal, internal),
  FUNCTION 5  pg_catalog.brin_minmax_multi_options    (internal),

  -- our distance function (support proc 11)
  FUNCTION 11 uuid47_brin_distance(uuid47, uuid47);