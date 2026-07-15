CREATE TABLE legacy_money_import_batches (
  batch_id TEXT PRIMARY KEY,
  source_schema_version TEXT NOT NULL,
  source_table TEXT NOT NULL,
  source_unit TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('quarantined','promoted')),
  row_count ANY NOT NULL,
  quarantine_count ANY NOT NULL,
  promoted_count ANY NOT NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  failure_reason TEXT,
  CHECK (batch_id<>'' AND source_schema_version<>'' AND source_table<>''),
  CHECK (source_unit='usd_decimal'),
  CHECK (length(payload_hash)=64),
  CHECK (typeof(row_count)='integer' AND row_count>=0),
  CHECK (typeof(quarantine_count)='integer' AND quarantine_count>=0),
  CHECK (typeof(promoted_count)='integer' AND promoted_count>=0),
  CHECK (
    (status='quarantined' AND quarantine_count>0 AND promoted_count=0)
    OR (status='promoted' AND quarantine_count=0 AND promoted_count=row_count)
  )
) STRICT;

CREATE TABLE legacy_money_import_quarantine (
  quarantine_id TEXT PRIMARY KEY,
  batch_id TEXT NOT NULL REFERENCES legacy_money_import_batches(batch_id),
  legacy_row_id TEXT NOT NULL,
  source_column TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_unit TEXT,
  source_value_text TEXT,
  reason_code TEXT NOT NULL,
  reason_detail TEXT NOT NULL,
  row_payload_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (quarantine_id<>'' AND batch_id<>'' AND legacy_row_id<>''),
  CHECK (source_column<>'' AND source_type<>'' AND reason_code<>''),
  CHECK (reason_detail<>'' AND length(row_payload_hash)=64),
  UNIQUE(batch_id,legacy_row_id,source_column,reason_code)
) STRICT;

CREATE TABLE legacy_money_import_promotions (
  batch_id TEXT NOT NULL REFERENCES legacy_money_import_batches(batch_id),
  legacy_row_id TEXT NOT NULL,
  row_payload_hash TEXT NOT NULL,
  settlement_id TEXT NOT NULL REFERENCES budget_settlements(settlement_id),
  promoted_at TEXT NOT NULL,
  PRIMARY KEY(batch_id,legacy_row_id),
  CHECK (batch_id<>'' AND legacy_row_id<>'' AND length(row_payload_hash)=64),
  CHECK (settlement_id<>'' AND promoted_at<>'')
) STRICT;

CREATE TRIGGER legacy_money_import_batches_preserve_update
BEFORE UPDATE ON legacy_money_import_batches
BEGIN
  SELECT RAISE(ABORT,'legacy money import evidence is immutable');
END;

CREATE TRIGGER legacy_money_import_batches_preserve_delete
BEFORE DELETE ON legacy_money_import_batches
BEGIN
  SELECT RAISE(ABORT,'legacy money import evidence is immutable');
END;

CREATE TRIGGER legacy_money_import_quarantine_preserve_update
BEFORE UPDATE ON legacy_money_import_quarantine
BEGIN
  SELECT RAISE(ABORT,'legacy money import quarantine evidence is immutable');
END;

CREATE TRIGGER legacy_money_import_quarantine_preserve_delete
BEFORE DELETE ON legacy_money_import_quarantine
BEGIN
  SELECT RAISE(ABORT,'legacy money import quarantine evidence is immutable');
END;

CREATE TRIGGER legacy_money_import_promotions_preserve_update
BEFORE UPDATE ON legacy_money_import_promotions
BEGIN
  SELECT RAISE(ABORT,'legacy money import promotion evidence is immutable');
END;

CREATE TRIGGER legacy_money_import_promotions_preserve_delete
BEFORE DELETE ON legacy_money_import_promotions
BEGIN
  SELECT RAISE(ABORT,'legacy money import promotion evidence is immutable');
END;
