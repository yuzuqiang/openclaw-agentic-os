CREATE TABLE artifact_projections_v2 (
  projection_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source_authority TEXT NOT NULL,
  generated_from_transition_id TEXT REFERENCES transitions(transition_id),
  generated_at TEXT NOT NULL,
  UNIQUE(run_id, path, source_authority)
) STRICT;

INSERT INTO artifact_projections_v2(
  projection_id,
  run_id,
  path,
  sha256,
  source_authority,
  generated_from_transition_id,
  generated_at
)
SELECT
  projection_id,
  run_id,
  path,
  sha256,
  source_authority,
  generated_from_transition_id,
  generated_at
FROM artifact_projections;

DROP TABLE artifact_projections;

ALTER TABLE artifact_projections_v2 RENAME TO artifact_projections;
