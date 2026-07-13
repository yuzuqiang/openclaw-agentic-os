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

CREATE TABLE artifact_projection_history (
  projection_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source_authority TEXT NOT NULL,
  generated_from_transition_id TEXT REFERENCES transitions(transition_id),
  generated_at TEXT NOT NULL,
  retained_projection_id TEXT NOT NULL,
  archived_at TEXT NOT NULL,
  archive_reason TEXT NOT NULL
) STRICT;

CREATE TEMP TABLE artifact_projection_timestamp_guard (
  run_id TEXT NOT NULL,
  path TEXT NOT NULL,
  source_authority TEXT NOT NULL,
  generated_at TEXT NOT NULL CHECK (
    julianday(generated_at) IS NOT NULL
    AND strftime('%Y-%m-%dT%H:%M:%S', generated_at)=substr(generated_at,1,19)
    AND substr(generated_at,12,2) BETWEEN '00' AND '23'
    AND substr(generated_at,15,2) BETWEEN '00' AND '59'
    AND substr(generated_at,18,2) BETWEEN '00' AND '59'
    AND (
      (
        length(generated_at)=25
        AND generated_at GLOB
          '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]+00:00'
      )
      OR (
        length(generated_at)=32
        AND generated_at GLOB
          '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]+00:00'
        AND substr(generated_at,21,6)<>'000000'
      )
    )
  ),
  UNIQUE(run_id,path,source_authority,generated_at)
) STRICT;

INSERT INTO artifact_projection_timestamp_guard(
  run_id,
  path,
  source_authority,
  generated_at
)
SELECT
  run_id,
  path,
  source_authority,
  generated_at
FROM artifact_projections
WHERE (run_id, path, source_authority) IN (
  SELECT run_id, path, source_authority
  FROM artifact_projections
  GROUP BY run_id, path, source_authority
  HAVING COUNT(*) > 1
);

DROP TABLE artifact_projection_timestamp_guard;

WITH ranked AS (
  SELECT
    projection_id,
    run_id,
    path,
    sha256,
    source_authority,
    generated_from_transition_id,
    generated_at,
    ROW_NUMBER() OVER (
      PARTITION BY run_id, path, source_authority
      ORDER BY julianday(generated_at) DESC, generated_at DESC, projection_id DESC
    ) AS projection_rank,
    COUNT(*) OVER (
      PARTITION BY run_id, path, source_authority
    ) AS projection_count,
    FIRST_VALUE(projection_id) OVER (
      PARTITION BY run_id, path, source_authority
      ORDER BY julianday(generated_at) DESC, generated_at DESC, projection_id DESC
    ) AS retained_projection_id
  FROM artifact_projections
)
INSERT INTO artifact_projection_history(
  projection_id,
  run_id,
  path,
  sha256,
  source_authority,
  generated_from_transition_id,
  generated_at,
  retained_projection_id,
  archived_at,
  archive_reason
)
SELECT
  projection_id,
  run_id,
  path,
  sha256,
  source_authority,
  generated_from_transition_id,
  generated_at,
  retained_projection_id,
  datetime('now'),
  'v1_identity_collapse'
FROM ranked
WHERE projection_count > 1
  AND projection_rank > 1;

WITH ranked AS (
  SELECT
    projection_id,
    run_id,
    path,
    sha256,
    source_authority,
    generated_from_transition_id,
    generated_at,
    ROW_NUMBER() OVER (
      PARTITION BY run_id, path, source_authority
      ORDER BY julianday(generated_at) DESC, generated_at DESC, projection_id DESC
    ) AS projection_rank
  FROM artifact_projections
)
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
FROM ranked
WHERE projection_rank = 1;

DROP TABLE artifact_projections;

ALTER TABLE artifact_projections_v2 RENAME TO artifact_projections;
