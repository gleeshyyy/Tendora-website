-- Tendora analytics event tracking
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS analytics_events (
  id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL CHECK (event_type IN ('application_click')),
  job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_analytics_event_date ON analytics_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_job_date ON analytics_events(job_id, created_at);
