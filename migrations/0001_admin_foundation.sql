-- Tendora Admin foundation: version 1
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  password_iterations INTEGER NOT NULL DEFAULT 310000,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','editor','reviewer')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','invited','disabled')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  employer TEXT NOT NULL,
  category TEXT,
  employment_type TEXT,
  location TEXT,
  salary_text TEXT,
  description TEXT NOT NULL,
  responsibilities TEXT,
  qualifications TEXT,
  experience TEXT,
  application_instructions TEXT,
  source_url TEXT NOT NULL,
  application_url TEXT NOT NULL,
  deadline TEXT,
  date_verified TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','pending_verification','pending_approval','published','rejected','expired','archived')),
  created_by TEXT REFERENCES admins(id),
  verified_by TEXT REFERENCES admins(id),
  approved_by TEXT REFERENCES admins(id),
  published_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_jobs_status_deadline ON jobs(status,deadline);
CREATE INDEX IF NOT EXISTS idx_jobs_employer ON jobs(employer);
CREATE INDEX IF NOT EXISTS idx_jobs_updated ON jobs(updated_at);

CREATE TABLE IF NOT EXISTS job_sources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  organization_type TEXT,
  website_url TEXT NOT NULL,
  careers_url TEXT NOT NULL,
  monitoring_method TEXT NOT NULL DEFAULT 'manual' CHECK (monitoring_method IN ('manual','rss','public_page')),
  monitoring_enabled INTEGER NOT NULL DEFAULT 1 CHECK (monitoring_enabled IN (0,1)),
  last_checked_at TEXT,
  last_status TEXT,
  notes TEXT,
  created_by TEXT REFERENCES admins(id),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_job_sources_enabled ON job_sources(monitoring_enabled);

CREATE TABLE IF NOT EXISTS discovery_candidates (
  id TEXT PRIMARY KEY,
  source_id TEXT REFERENCES job_sources(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  employer TEXT,
  source_url TEXT NOT NULL,
  application_url TEXT,
  deadline TEXT,
  detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','reviewing','converted','rejected','duplicate')),
  notes TEXT,
  linked_job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_discovery_status ON discovery_candidates(status,detected_at);

CREATE TABLE IF NOT EXISTS content_pages (
  id TEXT PRIMARY KEY,
  page_key TEXT NOT NULL UNIQUE,
  title_en TEXT,
  body_en TEXT,
  title_rw TEXT,
  body_rw TEXT,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published')),
  updated_by TEXT REFERENCES admins(id),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS tool_settings (
  id TEXT PRIMARY KEY,
  tool_key TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  description TEXT,
  category TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  featured INTEGER NOT NULL DEFAULT 0 CHECK (featured IN (0,1)),
  updated_by TEXT REFERENCES admins(id),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id TEXT PRIMARY KEY,
  admin_id TEXT REFERENCES admins(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  details_json TEXT,
  ip_hash TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_admin ON admin_audit_logs(admin_id);
