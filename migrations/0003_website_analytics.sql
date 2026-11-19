CREATE TABLE IF NOT EXISTS website_analytics_events (
 id TEXT PRIMARY KEY,
 event_type TEXT NOT NULL CHECK (event_type IN ('page_view','tool_use')),
 visitor_hash TEXT NOT NULL,
 page_path TEXT NOT NULL,
 tool_key TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_website_analytics_event_date ON website_analytics_events(event_type,created_at);
CREATE INDEX IF NOT EXISTS idx_website_analytics_tool_date ON website_analytics_events(tool_key,created_at);
CREATE INDEX IF NOT EXISTS idx_website_analytics_visitor_date ON website_analytics_events(visitor_hash,created_at);
CREATE TABLE IF NOT EXISTS website_analytics_presence (
 visitor_hash TEXT PRIMARY KEY,
 current_path TEXT NOT NULL,
 last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_website_analytics_presence_seen ON website_analytics_presence(last_seen_at);
