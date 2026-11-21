CREATE TABLE IF NOT EXISTS chat_conversations (
 id TEXT PRIMARY KEY,
 visitor_token_hash TEXT NOT NULL UNIQUE,
 visitor_name TEXT NOT NULL,
 visitor_unread INTEGER NOT NULL DEFAULT 0,
 admin_unread INTEGER NOT NULL DEFAULT 0,
 last_message_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_chat_conversations_last_message ON chat_conversations(last_message_at DESC);
CREATE TABLE IF NOT EXISTS chat_messages (
 id TEXT PRIMARY KEY,
 conversation_id TEXT NOT NULL REFERENCES chat_conversations(id) ON DELETE CASCADE,
 sender TEXT NOT NULL CHECK(sender IN ('visitor','admin')),
 body TEXT NOT NULL DEFAULT '',
 attachment_key TEXT,
 attachment_type TEXT,
 attachment_name TEXT,
 attachment_size INTEGER,
 attachment_expires_at TEXT,
 created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation ON chat_messages(conversation_id,created_at);
