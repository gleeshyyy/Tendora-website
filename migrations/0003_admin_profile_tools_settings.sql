-- Tendora admin profile, settings and document tool management
ALTER TABLE admins ADD COLUMN avatar_data_url TEXT;
CREATE TABLE IF NOT EXISTS site_settings (setting_key TEXT PRIMARY KEY,setting_value TEXT NOT NULL,updated_by TEXT REFERENCES admins(id),updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
INSERT OR IGNORE INTO site_settings(setting_key,setting_value) VALUES ('site_name','Tendora'),('default_language','English'),('timezone','Africa/Kigali'),('default_job_location','Rwanda');
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-01','cv-builder','CV Builder','CV Builder on Tendora','CV & Cover Letters',1,1);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-02','merge-pdf','Merge PDF','Merge PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-03','split-pdf','Split PDF','Split PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-04','pdf-to-word','PDF to Word','PDF to Word on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-05','pdf-to-images','PDF to Images','PDF to Images on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-06','compress-pdf','Compress PDF','Compress PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-07','rotate-pdf','Rotate PDF','Rotate PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-08','add-page-numbers','Add Page Numbers to PDF','Add Page Numbers to PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-09','word-to-pdf','Word/Excel to PDF','Word/Excel to PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-10','text-to-pdf','Text to PDF','Text to PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-11','image-to-pdf','Image to PDF','Image to PDF on Tendora','PDF Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-12','image-converter','Image Converter','Image Converter on Tendora','Image Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-13','image-compressor','Image Compressor','Image Compressor on Tendora','Image Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-14','qr-code-generator','QR Code Generator','QR Code Generator on Tendora','Image Tools',1,0);
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured) VALUES('tendora-tool-15','png-to-jpg','PNG to JPG','PNG to JPG on Tendora','Image Tools',1,0);