-- Register Tendora's browser-based AI background remover.
INSERT OR IGNORE INTO tool_settings(id,tool_key,display_name,description,category,enabled,featured)
VALUES('tendora-tool-16','background-remover','Background Remover','Remove image backgrounds with on-device AI','Image Tools',1,0);
