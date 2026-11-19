-- Require newly created and reset administrator accounts to replace temporary passwords.
ALTER TABLE admins ADD COLUMN password_reset_required INTEGER NOT NULL DEFAULT 0 CHECK (password_reset_required IN (0,1));
