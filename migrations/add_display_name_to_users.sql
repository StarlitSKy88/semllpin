-- Add display_name field to users table
ALTER TABLE users ADD COLUMN display_name VARCHAR(100);

-- Add index for display_name for better search performance
CREATE INDEX idx_users_display_name ON users(display_name);