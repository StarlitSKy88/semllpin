-- Add university and graduation_year fields to users table
ALTER TABLE users 
ADD COLUMN university VARCHAR(100),
ADD COLUMN graduation_year INTEGER,
ADD COLUMN preferred_language VARCHAR(10) DEFAULT 'en',
ADD COLUMN balance DECIMAL(10,2) DEFAULT 0.00,
ADD COLUMN total_earned DECIMAL(10,2) DEFAULT 0.00,
ADD COLUMN total_spent DECIMAL(10,2) DEFAULT 0.00,
ADD COLUMN points INTEGER DEFAULT 0,
ADD COLUMN level INTEGER DEFAULT 1,
ADD COLUMN prank_count INTEGER DEFAULT 0,
ADD COLUMN discovery_count INTEGER DEFAULT 0,
ADD COLUMN social_shares INTEGER DEFAULT 0,
ADD COLUMN phone VARCHAR(20) UNIQUE,
ADD COLUMN phone_verified BOOLEAN DEFAULT false,
ADD COLUMN is_premium BOOLEAN DEFAULT false;

-- Create indexes for new fields
CREATE INDEX idx_users_university ON users(university);
CREATE INDEX idx_users_level ON users(level);
CREATE INDEX idx_users_phone ON users(phone);