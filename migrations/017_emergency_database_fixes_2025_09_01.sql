-- Emergency database fixes for SmellPin MVP launch
-- Date: 2025-09-01
-- Purpose: Fix critical table structure issues blocking production launch

-- =============================================================================
-- USERS TABLE FIXES
-- =============================================================================

-- 1. Add missing display_name field
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(100);
CREATE INDEX IF NOT EXISTS idx_users_display_name ON users(display_name);

-- Update admin user to ensure display_name is populated
UPDATE users SET 
  display_name = COALESCE(display_name, full_name, username),
  updated_at = CURRENT_TIMESTAMP
WHERE display_name IS NULL OR display_name = '';

-- =============================================================================
-- ANNOTATIONS TABLE FIXES  
-- =============================================================================

-- 2. Add missing geographic fields for PostGIS integration
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS latitude DECIMAL(10, 8);
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS longitude DECIMAL(11, 8);
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS location_point GEOMETRY(POINT, 4326);

-- 3. Add missing annotation fields for API compatibility
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS country VARCHAR(2);
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS region VARCHAR(100);
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS city VARCHAR(100);
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS moderation_reason TEXT;
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS moderated_by UUID REFERENCES users(id);
ALTER TABLE annotations ADD COLUMN IF NOT EXISTS moderated_at TIMESTAMP WITH TIME ZONE;

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- =============================================================================

-- Geographic field indexes
CREATE INDEX IF NOT EXISTS idx_annotations_latitude ON annotations(latitude);
CREATE INDEX IF NOT EXISTS idx_annotations_longitude ON annotations(longitude);
CREATE INDEX IF NOT EXISTS idx_annotations_lat_lng ON annotations(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_annotations_location_point ON annotations USING GIST(location_point);

-- Location metadata indexes
CREATE INDEX IF NOT EXISTS idx_annotations_country ON annotations(country);
CREATE INDEX IF NOT EXISTS idx_annotations_region ON annotations(region);
CREATE INDEX IF NOT EXISTS idx_annotations_city ON annotations(city);
CREATE INDEX IF NOT EXISTS idx_annotations_moderated_by ON annotations(moderated_by);

-- =============================================================================
-- POSTGIS FUNCTIONS AND TRIGGERS
-- =============================================================================

-- Ensure PostGIS extension is available
CREATE EXTENSION IF NOT EXISTS postgis;

-- Function to automatically set location_point from lat/lng coordinates
CREATE OR REPLACE FUNCTION set_location_point()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.latitude IS NOT NULL AND NEW.longitude IS NOT NULL THEN
    NEW.location_point = ST_SetSRID(ST_MakePoint(NEW.longitude, NEW.latitude), 4326);
  END IF;
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to automatically update location_point when lat/lng changes
DROP TRIGGER IF EXISTS set_annotations_location_point ON annotations;
CREATE TRIGGER set_annotations_location_point
  BEFORE INSERT OR UPDATE ON annotations
  FOR EACH ROW
  EXECUTE FUNCTION set_location_point();

-- =============================================================================
-- GEOGRAPHIC QUERY FUNCTIONS
-- =============================================================================

-- Function to find nearby annotations using PostGIS
CREATE OR REPLACE FUNCTION get_nearby_annotations(
  p_latitude DECIMAL,
  p_longitude DECIMAL,
  p_radius_meters INTEGER DEFAULT 1000,
  p_limit INTEGER DEFAULT 10
)
RETURNS TABLE (
  id UUID,
  user_id UUID,
  latitude DECIMAL,
  longitude DECIMAL,
  smell_intensity INTEGER,
  content TEXT,
  distance_meters DOUBLE PRECISION,
  created_at TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    a.id,
    a.user_id,
    a.latitude,
    a.longitude,
    a.smell_intensity,
    a.content,
    ST_Distance(
      a.location_point,
      ST_SetSRID(ST_MakePoint(p_longitude, p_latitude), 4326)
    ) as distance_meters,
    a.created_at
  FROM annotations a
  WHERE 
    a.status = 'active'
    AND a.latitude IS NOT NULL
    AND a.longitude IS NOT NULL
    AND ST_DWithin(
      a.location_point,
      ST_SetSRID(ST_MakePoint(p_longitude, p_latitude), 4326),
      p_radius_meters
    )
  ORDER BY distance_meters
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- DATA CONSISTENCY UPDATES
-- =============================================================================

-- Ensure admin user has proper display_name and role
INSERT INTO users (
  email,
  username,
  password_hash,
  display_name,
  full_name,
  role,
  email_verified
) VALUES (
  'admin@smellpin.com',
  'admin',
  '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj6hsxq5S/kS', -- admin123!
  'System Administrator',
  'System Administrator',
  'admin',
  TRUE
) ON CONFLICT (email) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  role = EXCLUDED.role,
  updated_at = CURRENT_TIMESTAMP;

-- =============================================================================
-- VERIFICATION QUERIES (for testing)
-- =============================================================================

-- Verify users table has display_name
SELECT 'Users table verification' as test, 
       COUNT(*) as total_users,
       COUNT(display_name) as users_with_display_name
FROM users;

-- Verify annotations table has geographic fields
SELECT 'Annotations table verification' as test,
       COUNT(*) as total_annotations,
       COUNT(latitude) as annotations_with_coordinates,
       COUNT(location_point) as annotations_with_postgis_points
FROM annotations;

-- Verify PostGIS functionality
SELECT 'PostGIS verification' as test,
       ST_AsText(ST_MakePoint(-122.4194, 37.7749)) as sample_point;

-- =============================================================================
-- MIGRATION COMPLETION
-- =============================================================================

SELECT 'Emergency database fixes completed successfully' as status,
       CURRENT_TIMESTAMP as completed_at;