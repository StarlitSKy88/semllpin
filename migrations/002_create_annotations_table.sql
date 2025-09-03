-- Create PostGIS extension for geographic data
CREATE EXTENSION IF NOT EXISTS postgis;

-- Create annotations table
CREATE TABLE annotations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  location_point GEOMETRY(POINT, 4326) NOT NULL,
  smell_intensity INTEGER NOT NULL CHECK (smell_intensity >= 1 AND smell_intensity <= 10),
  description TEXT,
  country VARCHAR(2), -- ISO country code
  region VARCHAR(100),
  city VARCHAR(100),
  address TEXT,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  moderation_reason TEXT,
  moderated_by UUID REFERENCES users(id),
  moderated_at TIMESTAMP WITH TIME ZONE,
  payment_id UUID, -- Reference to payment record
  media_files JSONB DEFAULT '[]'::jsonb, -- Array of media file IDs
  view_count INTEGER DEFAULT 0,
  like_count INTEGER DEFAULT 0,
  comment_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_annotations_user_id ON annotations(user_id);
CREATE INDEX idx_annotations_status ON annotations(status);
CREATE INDEX idx_annotations_smell_intensity ON annotations(smell_intensity);
CREATE INDEX idx_annotations_country ON annotations(country);
CREATE INDEX idx_annotations_region ON annotations(region);
CREATE INDEX idx_annotations_city ON annotations(city);
CREATE INDEX idx_annotations_created_at ON annotations(created_at);
CREATE INDEX idx_annotations_moderated_by ON annotations(moderated_by);
CREATE INDEX idx_annotations_payment_id ON annotations(payment_id);

-- Create spatial indexes
CREATE INDEX idx_annotations_location_point ON annotations USING GIST(location_point);
CREATE INDEX idx_annotations_lat_lng ON annotations(latitude, longitude);

-- Create composite indexes for common queries
CREATE INDEX idx_annotations_status_created_at ON annotations(status, created_at DESC);
CREATE INDEX idx_annotations_user_status ON annotations(user_id, status);
CREATE INDEX idx_annotations_intensity_status ON annotations(smell_intensity, status);

-- Create trigger to update updated_at
CREATE TRIGGER update_annotations_updated_at
  BEFORE UPDATE ON annotations
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Create trigger to automatically set location_point from lat/lng
CREATE OR REPLACE FUNCTION set_location_point()
RETURNS TRIGGER AS $$
BEGIN
  NEW.location_point = ST_SetSRID(ST_MakePoint(NEW.longitude, NEW.latitude), 4326);
  RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER set_annotations_location_point
  BEFORE INSERT OR UPDATE ON annotations
  FOR EACH ROW
  EXECUTE FUNCTION set_location_point();

-- Create function to get nearby annotations
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
  description TEXT,
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
    a.description,
    ST_Distance(
      a.location_point,
      ST_SetSRID(ST_MakePoint(p_longitude, p_latitude), 4326)
    ) as distance_meters,
    a.created_at
  FROM annotations a
  WHERE 
    a.status = 'approved'
    AND ST_DWithin(
      a.location_point,
      ST_SetSRID(ST_MakePoint(p_longitude, p_latitude), 4326),
      p_radius_meters
    )
  ORDER BY distance_meters
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- Create function to get annotations within bounds
CREATE OR REPLACE FUNCTION get_annotations_in_bounds(
  p_north DECIMAL,
  p_south DECIMAL,
  p_east DECIMAL,
  p_west DECIMAL,
  p_intensity_min INTEGER DEFAULT NULL,
  p_intensity_max INTEGER DEFAULT NULL,
  p_limit INTEGER DEFAULT 1000
)
RETURNS TABLE (
  id UUID,
  latitude DECIMAL,
  longitude DECIMAL,
  smell_intensity INTEGER,
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    a.id,
    a.latitude,
    a.longitude,
    a.smell_intensity,
    a.description,
    a.created_at
  FROM annotations a
  WHERE 
    a.status = 'approved'
    AND a.latitude BETWEEN p_south AND p_north
    AND a.longitude BETWEEN p_west AND p_east
    AND (p_intensity_min IS NULL OR a.smell_intensity >= p_intensity_min)
    AND (p_intensity_max IS NULL OR a.smell_intensity <= p_intensity_max)
  ORDER BY a.smell_intensity DESC, a.created_at DESC
  LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;