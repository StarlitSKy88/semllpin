-- Create geocoding cache table
CREATE TABLE IF NOT EXISTS geocoding_cache (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  address TEXT NOT NULL,
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  formatted_address TEXT,
  country TEXT,
  city TEXT,
  state TEXT,
  postal_code TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '30 days'),
  hit_count INTEGER DEFAULT 1
);

-- Create reverse geocoding cache table
CREATE TABLE IF NOT EXISTS reverse_geocoding_cache (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  latitude DECIMAL(10, 8) NOT NULL,
  longitude DECIMAL(11, 8) NOT NULL,
  address TEXT NOT NULL,
  formatted_address TEXT,
  country TEXT,
  city TEXT,
  state TEXT,
  postal_code TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  expires_at TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '30 days'),
  hit_count INTEGER DEFAULT 1
);

-- Create geocoding usage logs table
CREATE TABLE IF NOT EXISTS geocoding_usage_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  request_type TEXT NOT NULL CHECK (request_type IN ('geocode', 'reverse_geocode')),
  input_data JSONB NOT NULL,
  output_data JSONB,
  success BOOLEAN NOT NULL DEFAULT true,
  error_message TEXT,
  response_time_ms INTEGER,
  provider TEXT DEFAULT 'mock',
  cache_hit BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_geocoding_cache_address ON geocoding_cache(address);
CREATE INDEX IF NOT EXISTS idx_geocoding_cache_expires_at ON geocoding_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_reverse_geocoding_cache_coords ON reverse_geocoding_cache(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_reverse_geocoding_cache_expires_at ON reverse_geocoding_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_geocoding_usage_logs_user_id ON geocoding_usage_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_geocoding_usage_logs_created_at ON geocoding_usage_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_geocoding_usage_logs_request_type ON geocoding_usage_logs(request_type);

-- Enable Row Level Security
ALTER TABLE geocoding_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE reverse_geocoding_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE geocoding_usage_logs ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for geocoding_cache
CREATE POLICY "Allow public read access to geocoding_cache" ON geocoding_cache
  FOR SELECT USING (true);

CREATE POLICY "Allow authenticated users to insert geocoding_cache" ON geocoding_cache
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow authenticated users to update geocoding_cache" ON geocoding_cache
  FOR UPDATE USING (true);

-- Create RLS policies for reverse_geocoding_cache
CREATE POLICY "Allow public read access to reverse_geocoding_cache" ON reverse_geocoding_cache
  FOR SELECT USING (true);

CREATE POLICY "Allow authenticated users to insert reverse_geocoding_cache" ON reverse_geocoding_cache
  FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow authenticated users to update reverse_geocoding_cache" ON reverse_geocoding_cache
  FOR UPDATE USING (true);

-- Create RLS policies for geocoding_usage_logs
CREATE POLICY "Users can view their own geocoding usage logs" ON geocoding_usage_logs
  FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Allow authenticated users to insert geocoding usage logs" ON geocoding_usage_logs
  FOR INSERT WITH CHECK (auth.uid() = user_id);

-- Grant permissions to anon and authenticated roles
GRANT SELECT ON geocoding_cache TO anon;
GRANT ALL PRIVILEGES ON geocoding_cache TO authenticated;

GRANT SELECT ON reverse_geocoding_cache TO anon;
GRANT ALL PRIVILEGES ON reverse_geocoding_cache TO authenticated;

GRANT SELECT, INSERT ON geocoding_usage_logs TO authenticated;

-- Create function to clean up expired cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_geocoding_cache()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  -- Delete expired geocoding cache entries
  DELETE FROM geocoding_cache WHERE expires_at < NOW();
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  
  -- Delete expired reverse geocoding cache entries
  DELETE FROM reverse_geocoding_cache WHERE expires_at < NOW();
  GET DIAGNOSTICS deleted_count = deleted_count + ROW_COUNT;
  
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to get geocoding statistics
CREATE OR REPLACE FUNCTION get_geocoding_stats()
RETURNS TABLE(
  total_geocoding_requests BIGINT,
  total_reverse_geocoding_requests BIGINT,
  cache_hit_rate DECIMAL,
  avg_response_time_ms DECIMAL,
  total_cache_entries BIGINT,
  expired_cache_entries BIGINT
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    (SELECT COUNT(*) FROM geocoding_usage_logs WHERE request_type = 'geocode'),
    (SELECT COUNT(*) FROM geocoding_usage_logs WHERE request_type = 'reverse_geocode'),
    (SELECT ROUND(AVG(CASE WHEN cache_hit THEN 1.0 ELSE 0.0 END) * 100, 2) FROM geocoding_usage_logs),
    (SELECT ROUND(AVG(response_time_ms), 2) FROM geocoding_usage_logs WHERE response_time_ms IS NOT NULL),
    (SELECT COUNT(*) FROM geocoding_cache) + (SELECT COUNT(*) FROM reverse_geocoding_cache),
    (SELECT COUNT(*) FROM geocoding_cache WHERE expires_at < NOW()) + (SELECT COUNT(*) FROM reverse_geocoding_cache WHERE expires_at < NOW());
END;
$$ LANGUAGE plpgsql;