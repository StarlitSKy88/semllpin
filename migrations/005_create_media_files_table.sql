-- Create media_files table
CREATE TABLE media_files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  annotation_id UUID REFERENCES annotations(id) ON DELETE CASCADE,
  filename VARCHAR(255) NOT NULL,
  original_filename VARCHAR(255) NOT NULL,
  file_path VARCHAR(500) NOT NULL,
  file_url VARCHAR(500),
  file_size BIGINT NOT NULL, -- in bytes
  mime_type VARCHAR(100) NOT NULL,
  file_type VARCHAR(20) NOT NULL CHECK (file_type IN ('image', 'video', 'audio')),
  width INTEGER, -- for images and videos
  height INTEGER, -- for images and videos
  duration INTEGER, -- for videos and audio (in seconds)
  thumbnail_url VARCHAR(500), -- for videos
  metadata JSONB DEFAULT '{}'::jsonb, -- EXIF data, etc.
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'deleted', 'processing', 'failed')),
  upload_session_id VARCHAR(255), -- for tracking upload sessions
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_media_files_user_id ON media_files(user_id);
CREATE INDEX idx_media_files_annotation_id ON media_files(annotation_id);
CREATE INDEX idx_media_files_file_type ON media_files(file_type);
CREATE INDEX idx_media_files_mime_type ON media_files(mime_type);
CREATE INDEX idx_media_files_status ON media_files(status);
CREATE INDEX idx_media_files_created_at ON media_files(created_at);
CREATE INDEX idx_media_files_upload_session_id ON media_files(upload_session_id);

-- Create composite indexes
CREATE INDEX idx_media_files_user_type ON media_files(user_id, file_type);
CREATE INDEX idx_media_files_annotation_status ON media_files(annotation_id, status);

-- Create trigger to update updated_at
CREATE TRIGGER update_media_files_updated_at
  BEFORE UPDATE ON media_files
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Create function to clean up orphaned media files
CREATE OR REPLACE FUNCTION cleanup_orphaned_media_files()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  -- Delete media files that are not associated with any annotation
  -- and are older than 24 hours
  UPDATE media_files 
  SET status = 'deleted'
  WHERE 
    annotation_id IS NULL 
    AND created_at < CURRENT_TIMESTAMP - INTERVAL '24 hours'
    AND status = 'active';
  
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to get media file statistics
CREATE OR REPLACE FUNCTION get_media_file_stats(
  p_user_id UUID DEFAULT NULL,
  p_start_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
  p_end_date TIMESTAMP WITH TIME ZONE DEFAULT NULL
)
RETURNS TABLE (
  file_type VARCHAR,
  total_files BIGINT,
  total_size BIGINT,
  avg_size NUMERIC,
  max_size BIGINT,
  min_size BIGINT
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    mf.file_type,
    COUNT(*) as total_files,
    SUM(mf.file_size) as total_size,
    AVG(mf.file_size) as avg_size,
    MAX(mf.file_size) as max_size,
    MIN(mf.file_size) as min_size
  FROM media_files mf
  WHERE 
    mf.status = 'active'
    AND (p_user_id IS NULL OR mf.user_id = p_user_id)
    AND (p_start_date IS NULL OR mf.created_at >= p_start_date)
    AND (p_end_date IS NULL OR mf.created_at <= p_end_date)
  GROUP BY mf.file_type
  ORDER BY total_files DESC;
END;
$$ LANGUAGE plpgsql;

-- Create view for media file summary
CREATE VIEW media_file_summary AS
SELECT 
  DATE_TRUNC('day', created_at) as date,
  file_type,
  COUNT(*) as files_uploaded,
  SUM(file_size) as total_size,
  AVG(file_size) as avg_size,
  COUNT(CASE WHEN status = 'active' THEN 1 END) as active_files,
  COUNT(CASE WHEN status = 'deleted' THEN 1 END) as deleted_files,
  COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_files
FROM media_files
GROUP BY DATE_TRUNC('day', created_at), file_type
ORDER BY date DESC;

-- Create function to get user's media files
CREATE OR REPLACE FUNCTION get_user_media_files(
  p_user_id UUID,
  p_file_type VARCHAR DEFAULT NULL,
  p_limit INTEGER DEFAULT 20,
  p_offset INTEGER DEFAULT 0
)
RETURNS TABLE (
  id UUID,
  annotation_id UUID,
  filename VARCHAR,
  original_filename VARCHAR,
  file_url VARCHAR,
  file_size BIGINT,
  mime_type VARCHAR,
  file_type VARCHAR,
  width INTEGER,
  height INTEGER,
  duration INTEGER,
  thumbnail_url VARCHAR,
  created_at TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    mf.id,
    mf.annotation_id,
    mf.filename,
    mf.original_filename,
    mf.file_url,
    mf.file_size,
    mf.mime_type,
    mf.file_type,
    mf.width,
    mf.height,
    mf.duration,
    mf.thumbnail_url,
    mf.created_at
  FROM media_files mf
  WHERE 
    mf.user_id = p_user_id
    AND mf.status = 'active'
    AND (p_file_type IS NULL OR mf.file_type = p_file_type)
  ORDER BY mf.created_at DESC
  LIMIT p_limit
  OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update annotation media_files array
CREATE OR REPLACE FUNCTION update_annotation_media_files()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.annotation_id IS NOT NULL THEN
    UPDATE annotations 
    SET media_files = (
      SELECT COALESCE(jsonb_agg(id), '[]'::jsonb)
      FROM media_files 
      WHERE annotation_id = NEW.annotation_id AND status = 'active'
    )
    WHERE id = NEW.annotation_id;
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    -- Update both old and new annotation if annotation_id changed
    IF OLD.annotation_id IS NOT NULL THEN
      UPDATE annotations 
      SET media_files = (
        SELECT COALESCE(jsonb_agg(id), '[]'::jsonb)
        FROM media_files 
        WHERE annotation_id = OLD.annotation_id AND status = 'active'
      )
      WHERE id = OLD.annotation_id;
    END IF;
    
    IF NEW.annotation_id IS NOT NULL THEN
      UPDATE annotations 
      SET media_files = (
        SELECT COALESCE(jsonb_agg(id), '[]'::jsonb)
        FROM media_files 
        WHERE annotation_id = NEW.annotation_id AND status = 'active'
      )
      WHERE id = NEW.annotation_id;
    END IF;
    
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' AND OLD.annotation_id IS NOT NULL THEN
    UPDATE annotations 
    SET media_files = (
      SELECT COALESCE(jsonb_agg(id), '[]'::jsonb)
      FROM media_files 
      WHERE annotation_id = OLD.annotation_id AND status = 'active'
    )
    WHERE id = OLD.annotation_id;
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_annotation_media_files_trigger
  AFTER INSERT OR UPDATE OR DELETE ON media_files
  FOR EACH ROW
  EXECUTE FUNCTION update_annotation_media_files();