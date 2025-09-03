-- Create comments table
CREATE TABLE comments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  annotation_id UUID NOT NULL REFERENCES annotations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES comments(id) ON DELETE CASCADE, -- For nested comments
  content TEXT NOT NULL,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'deleted', 'hidden')),
  like_count INTEGER DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_comments_annotation_id ON comments(annotation_id);
CREATE INDEX idx_comments_user_id ON comments(user_id);
CREATE INDEX idx_comments_parent_id ON comments(parent_id);
CREATE INDEX idx_comments_status ON comments(status);
CREATE INDEX idx_comments_created_at ON comments(created_at);

-- Create composite indexes
CREATE INDEX idx_comments_annotation_status ON comments(annotation_id, status);
CREATE INDEX idx_comments_annotation_created_at ON comments(annotation_id, created_at DESC);

-- Create trigger to update updated_at
CREATE TRIGGER update_comments_updated_at
  BEFORE UPDATE ON comments
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

-- Create trigger to update annotation comment count
CREATE OR REPLACE FUNCTION update_annotation_comment_count()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    UPDATE annotations 
    SET comment_count = (
      SELECT COUNT(*) 
      FROM comments 
      WHERE annotation_id = NEW.annotation_id AND status = 'active'
    )
    WHERE id = NEW.annotation_id;
    RETURN NEW;
  ELSIF TG_OP = 'UPDATE' THEN
    UPDATE annotations 
    SET comment_count = (
      SELECT COUNT(*) 
      FROM comments 
      WHERE annotation_id = NEW.annotation_id AND status = 'active'
    )
    WHERE id = NEW.annotation_id;
    RETURN NEW;
  ELSIF TG_OP = 'DELETE' THEN
    UPDATE annotations 
    SET comment_count = (
      SELECT COUNT(*) 
      FROM comments 
      WHERE annotation_id = OLD.annotation_id AND status = 'active'
    )
    WHERE id = OLD.annotation_id;
    RETURN OLD;
  END IF;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_annotation_comment_count_trigger
  AFTER INSERT OR UPDATE OR DELETE ON comments
  FOR EACH ROW
  EXECUTE FUNCTION update_annotation_comment_count();

-- Create function to get comment tree
CREATE OR REPLACE FUNCTION get_comment_tree(
  p_annotation_id UUID,
  p_limit INTEGER DEFAULT 50,
  p_offset INTEGER DEFAULT 0
)
RETURNS TABLE (
  id UUID,
  annotation_id UUID,
  user_id UUID,
  username VARCHAR,
  display_name VARCHAR,
  avatar_url VARCHAR,
  parent_id UUID,
  content TEXT,
  like_count INTEGER,
  created_at TIMESTAMP WITH TIME ZONE,
  level INTEGER
) AS $$
BEGIN
  RETURN QUERY
  WITH RECURSIVE comment_tree AS (
    -- Base case: top-level comments
    SELECT 
      c.id,
      c.annotation_id,
      c.user_id,
      u.username,
      u.display_name,
      u.avatar_url,
      c.parent_id,
      c.content,
      c.like_count,
      c.created_at,
      0 as level
    FROM comments c
    JOIN users u ON c.user_id = u.id
    WHERE 
      c.annotation_id = p_annotation_id 
      AND c.parent_id IS NULL 
      AND c.status = 'active'
    
    UNION ALL
    
    -- Recursive case: child comments
    SELECT 
      c.id,
      c.annotation_id,
      c.user_id,
      u.username,
      u.display_name,
      u.avatar_url,
      c.parent_id,
      c.content,
      c.like_count,
      c.created_at,
      ct.level + 1
    FROM comments c
    JOIN users u ON c.user_id = u.id
    JOIN comment_tree ct ON c.parent_id = ct.id
    WHERE c.status = 'active' AND ct.level < 5 -- Limit nesting depth
  )
  SELECT * FROM comment_tree
  ORDER BY level, created_at ASC
  LIMIT p_limit
  OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;