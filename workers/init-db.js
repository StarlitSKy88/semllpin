// Database initialization script
import { createNeonDatabase } from './src/utils/neon-database.js';

const env = {
  NEON_DATABASE_URL: process.env.NEON_DATABASE_URL || 'postgresql://neondb_owner:npg_password@ep-example.us-east-1.aws.neon.tech/neondb?sslmode=require'
};

async function initDatabase() {
  try {
    const db = createNeonDatabase(env);
    
    console.log('Creating user_files table...');
    
    // Create user_files table
    await db.query(`
      CREATE TABLE IF NOT EXISTS user_files (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        file_path TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size BIGINT NOT NULL,
        content_type TEXT NOT NULL,
        bucket TEXT NOT NULL,
        public_url TEXT NOT NULL,
        uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        is_secure BOOLEAN DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);
    
    // Create indexes
    await db.query('CREATE INDEX IF NOT EXISTS idx_user_files_user_id ON user_files(user_id)');
    await db.query('CREATE INDEX IF NOT EXISTS idx_user_files_bucket ON user_files(bucket)');
    await db.query('CREATE INDEX IF NOT EXISTS idx_user_files_uploaded_at ON user_files(uploaded_at DESC)');
    await db.query('CREATE INDEX IF NOT EXISTS idx_user_files_content_type ON user_files(content_type)');
    
    console.log('✅ Database initialized successfully!');
    
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

initDatabase();