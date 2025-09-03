const dotenv = require('dotenv');
const { neon } = require('@neondatabase/serverless');
const path = require('path');

// Load environment variables from workers/.dev.vars
dotenv.config({ path: path.join(process.cwd(), 'workers', '.dev.vars') });

async function checkUsersTable() {
  try {
    console.log('DATABASE_URL:', process.env.DATABASE_URL ? 'Found' : 'Not found');
    
    if (!process.env.DATABASE_URL) {
      console.error('DATABASE_URL not found in environment variables');
      return;
    }

    const sql = neon(process.env.DATABASE_URL);
    
    // Query to get column information for users table
    const result = await sql`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns 
      WHERE table_name = 'users' 
      AND table_schema = 'public'
      ORDER BY ordinal_position;
    `;
    
    console.log('Users table structure:');
    console.table(result);
    
    // Check if password_hash column exists
    const hasPasswordHash = result.some(col => col.column_name === 'password_hash');
    console.log('\nHas password_hash column:', hasPasswordHash);
    
  } catch (error) {
    console.error('Error checking users table:', error.message);
  }
}

checkUsersTable();