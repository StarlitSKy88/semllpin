const fs = require('fs');
const { neon } = require('@neondatabase/serverless');
const path = require('path');

// Read DATABASE_URL directly from .dev.vars file
function getDatabaseUrl() {
  try {
    const devVarsPath = path.join(__dirname, '.dev.vars');
    const content = fs.readFileSync(devVarsPath, 'utf8');
    const lines = content.split('\n');
    
    for (const line of lines) {
      if (line.startsWith('DATABASE_URL=')) {
        return line.split('=')[1];
      }
    }
    return null;
  } catch (error) {
    console.error('Error reading .dev.vars:', error.message);
    return null;
  }
}

async function checkUsersTable() {
  try {
    const databaseUrl = getDatabaseUrl();
    console.log('DATABASE_URL:', databaseUrl ? 'Found' : 'Not found');
    
    if (!databaseUrl) {
      console.error('DATABASE_URL not found in .dev.vars file');
      return;
    }

    const sql = neon(databaseUrl);
    
    console.log('Checking users table structure...');
    const result = await sql`
      SELECT column_name, data_type, is_nullable, column_default 
      FROM information_schema.columns 
      WHERE table_name = 'users' 
      ORDER BY ordinal_position
    `;
    
    console.log('Users table columns:');
    result.forEach(col => {
      console.log(`- ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
    });
    
  } catch (error) {
    console.error('Error:', error);
  }
}

checkUsersTable();