const fs = require('fs');
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

// Read DATABASE_URL from .dev.vars
const devVars = fs.readFileSync('.dev.vars', 'utf8');
const databaseUrlMatch = devVars.match(/DATABASE_URL=(.+)/);
if (!databaseUrlMatch) {
  console.error('DATABASE_URL not found in .dev.vars');
  process.exit(1);
}

const DATABASE_URL = databaseUrlMatch[1];
console.log('DATABASE_URL: Found');

const sql = neon(DATABASE_URL);

async function testCreateUser() {
  try {
    console.log('Testing createUser SQL...');
    
    const userData = {
      id: crypto.randomUUID(),
      email: 'test@example.com',
      username: 'testuser',
      full_name: 'Test User',
      password_hash: 'hashed_password_123'
    };
    
    console.log('User data:', userData);
    
    // Test the exact SQL from createUser method
    const result = await sql`
      INSERT INTO users (id, email, username, full_name, password_hash, role, status, email_verified, is_verified, created_at, updated_at)
      VALUES (${userData.id}, ${userData.email}, ${userData.username}, ${userData.full_name}, ${userData.password_hash}, 'user', 'active', false, false, NOW(), NOW())
      RETURNING id, email, username, full_name, created_at
    `;
    
    console.log('✅ User created successfully:', result);
    
  } catch (error) {
    console.error('❌ Error creating user:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      position: error.position,
      severity: error.severity
    });
  }
}

testCreateUser();