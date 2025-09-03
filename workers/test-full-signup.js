const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
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

async function testFullSignup() {
  try {
    console.log('Testing full signup flow...');
    
    const signupData = {
  email: `fulltest${Date.now()}@example.com`,
  password: 'testpassword123',
  username: `fulltest${Date.now()}`,
  full_name: 'Full Test User'
};
    
    console.log('Signup data:', signupData);
    
    // Step 1: Check if email already exists
    console.log('\n1. Checking if email exists...');
    const existingEmail = await sql`SELECT id, email FROM users WHERE email = ${signupData.email}`;
    console.log('Existing email result:', existingEmail);
    
    if (existingEmail.length > 0) {
      console.log('Email already exists, skipping...');
      return;
    }
    
    // Step 2: Check if username already exists
    console.log('\n2. Checking if username exists...');
    const existingUsername = await sql`SELECT id, username FROM users WHERE username = ${signupData.username}`;
    console.log('Existing username result:', existingUsername);
    
    if (existingUsername.length > 0) {
      console.log('Username already exists, skipping...');
      return;
    }
    
    // Step 3: Hash password
    console.log('\n3. Hashing password...');
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(signupData.password, saltRounds);
    console.log('Password hashed successfully, length:', passwordHash.length);
    
    // Step 4: Generate UUID
    console.log('\n4. Generating UUID...');
    const userId = crypto.randomUUID();
    console.log('Generated UUID:', userId);
    
    // Step 5: Create user
    console.log('\n5. Creating user...');
    const userData = {
      id: userId,
      email: signupData.email,
      username: signupData.username,
      full_name: signupData.full_name,
      password_hash: passwordHash
    };
    
    console.log('Final user data:', {
      ...userData,
      password_hash: `[${userData.password_hash.length} chars]`
    });
    
    const result = await sql`
      INSERT INTO users (id, email, username, full_name, password_hash, role, status, email_verified, is_verified, created_at, updated_at)
      VALUES (${userData.id}, ${userData.email}, ${userData.username}, ${userData.full_name}, ${userData.password_hash}, 'user', 'active', false, false, NOW(), NOW())
      RETURNING id, email, username, full_name, created_at
    `;
    
    console.log('✅ Full signup test successful:', result);
    
  } catch (error) {
    console.error('❌ Error in full signup test:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      position: error.position,
      severity: error.severity,
      file: error.file,
      line: error.line,
      routine: error.routine
    });
  }
}

testFullSignup();