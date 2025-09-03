import { neon } from '@neondatabase/serverless';
import { readFileSync } from 'fs';

// Load environment variables from .dev.vars
const envContent = readFileSync('.dev.vars', 'utf8');
const envVars = {};
envContent.split('\n').forEach(line => {
  if (line.trim() && !line.startsWith('#')) {
    const [key, value] = line.split('=');
    if (key && value) {
      envVars[key.trim()] = value.trim();
    }
  }
});

const sql = neon(envVars.DATABASE_URL);

async function checkDatabaseTables() {
  console.log('🔍 Checking database tables...');
  
  try {
    // Check if users table exists
    console.log('\n📋 Checking users table...');
    const usersResult = await sql`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'users' AND table_schema = 'public'
      ORDER BY ordinal_position;
    `;
    
    if (usersResult.length > 0) {
      console.log('✅ Users table exists with columns:');
      usersResult.forEach(col => {
        console.log(`   - ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
      });
    } else {
      console.log('❌ Users table does not exist');
    }
    
    // Check if wallets table exists
    console.log('\n💰 Checking wallets table...');
    const walletsResult = await sql`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'wallets' AND table_schema = 'public'
      ORDER BY ordinal_position;
    `;
    
    if (walletsResult.length > 0) {
      console.log('✅ Wallets table exists with columns:');
      walletsResult.forEach(col => {
        console.log(`   - ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
      });
    } else {
      console.log('❌ Wallets table does not exist');
    }
    
    // Check if transactions table exists
    console.log('\n💳 Checking transactions table...');
    const transactionsResult = await sql`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'transactions' AND table_schema = 'public'
      ORDER BY ordinal_position;
    `;
    
    if (transactionsResult.length > 0) {
      console.log('✅ Transactions table exists with columns:');
      transactionsResult.forEach(col => {
        console.log(`   - ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
      });
    } else {
      console.log('❌ Transactions table does not exist');
    }
    
    // Check if lbs_rewards table exists
    console.log('\n📍 Checking lbs_rewards table...');
    const lbsResult = await sql`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'lbs_rewards' AND table_schema = 'public'
      ORDER BY ordinal_position;
    `;
    
    if (lbsResult.length > 0) {
      console.log('✅ LBS rewards table exists with columns:');
      lbsResult.forEach(col => {
        console.log(`   - ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
      });
    } else {
      console.log('❌ LBS rewards table does not exist');
    }
    
    // List all tables in the database
    console.log('\n📊 All tables in database:');
    const allTables = await sql`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
      ORDER BY table_name;
    `;
    
    if (allTables.length > 0) {
      allTables.forEach(table => {
        console.log(`   - ${table.table_name}`);
      });
    } else {
      console.log('   No tables found in public schema');
    }
    
  } catch (error) {
    console.error('❌ Error checking database tables:', error);
  }
}

checkDatabaseTables().catch(console.error);