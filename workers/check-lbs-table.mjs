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

async function checkLbsTable() {
  console.log('🔍 Checking lbs_rewards table structure...');
  
  try {
    // Check lbs_rewards table structure
    const lbsColumns = await sql`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns 
      WHERE table_name = 'lbs_rewards' AND table_schema = 'public'
      ORDER BY ordinal_position;
    `;
    
    console.log('\n📍 LBS Rewards table columns:');
    lbsColumns.forEach(col => {
      console.log(`   - ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable}, default: ${col.column_default || 'none'})`);
    });
    
    // Test a simple query
    console.log('\n🧪 Testing simple query...');
    const testQuery = await sql`
      SELECT COUNT(*) as count FROM lbs_rewards
    `;
    console.log(`   Records count: ${testQuery[0].count}`);
    
    // Test query with created_at
    console.log('\n🧪 Testing query with created_at...');
    try {
      const testCreatedAt = await sql`
        SELECT id, user_id, created_at FROM lbs_rewards LIMIT 1
      `;
      console.log('   ✅ created_at field accessible');
    } catch (error) {
      console.log('   ❌ created_at field error:', error.message);
    }
    
  } catch (error) {
    console.error('❌ Error checking lbs_rewards table:', error);
  }
}

checkLbsTable().catch(console.error);