const { Pool } = require('pg');
require('dotenv').config({ path: '../.env' });

async function checkTableStructure() {
  const pool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'smellpin',
    user: 'postgres',
    password: 'password'
  });
  
  try {
    
    console.log('Checking checkin_records table structure:');
    const columnsResult = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default 
      FROM information_schema.columns 
      WHERE table_name = 'checkin_records' 
      ORDER BY ordinal_position
    `);
    const columns = columnsResult.rows;
    
    columns.forEach(col => {
      console.log(`- ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable}, default: ${col.column_default})`);
    });
    
    console.log('\nChecking reward_records table structure:');
    const rewardColumnsResult = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default 
      FROM information_schema.columns 
      WHERE table_name = 'reward_records' 
      ORDER BY ordinal_position
    `);
    const rewardColumns = rewardColumnsResult.rows;
    
    rewardColumns.forEach(col => {
      console.log(`- ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable}, default: ${col.column_default})`);
    });
    
  } catch (error) {
    console.error('Error checking table structure:', error);
  } finally {
    await pool.end();
  }
}

checkTableStructure();