const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config({ path: '../.env' });

async function setupLBSTables() {
  // 首先尝试连接到本地PostgreSQL
  let pool = new Pool({
    host: 'localhost',
    port: 5432,
    database: 'smellpin',
    user: 'postgres',
    password: 'password'
  });
  
  try {
    // 测试连接
    await pool.query('SELECT 1');
    console.log('✅ 连接到本地PostgreSQL数据库成功');
  } catch (error) {
    console.log('❌ 无法连接到本地PostgreSQL，尝试创建内存数据库进行测试...');
    
    // 如果无法连接到PostgreSQL，创建一个简单的SQLite内存数据库用于测试
    const sqlite3 = require('sqlite3');
    const { open } = require('sqlite');
    
    try {
      const db = await open({
        filename: ':memory:',
        driver: sqlite3.Database
      });
      
      console.log('✅ 创建SQLite内存数据库成功，用于测试表结构');
      
      // 创建基础的users表用于测试
      await db.exec(`
        CREATE TABLE users (
          id TEXT PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          username TEXT UNIQUE NOT NULL,
          full_name TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);
      
      // 创建简化的LBS表结构
      await db.exec(`
        CREATE TABLE checkin_records (
          id TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          latitude REAL NOT NULL,
          longitude REAL NOT NULL,
          location_name TEXT,
          points_earned INTEGER DEFAULT 0,
          is_first_time BOOLEAN DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE reward_records (
          id TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL,
          reward_type TEXT NOT NULL,
          reward_category TEXT NOT NULL,
          points INTEGER DEFAULT 0,
          description TEXT NOT NULL,
          source_id TEXT,
          source_type TEXT,
          latitude REAL,
          longitude REAL,
          status TEXT DEFAULT 'pending',
          claimed_at DATETIME,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE user_stats (
          id TEXT PRIMARY KEY,
          user_id TEXT NOT NULL UNIQUE,
          total_points INTEGER DEFAULT 0,
          total_checkins INTEGER DEFAULT 0,
          consecutive_checkins INTEGER DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);
      
      console.log('✅ SQLite测试表创建成功');
      
      // 验证表结构
      const tables = await db.all("SELECT name FROM sqlite_master WHERE type='table'");
      console.log('📋 创建的表:', tables.map(t => t.name));
      
      // 检查checkin_records表结构
      const checkinColumns = await db.all("PRAGMA table_info(checkin_records)");
      console.log('\n📋 checkin_records表结构:');
      checkinColumns.forEach(col => {
        console.log(`  ${col.name}: ${col.type} ${col.notnull ? 'NOT NULL' : ''} ${col.dflt_value ? `DEFAULT ${col.dflt_value}` : ''}`);
      });
      
      // 检查reward_records表结构
      const rewardColumns = await db.all("PRAGMA table_info(reward_records)");
      console.log('\n📋 reward_records表结构:');
      rewardColumns.forEach(col => {
        console.log(`  ${col.name}: ${col.type} ${col.notnull ? 'NOT NULL' : ''} ${col.dflt_value ? `DEFAULT ${col.dflt_value}` : ''}`);
      });
      
      await db.close();
      console.log('\n✅ SQLite测试完成，表结构验证成功');
      console.log('\n💡 提示: 要在生产环境中使用，请确保PostgreSQL数据库正在运行');
      return;
      
    } catch (sqliteError) {
      console.error('❌ SQLite测试也失败了:', sqliteError.message);
      return;
    }
  }
  
  try {
    // 读取SQL文件
    const sqlFile = path.join(__dirname, 'create-lbs-tables.sql');
    const sqlContent = fs.readFileSync(sqlFile, 'utf8');
    
    console.log('📄 执行LBS表创建脚本...');
    
    // 执行SQL
    await pool.query(sqlContent);
    
    console.log('✅ LBS系统表创建成功!');
    
    // 验证表是否创建成功
    const result = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('checkin_records', 'reward_records', 'user_stats', 'user_locations')
      ORDER BY table_name
    `);
    
    console.log('📋 已创建的LBS表:', result.rows.map(row => row.table_name));
    
    // 检查checkin_records表结构
    const checkinStructure = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default 
      FROM information_schema.columns 
      WHERE table_name = 'checkin_records' 
      ORDER BY ordinal_position
    `);
    
    console.log('\n📋 checkin_records表结构:');
    checkinStructure.rows.forEach(col => {
      console.log(`  ${col.column_name}: ${col.data_type} ${col.is_nullable === 'NO' ? 'NOT NULL' : ''} ${col.column_default || ''}`);
    });
    
    // 检查reward_records表结构
    const rewardStructure = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default 
      FROM information_schema.columns 
      WHERE table_name = 'reward_records' 
      ORDER BY ordinal_position
    `);
    
    console.log('\n📋 reward_records表结构:');
    rewardStructure.rows.forEach(col => {
      console.log(`  ${col.column_name}: ${col.data_type} ${col.is_nullable === 'NO' ? 'NOT NULL' : ''} ${col.column_default || ''}`);
    });
    
  } catch (error) {
    console.error('❌ 创建LBS表时出错:', error.message);
    if (error.code) {
      console.error('错误代码:', error.code);
    }
  } finally {
    await pool.end();
  }
}

setupLBSTables().catch(console.error);