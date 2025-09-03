const { neon } = require('@neondatabase/serverless');
const fs = require('fs');
const path = require('path');

// 加载环境变量
function loadEnvVars() {
  const envPath = path.join(__dirname, '.dev.vars');
  if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    const lines = envContent.split('\n');
    
    lines.forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine && !trimmedLine.startsWith('#')) {
        const [key, ...valueParts] = trimmedLine.split('=');
        if (key && valueParts.length > 0) {
          const value = valueParts.join('=').replace(/^["']|["']$/g, '');
          process.env[key] = value;
        }
      }
    });
  }
}

// 加载环境变量
loadEnvVars();

// 数据库连接
const sql = neon(process.env.DATABASE_URL);

async function cleanupOldTables() {
  console.log('🧹 清理旧的数据库表...');
  
  try {
    // 删除旧表（如果存在）
    const tablesToDrop = [
      'checkin_records',
      'reward_records', 
      'user_locations',
      'user_stats',
      'nearby_users',
      'location_hotspots',
      'user_wallets',
      'wallets',
      'transactions'
    ];
    
    for (const table of tablesToDrop) {
      try {
        await sql.unsafe(`DROP TABLE IF EXISTS ${table} CASCADE`);
        console.log(`✅ 删除表: ${table}`);
      } catch (error) {
        console.log(`⚠️  删除表 ${table} 失败:`, error.message);
      }
    }
    
    console.log('✅ 旧表清理完成');
    
  } catch (error) {
    console.error('❌ 清理旧表失败:', error.message);
    throw error;
  }
}

async function recreateTables() {
  console.log('🔧 重新创建LBS数据库表...');
  
  try {
    // 创建签到记录表
    await sql`
      CREATE TABLE checkin_records (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        latitude DECIMAL(10, 8) NOT NULL,
        longitude DECIMAL(11, 8) NOT NULL,
        location_name VARCHAR(255),
        accuracy DECIMAL(10, 2),
        points_earned INTEGER DEFAULT 0,
        is_first_time BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建奖励记录表
    await sql`
      CREATE TABLE reward_records (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        reward_type VARCHAR(50) NOT NULL,
        reward_category VARCHAR(50),
        points INTEGER NOT NULL,
        description TEXT,
        source_id INTEGER,
        source_type VARCHAR(50),
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        status VARCHAR(20) DEFAULT 'pending',
        claimed_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    // 创建钱包表
    await sql`
      CREATE TABLE wallets (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        currency VARCHAR(10) DEFAULT 'usd',
        balance DECIMAL(15, 2) DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, currency)
      )
    `;
    
    // 创建交易记录表
    await sql`
      CREATE TABLE transactions (
        id SERIAL PRIMARY KEY,
        user_id UUID NOT NULL,
        type VARCHAR(50) NOT NULL,
        amount DECIMAL(15, 2) NOT NULL,
        currency VARCHAR(10) DEFAULT 'usd',
        status VARCHAR(20) DEFAULT 'pending',
        completed_at TIMESTAMP,
        description TEXT,
        metadata JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    
    console.log('✅ LBS数据库表重新创建完成');
    
  } catch (error) {
    console.error('❌ 重新创建表失败:', error.message);
    throw error;
  }
}

async function main() {
  try {
    console.log('🚀 开始清理和重建数据库表...');
    console.log('==================================================');
    
    await cleanupOldTables();
    await recreateTables();
    
    console.log('==================================================');
    console.log('🎉 数据库表清理和重建完成！');
    
  } catch (error) {
    console.error('❌ 执行失败:', error.message);
    process.exit(1);
  }
}

main();