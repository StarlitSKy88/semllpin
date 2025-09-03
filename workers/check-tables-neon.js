const fs = require('fs');
const path = require('path');
const { neon } = require('@neondatabase/serverless');

// 从 .dev.vars 文件读取配置
function loadEnvVars() {
  const envPath = path.join(__dirname, '.dev.vars');
  const envContent = fs.readFileSync(envPath, 'utf8');
  const env = {};
  
  envContent.split('\n').forEach(line => {
    if (line.trim() && !line.startsWith('#')) {
      const [key, ...valueParts] = line.split('=');
      if (key && valueParts.length > 0) {
        env[key.trim()] = valueParts.join('=').trim();
      }
    }
  });
  
  return env;
}

async function checkDatabaseTables() {
  try {
    console.log('🔄 加载环境变量...');
    const env = loadEnvVars();
    
    if (!env.DATABASE_URL) {
      throw new Error('缺少必要的DATABASE_URL配置');
    }
    
    console.log('🔄 连接到Neon PostgreSQL数据库...');
    const sql = neon(env.DATABASE_URL);
    
    console.log('🔄 检查数据库表状态...');
    
    // 检查所有表
    const tables = await sql`
      SELECT table_name, table_type 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
      ORDER BY table_name
    `;
    
    console.log('📊 现有数据表:');
    for (const table of tables) {
      console.log(`  - ${table.table_name} (${table.table_type})`);
    }
    
    // 检查annotations表的字段
    if (tables.some(t => t.table_name === 'annotations')) {
      console.log('\n🔍 annotations表字段详情:');
      const columns = await sql`
        SELECT column_name, data_type, is_nullable, column_default 
        FROM information_schema.columns 
        WHERE table_name = 'annotations' AND table_schema = 'public'
        ORDER BY ordinal_position
      `;
      
      for (const col of columns) {
        console.log(`  - ${col.column_name}: ${col.data_type} ${col.is_nullable === 'NO' ? 'NOT NULL' : 'NULL'} ${col.column_default ? `DEFAULT ${col.column_default}` : ''}`);
      }
    }
    
    // 检查索引
    console.log('\n🔍 数据库索引:');
    const indexes = await sql`
      SELECT schemaname, tablename, indexname, indexdef 
      FROM pg_indexes 
      WHERE schemaname = 'public'
      ORDER BY tablename, indexname
    `;
    
    for (const idx of indexes) {
      if (!idx.indexname.includes('_pkey')) { // 跳过主键索引
        console.log(`  - ${idx.tablename}.${idx.indexname}`);
      }
    }
    
    // 检查外键约束
    console.log('\n🔍 外键约束:');
    const constraints = await sql`
      SELECT 
        tc.constraint_name,
        tc.table_name,
        kcu.column_name,
        ccu.table_name AS foreign_table_name,
        ccu.column_name AS foreign_column_name
      FROM information_schema.table_constraints AS tc 
      JOIN information_schema.key_column_usage AS kcu
        ON tc.constraint_name = kcu.constraint_name
        AND tc.table_schema = kcu.table_schema
      JOIN information_schema.constraint_column_usage AS ccu
        ON ccu.constraint_name = tc.constraint_name
        AND ccu.table_schema = tc.table_schema
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema = 'public'
      ORDER BY tc.table_name, tc.constraint_name
    `;
    
    for (const constraint of constraints) {
      console.log(`  - ${constraint.table_name}.${constraint.column_name} -> ${constraint.foreign_table_name}.${constraint.foreign_column_name}`);
    }
    
    // 检查PostGIS扩展
    console.log('\n🔍 数据库扩展:');
    const extensions = await sql`SELECT extname FROM pg_extension ORDER BY extname`;
    for (const ext of extensions) {
      console.log(`  - ${ext.extname}`);
    }
    
    console.log('\n✅ 数据库检查完成!');
    
  } catch (error) {
    console.error('❌ 检查数据库表失败:', error.message);
    console.error('详细错误:', error);
    process.exit(1);
  }
}

// 运行检查脚本
if (require.main === module) {
  checkDatabaseTables();
}

module.exports = { checkDatabaseTables };