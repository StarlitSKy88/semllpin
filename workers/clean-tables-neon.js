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

async function cleanDatabaseTables() {
  try {
    console.log('🔄 加载环境变量...');
    const env = loadEnvVars();
    
    if (!env.DATABASE_URL) {
      throw new Error('缺少必要的DATABASE_URL配置');
    }
    
    console.log('🔄 连接到Neon PostgreSQL数据库...');
    const sql = neon(env.DATABASE_URL);
    
    console.log('🔄 开始清理数据库表...');
    
    const tables = [
      'payment_records',
      'likes', 
      'comments',
      'lbs_rewards',
      'wallets',
      'annotations',
      'users'
    ];
    
    // 删除表（按依赖关系倒序）
    for (const table of tables) {
      try {
        await sql.unsafe(`DROP TABLE IF EXISTS ${table} CASCADE`);
        console.log(`✅ 表 ${table} 删除成功`);
      } catch (error) {
        console.log(`⚠️  表 ${table} 删除失败:`, error.message);
      }
    }
    
    // 删除自定义函数
    try {
      await sql`DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE`;
      console.log('✅ 自定义函数删除成功');
    } catch (error) {
      console.log('⚠️  自定义函数删除失败:', error.message);
    }
    
    console.log('✅ 数据库表清理完成!');
    console.log('💡 现在可以运行 create-tables-neon.js 重新创建表');
    
  } catch (error) {
    console.error('❌ 清理数据库表失败:', error.message);
    console.error('详细错误:', error);
    process.exit(1);
  }
}

// 运行清理脚本
if (require.main === module) {
  cleanDatabaseTables();
}

module.exports = { cleanDatabaseTables };