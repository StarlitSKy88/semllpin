const { neon } = require('@neondatabase/serverless');
const fs = require('fs');
const path = require('path');

// 读取 .dev.vars 文件
const devVarsPath = path.join(__dirname, '.dev.vars');
if (fs.existsSync(devVarsPath)) {
  const envContent = fs.readFileSync(devVarsPath, 'utf8');
  const lines = envContent.split('\n');
  
  lines.forEach(line => {
    line = line.trim();
    if (line && !line.startsWith('#') && line.includes('=')) {
      const [key, ...valueParts] = line.split('=');
      const value = valueParts.join('=');
      process.env[key] = value;
    }
  });
}

async function verifyDatabase() {
  try {
    console.log('=== 验证数据库连接和表结构 ===');
    
    if (!process.env.DATABASE_URL) {
      throw new Error('DATABASE_URL 环境变量未设置');
    }
    
    const sql = neon(process.env.DATABASE_URL);
    
    // 1. 测试数据库连接
    console.log('\n1. 测试数据库连接...');
    const connectionTest = await sql`SELECT NOW() as current_time`;
    console.log('✅ 数据库连接成功:', connectionTest[0].current_time);
    
    // 2. 检查表结构
    console.log('\n2. 检查主要表结构...');
    const tables = await sql`
      SELECT table_name, column_name, data_type, is_nullable, column_default
      FROM information_schema.columns 
      WHERE table_schema = 'public' 
        AND table_name IN ('users', 'annotations', 'lbs_rewards', 'comments', 'transactions')
      ORDER BY table_name, ordinal_position
    `;
    
    // 按表分组显示
    const tableGroups = {};
    tables.forEach(row => {
      if (!tableGroups[row.table_name]) {
        tableGroups[row.table_name] = [];
      }
      tableGroups[row.table_name].push(row);
    });
    
    Object.keys(tableGroups).forEach(tableName => {
      console.log(`\n📋 表: ${tableName}`);
      tableGroups[tableName].forEach(col => {
        console.log(`  - ${col.column_name}: ${col.data_type} ${col.is_nullable === 'NO' ? '(NOT NULL)' : '(NULLABLE)'}`);
      });
    });
    
    // 3. 检查数据统计
    console.log('\n3. 检查数据统计...');
    const userCount = await sql`SELECT COUNT(*) as count FROM users`;
    const annotationCount = await sql`SELECT COUNT(*) as count FROM annotations`;
    const rewardCount = await sql`SELECT COUNT(*) as count FROM lbs_rewards`;
    
    console.log(`📊 用户数量: ${userCount[0].count}`);
    console.log(`📊 标注数量: ${annotationCount[0].count}`);
    console.log(`📊 奖励数量: ${rewardCount[0].count}`);
    
    // 4. 检查最近的标注
    console.log('\n4. 检查最近的标注...');
    const recentAnnotations = await sql`
      SELECT a.id, a.content, a.created_at, u.username
      FROM annotations a
      JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT 3
    `;
    
    if (recentAnnotations.length > 0) {
      console.log('📝 最近的标注:');
      recentAnnotations.forEach(annotation => {
        console.log(`  - ${annotation.id}: "${annotation.content}" by ${annotation.username} (${annotation.created_at})`);
      });
    } else {
      console.log('📝 暂无标注数据');
    }
    
    console.log('\n✅ 数据库验证完成！');
    
  } catch (error) {
    console.error('❌ 数据库验证失败:', error);
    console.error('错误详情:', error.message);
    process.exit(1);
  }
}

verifyDatabase();