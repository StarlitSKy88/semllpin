// 设置Neon数据库表结构
const { neon } = require('@neondatabase/serverless');
const fs = require('fs');
const path = require('path');

// 从环境变量读取数据库URL
require('dotenv').config({ path: '.dev.vars' });

const sql = neon(process.env.DATABASE_URL);

async function setupDatabase() {
  try {
    console.log('开始设置数据库表结构...');
    
    // 读取SQL文件
    const sqlFile = path.join(__dirname, 'create-tables-neon-compatible.sql');
    const sqlContent = fs.readFileSync(sqlFile, 'utf8');
    
    // 分割SQL语句（按分号分割，但忽略注释行）
    const statements = sqlContent
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt && !stmt.startsWith('--') && !stmt.startsWith('/*'));
    
    console.log(`找到 ${statements.length} 个SQL语句`);
    
    // 逐个执行SQL语句
    for (let i = 0; i < statements.length; i++) {
      const statement = statements[i];
      if (statement) {
        try {
          console.log(`执行语句 ${i + 1}/${statements.length}...`);
          await sql(statement);
        } catch (error) {
          console.error(`执行语句 ${i + 1} 时出错:`, error.message);
          console.error('语句内容:', statement.substring(0, 100) + '...');
          // 继续执行其他语句
        }
      }
    }
    
    console.log('数据库表结构设置完成！');
    
    // 验证表是否创建成功
    const tables = await sql`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      ORDER BY table_name
    `;
    
    console.log('已创建的表:');
    tables.forEach(table => {
      console.log(`- ${table.table_name}`);
    });
    
  } catch (error) {
    console.error('设置数据库时出错:', error);
    process.exit(1);
  }
}

setupDatabase();