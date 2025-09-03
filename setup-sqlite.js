#!/usr/bin/env node

// SmellPin SQLite 数据库设置脚本
// 用于快速开发环境设置，无需 Docker

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🚀 开始设置 SmellPin SQLite 开发环境...');

// 检查是否安装了必要的依赖
try {
  require('sqlite3');
  console.log('✅ SQLite3 依赖已安装');
} catch (error) {
  console.log('📦 安装 SQLite3 依赖...');
  try {
    execSync('npm install sqlite3', { stdio: 'inherit' });
    console.log('✅ SQLite3 依赖安装完成');
  } catch (installError) {
    console.error('❌ SQLite3 依赖安装失败:', installError.message);
    process.exit(1);
  }
}

// 创建 SQLite 配置文件
const sqliteKnexConfig = `const path = require('path');
require('dotenv').config();

module.exports = {
  development: {
    client: 'sqlite3',
    connection: {
      filename: path.join(__dirname, 'smellpin.sqlite')
    },
    useNullAsDefault: true,
    migrations: {
      directory: './migrations',
      tableName: 'knex_migrations',
    },
    seeds: {
      directory: './seeds',
    },
  },
  
  production: {
    client: 'postgresql',
    connection: {
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    },
    pool: {
      min: 2,
      max: 10,
    },
    migrations: {
      directory: './migrations',
      tableName: 'knex_migrations',
    },
    seeds: {
      directory: './seeds',
    },
  },
};
`;

// 备份原始 knexfile.js
if (fs.existsSync('knexfile.js')) {
  fs.copyFileSync('knexfile.js', 'knexfile.postgres.js');
  console.log('✅ 原始 PostgreSQL 配置已备份为 knexfile.postgres.js');
}

// 写入 SQLite 配置
fs.writeFileSync('knexfile.js', sqliteKnexConfig);
console.log('✅ SQLite 配置已写入 knexfile.js');

// 更新 .env 文件以使用内存 Redis（如果没有 Redis）
let envContent = fs.readFileSync('.env', 'utf8');
if (!envContent.includes('REDIS_MOCK=true')) {
  envContent += '\n# SQLite 开发模式\nREDIS_MOCK=true\n';
  fs.writeFileSync('.env', envContent);
  console.log('✅ 已启用 Redis 模拟模式');
}

// 运行迁移
console.log('📊 运行数据库迁移...');
try {
  execSync('npx knex migrate:latest', { stdio: 'inherit' });
  console.log('✅ 数据库迁移完成');
} catch (error) {
  console.error('❌ 数据库迁移失败:', error.message);
  process.exit(1);
}

// 可选：运行种子数据
const readline = require('readline');
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question('🌱 是否要加载测试数据？(y/N): ', (answer) => {
  if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
    console.log('🌱 加载测试数据...');
    try {
      execSync('npx knex seed:run', { stdio: 'inherit' });
      console.log('✅ 测试数据加载完成');
    } catch (error) {
      console.error('❌ 测试数据加载失败:', error.message);
    }
  }
  
  console.log('');
  console.log('🎉 SQLite 开发环境设置完成！');
  console.log('');
  console.log('📋 环境信息:');
  console.log('   数据库: SQLite (smellpin.sqlite)');
  console.log('   Redis: 模拟模式');
  console.log('');
  console.log('🚀 现在可以启动后端服务器:');
  console.log('   npm run dev');
  console.log('');
  console.log('🔄 切换回 PostgreSQL:');
  console.log('   cp knexfile.postgres.js knexfile.js');
  console.log('');
  
  rl.close();
});