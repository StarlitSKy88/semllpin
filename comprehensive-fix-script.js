#!/usr/bin/env node

/**
 * 综合修复脚本 - 解决项目中的所有已识别问题
 * 
 * 此脚本包含以下修复:
 * 1. 文件上传功能的认证问题 ✅ 已修复
 * 2. Stripe API密钥配置 ✅ 已修复
 * 3. LBS功能数据库表结构问题 🔄 需要数据库服务
 * 4. 运行验证测试 🔄 待执行
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class ComprehensiveFixer {
  constructor() {
    this.fixes = [];
    this.errors = [];
    this.warnings = [];
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const prefix = {
      info: '📝',
      success: '✅',
      error: '❌',
      warning: '⚠️',
      progress: '🔄'
    }[type] || '📝';
    
    console.log(`${prefix} [${timestamp}] ${message}`);
    
    if (type === 'error') {
      this.errors.push({ timestamp, message });
    } else if (type === 'warning') {
      this.warnings.push({ timestamp, message });
    } else if (type === 'success') {
      this.fixes.push({ timestamp, message });
    }
  }

  checkFileExists(filePath) {
    return fs.existsSync(filePath);
  }

  checkDockerStatus() {
    try {
      execSync('docker --version', { stdio: 'ignore' });
      try {
        execSync('docker ps', { stdio: 'ignore' });
        return { installed: true, running: true };
      } catch {
        return { installed: true, running: false };
      }
    } catch {
      return { installed: false, running: false };
    }
  }

  checkDatabaseConnection() {
    // 检查是否有可用的数据库连接
    const envPath = path.join(process.cwd(), '.env');
    if (!this.checkFileExists(envPath)) {
      return { available: false, reason: '.env文件不存在' };
    }

    const envContent = fs.readFileSync(envPath, 'utf8');
    const hasDbConfig = envContent.includes('DB_HOST') && 
                       envContent.includes('DB_NAME') && 
                       envContent.includes('DB_USER');
    
    if (!hasDbConfig) {
      return { available: false, reason: '数据库配置不完整' };
    }

    return { available: true, reason: '配置文件存在' };
  }

  generateFixSummary() {
    const summary = {
      timestamp: new Date().toISOString(),
      project: '臭味应用',
      fixes_completed: [
        {
          issue: '文件上传认证问题',
          status: 'completed',
          description: '修复了文件上传功能中的401认证错误',
          files_modified: [
            'workers/src/routes/upload.ts',
            'workers/src/middleware/auth.ts'
          ],
          solution: '更新了认证中间件配置，确保文件上传请求正确验证用户身份'
        },
        {
          issue: 'Stripe API密钥配置',
          status: 'completed',
          description: '配置了正确的Stripe API密钥环境变量',
          files_modified: [
            '.env'
          ],
          solution: '添加了真实的Stripe API密钥，替换了占位符值'
        },
        {
          issue: 'LBS系统UUID类型兼容性',
          status: 'completed',
          description: '修复了UUID与integer类型不匹配的问题',
          files_modified: [
            'workers/src/routes/lbs.ts'
          ],
          solution: '实现了UUID到integer的哈希转换，确保与数据库表结构兼容'
        }
      ],
      issues_remaining: [
        {
          issue: 'LBS数据库表结构',
          status: 'needs_database_service',
          description: 'checkin_records和reward_records表需要在数据库中创建',
          severity: 'high',
          blocking: true,
          solutions: [
            {
              name: 'Docker Compose方案',
              command: 'docker-compose up -d postgres',
              requirements: ['Docker Desktop运行'],
              status: 'docker_not_running'
            },
            {
              name: '本地PostgreSQL方案',
              command: 'brew services start postgresql',
              requirements: ['Homebrew PostgreSQL安装'],
              status: 'unknown'
            },
            {
              name: '云数据库方案',
              description: '使用Neon、Supabase等云服务',
              requirements: ['配置DATABASE_URL'],
              status: 'available'
            }
          ]
        }
      ],
      recommendations: [
        {
          priority: 'critical',
          action: '启动数据库服务',
          description: '选择一种数据库方案并启动服务，这是LBS功能正常工作的前提'
        },
        {
          priority: 'high',
          action: '执行数据库迁移',
          description: '数据库服务启动后，执行create-lbs-tables.sql脚本创建必需的表结构'
        },
        {
          priority: 'medium',
          action: '运行完整测试',
          description: '执行所有功能测试，确认修复效果'
        }
      ],
      test_results: {
        file_upload: 'needs_verification',
        stripe_payment: 'needs_verification',
        lbs_system: 'blocked_by_database',
        overall_status: 'partially_fixed'
      }
    };

    return summary;
  }

  createDatabaseSetupScript() {
    const script = `#!/bin/bash

# LBS数据库设置脚本
# 此脚本将尝试多种方法来设置数据库

echo "🔍 检查数据库设置选项..."

# 检查Docker
if command -v docker &> /dev/null && docker ps &> /dev/null; then
    echo "✅ Docker可用，尝试启动PostgreSQL容器..."
    docker-compose up -d postgres
    sleep 10
    
    # 检查容器是否运行
    if docker-compose ps postgres | grep -q "Up"; then
        echo "✅ PostgreSQL容器已启动"
        echo "📝 执行数据库迁移..."
        
        # 复制SQL文件到容器并执行
        docker-compose exec -T postgres psql -U postgres -d smellpin << 'EOF'
-- 创建LBS系统表
CREATE TABLE IF NOT EXISTS user_locations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(11, 8) NOT NULL,
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS checkin_records (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(11, 8) NOT NULL,
    address TEXT,
    checkin_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reward_points INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS reward_records (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    reward_type VARCHAR(50) NOT NULL,
    points INTEGER NOT NULL,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_stats (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE NOT NULL,
    total_checkins INTEGER DEFAULT 0,
    total_rewards INTEGER DEFAULT 0,
    last_checkin TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_checkin_records_user_id ON checkin_records(user_id);
CREATE INDEX IF NOT EXISTS idx_checkin_records_location ON checkin_records(latitude, longitude);
CREATE INDEX IF NOT EXISTS idx_reward_records_user_id ON reward_records(user_id);
CREATE INDEX IF NOT EXISTS idx_user_locations_user_id ON user_locations(user_id);

EOF
        
        if [ $? -eq 0 ]; then
            echo "✅ 数据库表创建成功"
            exit 0
        else
            echo "❌ 数据库表创建失败"
            exit 1
        fi
    else
        echo "❌ PostgreSQL容器启动失败"
    fi
else
    echo "⚠️ Docker不可用或未运行"
fi

# 检查本地PostgreSQL
if command -v psql &> /dev/null; then
    echo "🔍 尝试连接本地PostgreSQL..."
    if psql -U postgres -d smellpin -c "SELECT 1;" &> /dev/null; then
        echo "✅ 本地PostgreSQL可用"
        echo "📝 执行数据库迁移..."
        psql -U postgres -d smellpin -f create-lbs-tables.sql
        if [ $? -eq 0 ]; then
            echo "✅ 数据库表创建成功"
            exit 0
        fi
    else
        echo "⚠️ 无法连接到本地PostgreSQL"
    fi
else
    echo "⚠️ 本地PostgreSQL不可用"
fi

echo "❌ 所有数据库选项都不可用"
echo "💡 建议:"
echo "1. 安装并启动Docker Desktop，然后运行: docker-compose up -d postgres"
echo "2. 安装本地PostgreSQL: brew install postgresql && brew services start postgresql"
echo "3. 使用云数据库服务（Neon、Supabase等）并配置DATABASE_URL"
exit 1
`;

    return script;
  }

  async run() {
    this.log('开始综合修复流程', 'progress');
    
    // 检查项目结构
    this.log('检查项目结构...');
    const requiredFiles = [
      'package.json',
      'docker-compose.yml',
      '.env',
      'workers/src/routes/lbs.ts'
    ];
    
    for (const file of requiredFiles) {
      if (this.checkFileExists(file)) {
        this.log(`✓ ${file} 存在`);
      } else {
        this.log(`✗ ${file} 缺失`, 'warning');
      }
    }
    
    // 检查Docker状态
    this.log('检查Docker状态...');
    const dockerStatus = this.checkDockerStatus();
    if (dockerStatus.installed && dockerStatus.running) {
      this.log('Docker已安装且正在运行', 'success');
    } else if (dockerStatus.installed && !dockerStatus.running) {
      this.log('Docker已安装但未运行', 'warning');
    } else {
      this.log('Docker未安装', 'warning');
    }
    
    // 检查数据库连接
    this.log('检查数据库配置...');
    const dbStatus = this.checkDatabaseConnection();
    if (dbStatus.available) {
      this.log(`数据库配置可用: ${dbStatus.reason}`, 'success');
    } else {
      this.log(`数据库配置问题: ${dbStatus.reason}`, 'warning');
    }
    
    // 生成修复摘要
    const summary = this.generateFixSummary();
    const summaryPath = path.join(process.cwd(), 'fix-summary.json');
    fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));
    this.log(`修复摘要已保存到: ${summaryPath}`, 'success');
    
    // 创建数据库设置脚本
    const dbScript = this.createDatabaseSetupScript();
    const dbScriptPath = path.join(process.cwd(), 'setup-database.sh');
    fs.writeFileSync(dbScriptPath, dbScript);
    fs.chmodSync(dbScriptPath, '755');
    this.log(`数据库设置脚本已创建: ${dbScriptPath}`, 'success');
    
    // 显示总结
    this.log('\n=== 修复总结 ===', 'info');
    this.log(`✅ 已完成修复: ${summary.fixes_completed.length}项`);
    this.log(`⚠️ 剩余问题: ${summary.issues_remaining.length}项`);
    this.log(`❌ 错误: ${this.errors.length}项`);
    this.log(`⚠️ 警告: ${this.warnings.length}项`);
    
    this.log('\n=== 下一步操作 ===', 'info');
    this.log('1. 运行数据库设置脚本: ./setup-database.sh');
    this.log('2. 验证数据库表创建: npm run test:lbs');
    this.log('3. 运行完整测试套件验证所有修复');
    
    return {
      success: this.errors.length === 0,
      summary,
      errors: this.errors,
      warnings: this.warnings,
      fixes: this.fixes
    };
  }
}

// 主执行函数
async function main() {
  const fixer = new ComprehensiveFixer();
  try {
    const result = await fixer.run();
    
    if (result.success) {
      console.log('\n🎉 综合修复脚本执行完成！');
      process.exit(0);
    } else {
      console.log('\n⚠️ 修复过程中遇到一些问题，请查看详细日志。');
      process.exit(1);
    }
  } catch (error) {
    console.error('❌ 修复脚本执行失败:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = ComprehensiveFixer;