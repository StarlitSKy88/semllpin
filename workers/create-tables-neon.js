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

async function createDatabaseTables() {
  try {
    console.log('🔄 加载环境变量...');
    const env = loadEnvVars();
    
    if (!env.DATABASE_URL) {
      throw new Error('缺少必要的DATABASE_URL配置');
    }
    
    console.log('🔄 连接到Neon PostgreSQL数据库...');
    const sql = neon(env.DATABASE_URL);
    
    console.log('🔄 启用必要的扩展...');
    // 启用PostGIS扩展用于地理位置功能
    try {
      await sql`CREATE EXTENSION IF NOT EXISTS postgis`;
      console.log('✅ PostGIS扩展启用成功');
    } catch (error) {
      console.log('⚠️  PostGIS扩展启用失败:', error.message);
    }
    
    // 启用UUID生成扩展
    try {
      await sql`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`;
      console.log('✅ UUID扩展启用成功');
    } catch (error) {
      console.log('⚠️  UUID扩展启用失败:', error.message);
    }
    
    console.log('🔄 开始创建数据库表...');
    
    // 创建用户表
    console.log('🔄 创建users表...');
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          email VARCHAR(255) UNIQUE NOT NULL,
          username VARCHAR(50) UNIQUE NOT NULL,
          display_name VARCHAR(100),
          bio TEXT,
          avatar_url TEXT,
          university VARCHAR(100),
          role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'moderator', 'admin')),
          status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
          email_verified BOOLEAN DEFAULT false,
          last_login_at TIMESTAMP WITH TIME ZONE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;
      console.log('✅ users表创建成功');
      
      // 为users表创建索引
      await sql`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)`;
      console.log('✅ users表索引创建成功');
      
    } catch (error) {
      console.log('⚠️  users表创建失败:', error.message);
    }
    
    // 创建标注表（使用PostGIS几何类型）
    console.log('🔄 创建annotations表...');
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS annotations (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL,
          latitude DECIMAL(10, 8) NOT NULL,
          longitude DECIMAL(11, 8) NOT NULL,
          location GEOGRAPHY(POINT, 4326) GENERATED ALWAYS AS (ST_SetSRID(ST_MakePoint(longitude, latitude), 4326)) STORED,
          smell_intensity INTEGER NOT NULL CHECK (smell_intensity BETWEEN 1 AND 10),
          description TEXT,
          country VARCHAR(2),
          region VARCHAR(100),
          city VARCHAR(100),
          address TEXT,
          status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'hidden', 'deleted')),
          payment_amount DECIMAL(10, 2) NOT NULL,
          payment_id VARCHAR(255),
          media_files JSONB DEFAULT '[]',
          view_count INTEGER DEFAULT 0,
          like_count INTEGER DEFAULT 0,
          comment_count INTEGER DEFAULT 0,
          current_reward_pool DECIMAL(10, 2) DEFAULT 0,
          total_cleanup_time INTEGER DEFAULT 0,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;
      console.log('✅ annotations表创建成功');
      
      // 为annotations表创建索引
      await sql`CREATE INDEX IF NOT EXISTS idx_annotations_user_id ON annotations(user_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_annotations_status ON annotations(status)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_annotations_created_at ON annotations(created_at)`;
      
      try {
        await sql`CREATE INDEX IF NOT EXISTS idx_annotations_location ON annotations USING GIST(location)`;
        console.log('✅ PostGIS空间索引创建成功');
      } catch (indexError) {
        console.log('⚠️  PostGIS空间索引创建失败:', indexError.message);
      }
      
      await sql`CREATE INDEX IF NOT EXISTS idx_annotations_coordinates ON annotations(latitude, longitude)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_annotations_intensity ON annotations(smell_intensity)`;
      console.log('✅ annotations表基本索引创建成功');
      
    } catch (error) {
      console.log('⚠️  annotations表创建失败:', error.message);
    }
    
    // 创建LBS奖励表
    console.log('🔄 创建lbs_rewards表...');
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS lbs_rewards (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL,
          annotation_id UUID NOT NULL,
          start_time TIMESTAMP WITH TIME ZONE NOT NULL,
          end_time TIMESTAMP WITH TIME ZONE,
          duration_minutes INTEGER DEFAULT 0,
          reward_amount DECIMAL(10, 2) DEFAULT 0.00,
          participants_count INTEGER DEFAULT 1,
          status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'completed', 'cancelled')),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;
      console.log('✅ lbs_rewards表创建成功');
      
      // 为lbs_rewards表创建索引
      await sql`CREATE INDEX IF NOT EXISTS idx_lbs_rewards_user_id ON lbs_rewards(user_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_lbs_rewards_annotation_id ON lbs_rewards(annotation_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_lbs_rewards_status ON lbs_rewards(status)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_lbs_rewards_start_time ON lbs_rewards(start_time)`;
      console.log('✅ lbs_rewards表索引创建成功');
      
    } catch (error) {
      console.log('⚠️  lbs_rewards表创建失败:', error.message);
    }
    
    // 创建钱包表
    console.log('🔄 创建wallets表...');
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS wallets (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL UNIQUE,
          balance DECIMAL(10, 2) DEFAULT 0.00,
          total_earned DECIMAL(10, 2) DEFAULT 0.00,
          total_spent DECIMAL(10, 2) DEFAULT 0.00,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;
      console.log('✅ wallets表创建成功');
      
      // 为wallets表创建索引
      await sql`CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id)`;
      console.log('✅ wallets表索引创建成功');
      
    } catch (error) {
      console.log('⚠️  wallets表创建失败:', error.message);
    }
    
    // 创建评论表（新增）
    console.log('🔄 创建comments表...');
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS comments (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL,
          annotation_id UUID NOT NULL,
          content TEXT NOT NULL,
          status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'hidden', 'deleted')),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;
      console.log('✅ comments表创建成功');
      
      // 为comments表创建索引
      await sql`CREATE INDEX IF NOT EXISTS idx_comments_annotation_id ON comments(annotation_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_comments_status ON comments(status)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_comments_created_at ON comments(created_at)`;
      console.log('✅ comments表索引创建成功');
      
    } catch (error) {
      console.log('⚠️  comments表创建失败:', error.message);
    }
    
    // 创建点赞表（新增）
    console.log('🔄 创建likes表...');
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS likes (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL,
          annotation_id UUID NOT NULL,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          UNIQUE(user_id, annotation_id)
        )
      `;
      console.log('✅ likes表创建成功');
      
      // 为likes表创建索引
      await sql`CREATE INDEX IF NOT EXISTS idx_likes_annotation_id ON likes(annotation_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_likes_user_id ON likes(user_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_likes_user_annotation ON likes(user_id, annotation_id)`;
      console.log('✅ likes表索引创建成功');
      
    } catch (error) {
      console.log('⚠️  likes表创建失败:', error.message);
    }
    
    // 创建支付记录表（新增）
    console.log('🔄 创建payment_records表...');
    try {
      await sql`
        CREATE TABLE IF NOT EXISTS payment_records (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL,
          annotation_id UUID,
          payment_id VARCHAR(255) NOT NULL,
          payment_method VARCHAR(50) NOT NULL, -- 'stripe', 'paypal'
          payment_type VARCHAR(50) NOT NULL, -- 'annotation', 'reward_withdrawal'
          amount DECIMAL(10, 2) NOT NULL,
          currency VARCHAR(3) DEFAULT 'USD',
          status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'cancelled', 'refunded')),
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;
      console.log('✅ payment_records表创建成功');
      
      // 为payment_records表创建索引
      await sql`CREATE INDEX IF NOT EXISTS idx_payment_records_user_id ON payment_records(user_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_payment_records_payment_id ON payment_records(payment_id)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_payment_records_status ON payment_records(status)`;
      await sql`CREATE INDEX IF NOT EXISTS idx_payment_records_created_at ON payment_records(created_at)`;
      console.log('✅ payment_records表索引创建成功');
      
    } catch (error) {
      console.log('⚠️  payment_records表创建失败:', error.message);
    }
    
    // 添加外键约束
    console.log('🔄 添加外键约束...');
    const foreignKeys = [
      { name: 'fk_annotations_user_id', sql: 'ALTER TABLE annotations ADD CONSTRAINT fk_annotations_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' },
      { name: 'fk_lbs_rewards_user_id', sql: 'ALTER TABLE lbs_rewards ADD CONSTRAINT fk_lbs_rewards_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' },
      { name: 'fk_lbs_rewards_annotation_id', sql: 'ALTER TABLE lbs_rewards ADD CONSTRAINT fk_lbs_rewards_annotation_id FOREIGN KEY (annotation_id) REFERENCES annotations(id) ON DELETE CASCADE' },
      { name: 'fk_wallets_user_id', sql: 'ALTER TABLE wallets ADD CONSTRAINT fk_wallets_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' },
      { name: 'fk_comments_user_id', sql: 'ALTER TABLE comments ADD CONSTRAINT fk_comments_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' },
      { name: 'fk_comments_annotation_id', sql: 'ALTER TABLE comments ADD CONSTRAINT fk_comments_annotation_id FOREIGN KEY (annotation_id) REFERENCES annotations(id) ON DELETE CASCADE' },
      { name: 'fk_likes_user_id', sql: 'ALTER TABLE likes ADD CONSTRAINT fk_likes_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' },
      { name: 'fk_likes_annotation_id', sql: 'ALTER TABLE likes ADD CONSTRAINT fk_likes_annotation_id FOREIGN KEY (annotation_id) REFERENCES annotations(id) ON DELETE CASCADE' },
      { name: 'fk_payment_records_user_id', sql: 'ALTER TABLE payment_records ADD CONSTRAINT fk_payment_records_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE' },
      { name: 'fk_payment_records_annotation_id', sql: 'ALTER TABLE payment_records ADD CONSTRAINT fk_payment_records_annotation_id FOREIGN KEY (annotation_id) REFERENCES annotations(id) ON DELETE SET NULL' }
    ];
    
    for (const fk of foreignKeys) {
      try {
        // 检查约束是否已存在
        const exists = await sql`
          SELECT 1 FROM information_schema.table_constraints 
          WHERE constraint_name = ${fk.name} AND table_name IN ('annotations', 'lbs_rewards', 'wallets', 'comments', 'likes', 'payment_records')
        `;
        
        if (exists.length === 0) {
          await sql.unsafe(fk.sql);
          console.log(`✅ 外键约束 ${fk.name} 添加成功`);
        } else {
          console.log(`⚠️  外键约束 ${fk.name} 已存在，跳过`);
        }
      } catch (error) {
        console.log(`⚠️  外键约束 ${fk.name} 添加失败:`, error.message);
      }
    }
    
    // 创建触发器用于自动更新updated_at字段
    console.log('🔄 创建更新时间戳触发器...');
    try {
      await sql`
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
          NEW.updated_at = NOW();
          RETURN NEW;
        END;
        $$ language 'plpgsql'
      `;
      
      // 为需要的表添加触发器
      await sql`DROP TRIGGER IF EXISTS update_users_updated_at ON users`;
      await sql`CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`;
      
      await sql`DROP TRIGGER IF EXISTS update_annotations_updated_at ON annotations`;
      await sql`CREATE TRIGGER update_annotations_updated_at BEFORE UPDATE ON annotations FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`;
      
      await sql`DROP TRIGGER IF EXISTS update_wallets_updated_at ON wallets`;
      await sql`CREATE TRIGGER update_wallets_updated_at BEFORE UPDATE ON wallets FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`;
      
      await sql`DROP TRIGGER IF EXISTS update_comments_updated_at ON comments`;
      await sql`CREATE TRIGGER update_comments_updated_at BEFORE UPDATE ON comments FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`;
      
      await sql`DROP TRIGGER IF EXISTS update_payment_records_updated_at ON payment_records`;
      await sql`CREATE TRIGGER update_payment_records_updated_at BEFORE UPDATE ON payment_records FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()`;
      
      console.log('✅ 更新时间戳触发器创建成功');
    } catch (error) {
      console.log('⚠️  更新时间戳触发器创建失败:', error.message);
    }
    
    console.log('✅ 数据库表创建完成!');
    console.log('📊 创建的表:');
    console.log('  - users: 用户表');
    console.log('  - annotations: 气味标注表 (包含PostGIS地理位置支持)');
    console.log('  - lbs_rewards: LBS奖励表');
    console.log('  - wallets: 用户钱包表');
    console.log('  - comments: 评论表');
    console.log('  - likes: 点赞表');
    console.log('  - payment_records: 支付记录表');
    console.log('🔗 外键约束和索引已正确设置');
    console.log('⚡ 自动更新时间戳触发器已启用');
    
  } catch (error) {
    console.error('❌ 创建数据库表失败:', error.message);
    console.error('详细错误:', error);
    process.exit(1);
  }
}

// 运行创建表脚本
if (require.main === module) {
  createDatabaseTables();
}

module.exports = { createDatabaseTables };