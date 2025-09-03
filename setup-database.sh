#!/bin/bash

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
