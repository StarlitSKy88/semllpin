#!/bin/bash

# Neon PostgreSQL数据库设置脚本
echo "开始设置Neon PostgreSQL数据库..."

# 检查是否安装了psql
if ! command -v psql &> /dev/null; then
    echo "PostgreSQL客户端未安装，正在安装..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install postgresql
        else
            echo "请先安装Homebrew，然后运行: brew install postgresql"
            exit 1
        fi
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        sudo apt-get update
        sudo apt-get install postgresql-client
    else
        echo "请手动安装PostgreSQL客户端"
        exit 1
    fi
fi

# 读取数据库连接信息
echo "请输入Neon数据库连接信息:"
read -p "数据库URL (格式: postgresql://user:password@host:port/database): " DATABASE_URL

if [ -z "$DATABASE_URL" ]; then
    echo "数据库URL不能为空"
    exit 1
fi

# 验证数据库连接
echo "测试数据库连接..."
psql "$DATABASE_URL" -c "SELECT version();" > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "数据库连接失败，请检查连接信息"
    exit 1
fi

echo "数据库连接成功！"

# 执行迁移脚本
echo "执行数据库迁移..."
psql "$DATABASE_URL" -f neon-database-migration.sql

if [ $? -eq 0 ]; then
    echo "数据库迁移完成！"
else
    echo "数据库迁移失败，请检查错误信息"
    exit 1
fi

# 验证表创建
echo "验证表结构..."
psql "$DATABASE_URL" -c "\dt" | grep -E "users|annotations|comments|payments"

if [ $? -eq 0 ]; then
    echo "表结构验证成功！"
else
    echo "表结构验证失败"
    exit 1
fi

# 更新环境变量文件
echo "更新环境变量..."

# 更新workers/.dev.vars
if [ -f "workers/.dev.vars" ]; then
    # 备份原文件
    cp workers/.dev.vars workers/.dev.vars.backup
    
    # 更新DATABASE_URL
    if grep -q "DATABASE_URL=" workers/.dev.vars; then
        sed -i.bak "s|DATABASE_URL=.*|DATABASE_URL=$DATABASE_URL|" workers/.dev.vars
    else
        echo "DATABASE_URL=$DATABASE_URL" >> workers/.dev.vars
    fi
    
    echo "已更新 workers/.dev.vars"
fi

# 更新前端环境变量（如果需要）
if [ -f "frontend/.env.production" ]; then
    echo "前端生产环境配置已存在"
fi

echo "Neon数据库设置完成！"
echo "数据库URL已保存到环境变量文件中"
echo "请确保在部署时正确设置所有环境变量"

# 显示下一步操作
echo ""
echo "下一步操作:"
echo "1. 部署Cloudflare Workers: cd workers && ./deploy-workers.sh"
echo "2. 部署前端到CloudBase: cd frontend && ./deploy-cloudbase.sh"
echo "3. 测试跨平台连接"
echo ""