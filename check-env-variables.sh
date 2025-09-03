#!/bin/bash

echo "=== SmellPin 环境变量检查 ==="
echo ""

# 检查后端环境变量
echo "1. 后端环境变量 (Cloudflare Workers)"
if [ -f "workers/.dev.vars" ]; then
    echo "  ✓ workers/.dev.vars 文件存在"
    if grep -q "DATABASE_URL=" workers/.dev.vars; then
        echo "    ✓ 数据库连接已配置"
    else
        echo "    ✗ 数据库连接未配置"
    fi
    if grep -q "PAYPAL_CLIENT_ID=" workers/.dev.vars; then
        echo "    ✓ PayPal配置已设置"
    else
        echo "    ✗ PayPal配置未设置"
    fi
else
    echo "  ✗ workers/.dev.vars 文件不存在"
fi
echo ""

# 检查前端环境变量
echo "2. 前端环境变量"
if [ -f "frontend/.env" ]; then
    echo "  ✓ frontend/.env 文件存在"
else
    echo "  ✗ frontend/.env 文件不存在"
fi

if [ -f "frontend/.env.production" ]; then
    echo "  ✓ frontend/.env.production 文件存在"
else
    echo "  ✗ frontend/.env.production 文件不存在"
fi
echo ""

# 检查部署配置文件
echo "3. 部署配置文件"
if [ -f "workers/wrangler.toml" ]; then
    echo "  ✓ Cloudflare Workers配置存在"
else
    echo "  ✗ Cloudflare Workers配置不存在"
fi

if [ -f "frontend/cloudbaserc.json" ]; then
    echo "  ✓ 腾讯云CloudBase配置存在"
else
    echo "  ✗ 腾讯云CloudBase配置不存在"
fi

if [ -f "neon-database-migration.sql" ]; then
    echo "  ✓ 数据库迁移脚本存在"
else
    echo "  ✗ 数据库迁移脚本不存在"
fi
echo ""

# 检查部署脚本
echo "4. 部署脚本"
if [ -f "setup-neon-database.sh" ]; then
    echo "  ✓ 数据库设置脚本存在"
else
    echo "  ✗ 数据库设置脚本不存在"
fi

if [ -f "workers/deploy-workers.sh" ]; then
    echo "  ✓ Workers部署脚本存在"
else
    echo "  ✗ Workers部署脚本不存在"
fi

if [ -f "frontend/deploy-cloudbase.sh" ]; then
    echo "  ✓ CloudBase部署脚本存在"
else
    echo "  ✗ CloudBase部署脚本不存在"
fi
echo ""

# 检查CLI工具
echo "5. CLI工具检查"
if command -v wrangler &> /dev/null; then
    echo "  ✓ Cloudflare Wrangler CLI已安装"
else
    echo "  ✗ Cloudflare Wrangler CLI未安装 (运行: npm install -g wrangler)"
fi

if command -v tcb &> /dev/null; then
    echo "  ✓ 腾讯云CloudBase CLI已安装"
else
    echo "  ✗ 腾讯云CloudBase CLI未安装 (运行: npm install -g @cloudbase/cli)"
fi

if command -v psql &> /dev/null; then
    echo "  ✓ PostgreSQL客户端已安装"
else
    echo "  ⚠ PostgreSQL客户端未安装 (建议安装: brew install postgresql)"
fi
echo ""

echo "=== 检查完成 ==="
echo ""
echo "下一步操作:"
echo "1. 配置环境变量 (参考 DEPLOYMENT_GUIDE.md)"
echo "2. 运行数据库迁移: ./setup-neon-database.sh"
echo "3. 部署后端: cd workers && ./deploy-workers.sh"
echo "4. 部署前端: cd frontend && ./deploy-cloudbase.sh"
echo "5. 测试部署结果"
echo ""