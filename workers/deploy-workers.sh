#!/bin/bash

# Cloudflare Workers部署脚本
echo "开始部署SmellPin后端到Cloudflare Workers..."

# 检查是否安装了wrangler
if ! command -v wrangler &> /dev/null; then
    echo "Wrangler CLI未安装，正在安装..."
    npm install -g wrangler
fi

# 检查是否已登录
echo "检查Cloudflare登录状态..."
if ! wrangler whoami &> /dev/null; then
    echo "请先登录Cloudflare:"
    echo "wrangler login"
    exit 1
fi

# 设置环境变量函数
set_secrets() {
    local env=$1
    echo "设置 $env 环境的敏感变量..."
    
    echo "请输入以下环境变量值（或按Enter跳过）:"
    
    read -p "DATABASE_URL: " database_url
    if [ ! -z "$database_url" ]; then
        echo "$database_url" | wrangler secret put DATABASE_URL --env $env
    fi
    
    read -p "JWT_SECRET: " jwt_secret
    if [ ! -z "$jwt_secret" ]; then
        echo "$jwt_secret" | wrangler secret put JWT_SECRET --env $env
    fi
    
    read -p "PAYPAL_CLIENT_ID: " paypal_client_id
    if [ ! -z "$paypal_client_id" ]; then
        echo "$paypal_client_id" | wrangler secret put PAYPAL_CLIENT_ID --env $env
    fi
    
    read -p "PAYPAL_CLIENT_SECRET: " paypal_client_secret
    if [ ! -z "$paypal_client_secret" ]; then
        echo "$paypal_client_secret" | wrangler secret put PAYPAL_CLIENT_SECRET --env $env
    fi
    
    read -p "PAYPAL_ENVIRONMENT (sandbox/live): " paypal_env
    if [ ! -z "$paypal_env" ]; then
        echo "$paypal_env" | wrangler secret put PAYPAL_ENVIRONMENT --env $env
    fi
    
    read -p "GOOGLE_MAPS_API_KEY: " google_maps_key
    if [ ! -z "$google_maps_key" ]; then
        echo "$google_maps_key" | wrangler secret put GOOGLE_MAPS_API_KEY --env $env
    fi
}

# 选择部署环境
echo "选择部署环境:"
echo "1) development"
echo "2) production"
read -p "请选择 (1-2): " choice

case $choice in
    1)
        ENV="development"
        ;;
    2)
        ENV="production"
        ;;
    *)
        echo "无效选择，默认使用development"
        ENV="development"
        ;;
esac

echo "部署到 $ENV 环境..."

# 设置环境变量
read -p "是否需要设置/更新环境变量? (y/n): " update_secrets
if [ "$update_secrets" = "y" ] || [ "$update_secrets" = "Y" ]; then
    set_secrets $ENV
fi

# 构建和部署
echo "构建项目..."
npm run build

if [ $? -ne 0 ]; then
    echo "构建失败，请检查错误信息"
    exit 1
fi

echo "部署到Cloudflare Workers..."
if [ "$ENV" = "production" ]; then
    wrangler deploy --env production
else
    wrangler deploy --env development
fi

if [ $? -eq 0 ]; then
    echo "部署成功！"
    echo "Worker URL: https://smellpin-workers$([ "$ENV" = "development" ] && echo "-dev").your-subdomain.workers.dev"
    echo "请在Cloudflare Dashboard查看部署状态"
else
    echo "部署失败，请检查错误信息"
    exit 1
fi