#!/bin/bash

# SmellPin 生产环境部署脚本
# 使用方法: ./scripts/deploy.sh [environment]
# 环境选项: staging, production

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查参数
ENVIRONMENT=${1:-staging}
if [[ "$ENVIRONMENT" != "staging" && "$ENVIRONMENT" != "production" ]]; then
    log_error "无效的环境参数: $ENVIRONMENT"
    log_info "使用方法: ./scripts/deploy.sh [staging|production]"
    exit 1
fi

log_info "开始部署到 $ENVIRONMENT 环境..."

# 检查必要的工具
check_dependencies() {
    log_info "检查部署依赖..."
    
    local deps=("node" "npm" "git" "docker")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "缺少依赖: $dep"
            exit 1
        fi
    done
    
    log_success "所有依赖检查通过"
}

# 检查环境变量
check_environment() {
    log_info "检查环境配置..."
    
    local env_file=".env.$ENVIRONMENT"
    if [[ ! -f "$env_file" ]]; then
        log_error "环境配置文件不存在: $env_file"
        exit 1
    fi
    
    # 检查关键环境变量
    source "$env_file"
    local required_vars=("DATABASE_URL" "JWT_SECRET" "REDIS_URL")
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            log_error "缺少必要的环境变量: $var"
            exit 1
        fi
    done
    
    log_success "环境配置检查通过"
}

# 代码质量检查
run_quality_checks() {
    log_info "运行代码质量检查..."
    
    # TypeScript 类型检查
    log_info "运行 TypeScript 类型检查..."
    npm run type-check || {
        log_error "TypeScript 类型检查失败"
        exit 1
    }
    
    # ESLint 检查
    log_info "运行 ESLint 检查..."
    npm run lint || {
        log_error "ESLint 检查失败"
        exit 1
    }
    
    # 单元测试
    log_info "运行单元测试..."
    npm run test || {
        log_error "单元测试失败"
        exit 1
    }
    
    log_success "代码质量检查通过"
}

# 构建应用
build_application() {
    log_info "构建应用..."
    
    # 清理之前的构建
    rm -rf dist build
    
    # 安装依赖
    log_info "安装生产依赖..."
    npm ci --only=production
    
    # 构建后端
    log_info "构建后端应用..."
    npm run build
    
    # 构建前端
    if [[ -d "frontend" ]]; then
        log_info "构建前端应用..."
        cd frontend
        npm ci --only=production
        npm run build
        cd ..
    fi
    
    log_success "应用构建完成"
}

# 数据库迁移
run_migrations() {
    log_info "运行数据库迁移..."
    
    # 检查数据库连接
    npm run db:check || {
        log_error "数据库连接失败"
        exit 1
    }
    
    # 运行迁移
    npm run db:migrate || {
        log_error "数据库迁移失败"
        exit 1
    }
    
    log_success "数据库迁移完成"
}

# Docker 部署
deploy_with_docker() {
    log_info "使用 Docker 部署..."
    
    local image_name="smellpin-$ENVIRONMENT"
    local container_name="smellpin-$ENVIRONMENT"
    
    # 构建 Docker 镜像
    log_info "构建 Docker 镜像..."
    docker build -t "$image_name:latest" -f "docker/Dockerfile.$ENVIRONMENT" .
    
    # 停止旧容器
    if docker ps -q -f name="$container_name" | grep -q .; then
        log_info "停止旧容器..."
        docker stop "$container_name"
        docker rm "$container_name"
    fi
    
    # 启动新容器
    log_info "启动新容器..."
    docker run -d \
        --name "$container_name" \
        --env-file ".env.$ENVIRONMENT" \
        -p 3000:3000 \
        -p 3001:3001 \
        --restart unless-stopped \
        "$image_name:latest"
    
    log_success "Docker 部署完成"
}

# Cloudflare Workers 部署
deploy_to_cloudflare() {
    log_info "部署到 Cloudflare Workers..."
    
    # 检查 Wrangler CLI
    if ! command -v wrangler &> /dev/null; then
        log_error "Wrangler CLI 未安装"
        log_info "请运行: npm install -g wrangler"
        exit 1
    fi
    
    # 部署到 Cloudflare Workers
    if [[ "$ENVIRONMENT" == "production" ]]; then
        wrangler publish --env production
    else
        wrangler publish --env staging
    fi
    
    log_success "Cloudflare Workers 部署完成"
}

# Vercel 前端部署
deploy_frontend_to_vercel() {
    if [[ -d "frontend" ]]; then
        log_info "部署前端到 Vercel..."
        
        cd frontend
        
        # 检查 Vercel CLI
        if ! command -v vercel &> /dev/null; then
            log_error "Vercel CLI 未安装"
            log_info "请运行: npm install -g vercel"
            exit 1
        fi
        
        # 部署到 Vercel
        if [[ "$ENVIRONMENT" == "production" ]]; then
            vercel --prod
        else
            vercel
        fi
        
        cd ..
        log_success "前端部署到 Vercel 完成"
    fi
}

# 健康检查
health_check() {
    log_info "执行健康检查..."
    
    local health_url
    if [[ "$ENVIRONMENT" == "production" ]]; then
        health_url="https://api.smellpin.com/health"
    else
        health_url="https://api-staging.smellpin.com/health"
    fi
    
    # 等待服务启动
    sleep 30
    
    # 检查健康状态
    local max_attempts=10
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log_info "健康检查尝试 $attempt/$max_attempts..."
        
        # 检查基础健康状态
        if curl -f -s "$health_url" > /dev/null; then
            # 检查详细健康状态
            local health_response=$(curl -s "$health_url" | jq -r '.data.status' 2>/dev/null || echo "unknown")
            
            if [[ "$health_response" == "healthy" ]]; then
                log_success "健康检查通过 - 系统健康"
                return 0
            elif [[ "$health_response" == "degraded" ]]; then
                log_warning "健康检查通过 - 系统降级但功能正常"
                return 0
            else
                log_warning "健康检查返回: $health_response"
            fi
        fi
        
        sleep 10
        ((attempt++))
    done
    
    log_error "健康检查失败"
    return 1
}

# 详细健康检查
detailed_health_check() {
    local base_url="$1"
    
    log_info "执行详细健康检查..."
    
    # 检查各个健康检查端点
    local endpoints=("health" "health/simple" "health/ready" "health/live")
    
    for endpoint in "${endpoints[@]}"; do
        local full_url="$base_url/$endpoint"
        log_info "检查 $full_url"
        
        local response=$(curl -s -w "HTTP_CODE:%{http_code}" "$full_url" 2>/dev/null)
        local http_code=$(echo "$response" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
        local body=$(echo "$response" | sed 's/HTTP_CODE:[0-9]*$//')
        
        if [[ "$http_code" == "200" ]]; then
            log_success "✓ $endpoint: OK"
            if command -v jq &> /dev/null && echo "$body" | jq . &> /dev/null; then
                echo "$body" | jq .
            fi
        else
            log_warning "✗ $endpoint: HTTP $http_code"
        fi
        echo
    done
    
    # 检查系统信息
    log_info "检查系统信息..."
    local info_response=$(curl -s "$base_url/health/info" 2>/dev/null)
    if command -v jq &> /dev/null && echo "$info_response" | jq . &> /dev/null; then
        echo "$info_response" | jq '.data'
    fi
}

# 发送部署通知
send_notification() {
    local status=$1
    local message
    
    if [[ "$status" == "success" ]]; then
        message="✅ SmellPin $ENVIRONMENT 环境部署成功"
    else
        message="❌ SmellPin $ENVIRONMENT 环境部署失败"
    fi
    
    log_info "发送部署通知..."
    
    # 这里可以集成钉钉、企业微信、Slack 等通知服务
    # 示例：钉钉 Webhook
    if [[ -n "$DINGTALK_WEBHOOK" ]]; then
        curl -X POST "$DINGTALK_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d "{
                \"msgtype\": \"text\",
                \"text\": {
                    \"content\": \"$message\\n时间: $(date)\\n版本: $(git rev-parse --short HEAD)\\n环境: $ENVIRONMENT\"
                }
            }"
    fi
}

# 回滚函数
rollback() {
    log_warning "开始回滚..."
    
    # 这里实现回滚逻辑
    # 可以恢复到上一个稳定版本
    
    log_info "回滚功能待实现"
}

# 主部署流程
main() {
    local start_time=$(date +%s)
    
    log_info "=== SmellPin 部署开始 ==="
    log_info "环境: $ENVIRONMENT"
    log_info "时间: $(date)"
    log_info "版本: $(git rev-parse --short HEAD)"
    
    # 执行部署步骤
    check_dependencies
    check_environment
    run_quality_checks
    build_application
    run_migrations
    
    # 根据环境选择部署方式
    case "$ENVIRONMENT" in
        "staging")
            deploy_with_docker
            ;;
        "production")
            deploy_to_cloudflare
            deploy_frontend_to_vercel
            ;;
    esac
    
    # 健康检查
    if health_check; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_success "=== 部署成功完成 ==="
        log_info "总耗时: ${duration}秒"
        
        send_notification "success"
    else
        log_error "=== 部署失败 ==="
        send_notification "failure"
        
        # 询问是否回滚
        read -p "是否执行回滚? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rollback
        fi
        
        exit 1
    fi
}

# 捕获中断信号
trap 'log_error "部署被中断"; exit 1' INT TERM

# 执行主函数
main "$@"