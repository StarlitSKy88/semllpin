#!/bin/bash

# SmellPin 快速开发启动脚本
# 使用方法: ./start-dev.sh

set -e

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

echo "🚀 SmellPin 快速开发启动"
echo "========================"
echo ""

# 检查Node.js
if ! command -v node >/dev/null 2>&1; then
    log_error "Node.js 未安装，请先安装 Node.js 18+"
    echo "安装方法:"
    echo "1. 访问 https://nodejs.org 下载安装"
    echo "2. 或使用 Homebrew: brew install node"
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    log_warning "Node.js 版本过低 (当前: $(node -v))，建议使用 18+"
fi

# 检查npm
if ! command -v npm >/dev/null 2>&1; then
    log_error "npm 未安装"
    exit 1
fi

log_info "Node.js 版本: $(node -v)"
log_info "npm 版本: $(npm -v)"
echo ""

# 检查环境变量文件
if [ ! -f ".env" ]; then
    log_warning "未找到.env文件，复制.env.example"
    cp .env.example .env
    log_success "已创建 .env 文件"
fi

# 安装依赖
log_info "检查并安装依赖..."

if [ ! -d "node_modules" ]; then
    log_info "安装后端依赖..."
    npm install
else
    log_info "后端依赖已存在，跳过安装"
fi

if [ ! -d "frontend/node_modules" ]; then
    log_info "安装前端依赖..."
    cd frontend && npm install && cd ..
else
    log_info "前端依赖已存在，跳过安装"
fi

# 设置数据库
log_info "设置SQLite数据库..."
if [ ! -f "smellpin.sqlite" ]; then
    npm run migrate
    log_success "数据库初始化完成"
else
    log_info "数据库已存在，运行迁移..."
    npm run migrate
fi

echo ""
log_success "🎉 开发环境准备完成！"
echo ""
echo "📋 启动服务："
echo "   后端服务: npm run dev"
echo "   前端服务: cd frontend && npm run dev"
echo ""
echo "🌐 访问地址："
echo "   前端: http://localhost:5173"
echo "   后端: http://localhost:3000"
echo "   API文档: http://localhost:3000/api-docs"
echo ""
echo "💡 提示："
echo "   - 使用 Ctrl+C 停止服务"
echo "   - 修改代码会自动重载"
echo "   - 数据库文件: smellpin.sqlite"
echo ""

# 询问是否立即启动
read -p "是否立即启动开发服务？(y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "启动开发服务..."
    echo ""
    echo "🔥 启动后端服务 (端口 3000)..."
    
    # 在后台启动后端
    npm run dev &
    BACKEND_PID=$!
    
    # 等待后端启动
    sleep 3
    
    echo "🎨 启动前端服务 (端口 5173)..."
    echo "按 Ctrl+C 停止所有服务"
    echo ""
    
    # 启动前端（前台运行）
    cd frontend
    
    # 设置陷阱来清理后台进程
    trap 'echo "\n🛑 停止服务..."; kill $BACKEND_PID 2>/dev/null; exit' INT
    
    npm run dev
else
    echo "手动启动服务："
    echo "1. 终端1: npm run dev"
    echo "2. 终端2: cd frontend && npm run dev"
fi