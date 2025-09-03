#!/bin/bash

# SmellPin 快速开发启动脚本
# 用于快速启动前端和后端开发服务器

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

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    if ! command -v node &> /dev/null; then
        log_error "Node.js 未安装，请先安装 Node.js"
        exit 1
    fi
    
    if ! command -v npm &> /dev/null; then
        log_error "npm 未安装，请先安装 npm"
        exit 1
    fi
    
    log_success "依赖检查完成"
}

# 安装依赖
install_dependencies() {
    log_info "安装后端依赖..."
    npm install
    
    log_info "安装前端依赖..."
    cd frontend
    npm install
    cd ..
    
    log_success "依赖安装完成"
}

# 启动开发服务器
start_dev_servers() {
    log_info "启动开发服务器..."
    
    # 启动后端服务器
    log_info "启动后端服务器 (端口 3000)..."
    npm run dev &
    BACKEND_PID=$!
    
    # 等待后端启动
    sleep 3
    
    # 启动前端服务器
    log_info "启动前端服务器 (端口 5173)..."
    cd frontend
    npm run dev &
    FRONTEND_PID=$!
    cd ..
    
    # 保存进程ID
    echo $BACKEND_PID > .backend.pid
    echo $FRONTEND_PID > .frontend.pid
    
    log_success "开发服务器启动完成！"
    log_info "后端服务器: http://localhost:3000"
    log_info "前端服务器: http://localhost:5173"
    log_info "按 Ctrl+C 停止服务器"
    
    # 等待用户中断
    trap 'kill_servers' INT
    wait
}

# 停止服务器
kill_servers() {
    log_info "正在停止服务器..."
    
    if [ -f .backend.pid ]; then
        BACKEND_PID=$(cat .backend.pid)
        kill $BACKEND_PID 2>/dev/null || true
        rm .backend.pid
    fi
    
    if [ -f .frontend.pid ]; then
        FRONTEND_PID=$(cat .frontend.pid)
        kill $FRONTEND_PID 2>/dev/null || true
        rm .frontend.pid
    fi
    
    log_success "服务器已停止"
    exit 0
}

# 主函数
main() {
    log_info "SmellPin 快速开发启动脚本"
    log_info "=============================="
    
    check_dependencies
    
    # 检查是否需要安装依赖
    if [ ! -d "node_modules" ] || [ ! -d "frontend/node_modules" ]; then
        install_dependencies
    fi
    
    start_dev_servers
}

# 运行主函数
main "$@"