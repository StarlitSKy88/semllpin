#!/bin/bash

# SmellPin 监控系统部署脚本
# 作者: SmellPin Team
# 版本: 1.0.0

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
    log_info "检查系统依赖..."
    
    # 检查 Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker 未安装，请先安装 Docker"
        exit 1
    fi
    
    # 检查 Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose 未安装，请先安装 Docker Compose"
        exit 1
    fi
    
    log_success "依赖检查完成"
}

# 创建必要的目录
create_directories() {
    log_info "创建必要的目录结构..."
    
    mkdir -p data/prometheus
    mkdir -p data/grafana
    mkdir -p data/alertmanager
    mkdir -p logs
    
    # 设置权限
    chmod 755 data/prometheus
    chmod 755 data/grafana
    chmod 755 data/alertmanager
    
    log_success "目录创建完成"
}

# 配置环境变量
setup_environment() {
    log_info "配置环境变量..."
    
    # 创建 .env 文件
    cat > .env << EOF
# SmellPin 监控系统环境配置

# Grafana 配置
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=admin123
GF_USERS_ALLOW_SIGN_UP=false

# Prometheus 配置
PROMETHEUS_RETENTION_TIME=30d
PROMETHEUS_STORAGE_PATH=/prometheus

# AlertManager 配置
ALERT_SMTP_HOST=smtp.gmail.com:587
ALERT_SMTP_FROM=alerts@smellpin.com
ALERT_SMTP_USERNAME=alerts@smellpin.com
ALERT_SMTP_PASSWORD=your-email-password

# 数据库配置 (用于监控)
DB_HOST=host.docker.internal
DB_PORT=5432
DB_NAME=smellpin
DB_USER=username
DB_PASSWORD=password

# Redis 配置 (用于监控)
REDIS_HOST=host.docker.internal
REDIS_PORT=6379

# 应用配置
APP_HOST=host.docker.internal
APP_PORT=3000
EOF
    
    log_success "环境变量配置完成"
}

# 验证配置文件
validate_configs() {
    log_info "验证配置文件..."
    
    # 检查必要的配置文件
    local configs=(
        "prometheus/prometheus.yml"
        "alertmanager/alertmanager.yml"
        "blackbox/blackbox.yml"
        "grafana/datasources/prometheus.yml"
        "grafana/dashboards/dashboard.yml"
    )
    
    for config in "${configs[@]}"; do
        if [[ ! -f "$config" ]]; then
            log_error "配置文件 $config 不存在"
            exit 1
        fi
    done
    
    log_success "配置文件验证完成"
}

# 启动监控服务
start_services() {
    log_info "启动监控服务..."
    
    # 停止现有服务
    docker-compose down --remove-orphans
    
    # 拉取最新镜像
    docker-compose pull
    
    # 启动服务
    docker-compose up -d
    
    log_success "监控服务启动完成"
}

# 等待服务就绪
wait_for_services() {
    log_info "等待服务就绪..."
    
    local services=(
        "prometheus:9090"
        "grafana:3000"
        "alertmanager:9093"
        "node-exporter:9100"
    )
    
    for service in "${services[@]}"; do
        local name=$(echo $service | cut -d':' -f1)
        local port=$(echo $service | cut -d':' -f2)
        
        log_info "等待 $name 服务启动..."
        
        local retries=30
        while [[ $retries -gt 0 ]]; do
            if curl -s "http://localhost:$port" > /dev/null 2>&1; then
                log_success "$name 服务已就绪"
                break
            fi
            
            retries=$((retries - 1))
            sleep 2
        done
        
        if [[ $retries -eq 0 ]]; then
            log_warning "$name 服务启动超时，请检查日志"
        fi
    done
}

# 显示服务状态
show_status() {
    log_info "监控服务状态:"
    
    echo ""
    echo "=== 服务访问地址 ==="
    echo "Grafana:      http://localhost:3001 (admin/admin123)"
    echo "Prometheus:   http://localhost:9090"
    echo "AlertManager: http://localhost:9093"
    echo "Node Exporter: http://localhost:9100"
    echo ""
    
    echo "=== Docker 容器状态 ==="
    docker-compose ps
    echo ""
    
    echo "=== 有用的命令 ==="
    echo "查看日志: docker-compose logs -f [service_name]"
    echo "重启服务: docker-compose restart [service_name]"
    echo "停止服务: docker-compose down"
    echo "更新配置: docker-compose up -d --force-recreate"
    echo ""
}

# 健康检查
health_check() {
    log_info "执行健康检查..."
    
    local failed=0
    
    # 检查 Prometheus
    if curl -s "http://localhost:9090/-/healthy" > /dev/null; then
        log_success "Prometheus 健康检查通过"
    else
        log_error "Prometheus 健康检查失败"
        failed=1
    fi
    
    # 检查 Grafana
    if curl -s "http://localhost:3001/api/health" > /dev/null; then
        log_success "Grafana 健康检查通过"
    else
        log_error "Grafana 健康检查失败"
        failed=1
    fi
    
    # 检查 AlertManager
    if curl -s "http://localhost:9093/-/healthy" > /dev/null; then
        log_success "AlertManager 健康检查通过"
    else
        log_error "AlertManager 健康检查失败"
        failed=1
    fi
    
    if [[ $failed -eq 0 ]]; then
        log_success "所有服务健康检查通过"
    else
        log_warning "部分服务健康检查失败，请检查日志"
    fi
}

# 主函数
main() {
    echo "=== SmellPin 监控系统部署脚本 ==="
    echo ""
    
    case "${1:-deploy}" in
        "deploy")
            check_dependencies
            create_directories
            setup_environment
            validate_configs
            start_services
            wait_for_services
            health_check
            show_status
            ;;
        "start")
            start_services
            wait_for_services
            show_status
            ;;
        "stop")
            log_info "停止监控服务..."
            docker-compose down
            log_success "监控服务已停止"
            ;;
        "restart")
            log_info "重启监控服务..."
            docker-compose restart
            wait_for_services
            show_status
            ;;
        "status")
            show_status
            ;;
        "health")
            health_check
            ;;
        "logs")
            docker-compose logs -f "${2:-}"
            ;;
        "update")
            log_info "更新监控服务..."
            docker-compose pull
            docker-compose up -d --force-recreate
            wait_for_services
            show_status
            ;;
        "clean")
            log_info "清理监控数据..."
            docker-compose down -v
            sudo rm -rf data/
            log_success "监控数据已清理"
            ;;
        *)
            echo "用法: $0 {deploy|start|stop|restart|status|health|logs|update|clean}"
            echo ""
            echo "命令说明:"
            echo "  deploy  - 完整部署监控系统"
            echo "  start   - 启动监控服务"
            echo "  stop    - 停止监控服务"
            echo "  restart - 重启监控服务"
            echo "  status  - 显示服务状态"
            echo "  health  - 执行健康检查"
            echo "  logs    - 查看服务日志"
            echo "  update  - 更新监控服务"
            echo "  clean   - 清理监控数据"
            exit 1
            ;;
    esac
}

# 执行主函数
main "$@"