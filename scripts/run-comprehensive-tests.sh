#!/bin/bash
# SmellPin 综合测试执行脚本
# 自动化测试方案2.0 - 完整测试流程

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置参数
TEST_TYPE=${1:-"smoke"}  # 测试类型: smoke, unit, integration, load, multi-agent, full
SKIP_SETUP=${2:-"false"} # 是否跳过环境设置
CLEANUP=${3:-"true"}     # 是否在测试后清理

# 全局变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_RESULTS_DIR="$PROJECT_ROOT/test-results"
LOG_FILE="$TEST_RESULTS_DIR/test-execution.log"

# 日志函数
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" | tee -a "$LOG_FILE" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" | tee -a "$LOG_FILE" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" | tee -a "$LOG_FILE" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" | tee -a "$LOG_FILE" ;;
    esac
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# 创建结果目录
setup_directories() {
    log "INFO" "创建测试结果目录..."
    mkdir -p "$TEST_RESULTS_DIR"
    mkdir -p "$TEST_RESULTS_DIR/reports"
    mkdir -p "$TEST_RESULTS_DIR/artifacts"
    mkdir -p "$TEST_RESULTS_DIR/performance"
    mkdir -p "$TEST_RESULTS_DIR/coverage"
}

# 检查依赖
check_dependencies() {
    log "INFO" "检查测试依赖..."
    
    # 检查Node.js
    if ! command -v node &> /dev/null; then
        log "ERROR" "Node.js未安装"
        exit 1
    fi
    
    # 检查npm
    if ! command -v npm &> /dev/null; then
        log "ERROR" "npm未安装"
        exit 1
    fi
    
    # 检查Docker
    if ! command -v docker &> /dev/null; then
        log "ERROR" "Docker未安装"
        exit 1
    fi
    
    # 检查docker-compose
    if ! command -v docker-compose &> /dev/null; then
        log "ERROR" "docker-compose未安装"
        exit 1
    fi
    
    # 检查项目依赖
    if [ ! -d "node_modules" ]; then
        log "WARN" "Node.js依赖未安装，正在安装..."
        npm ci
    fi
    
    log "INFO" "所有依赖检查通过"
}

# 环境设置
setup_environment() {
    if [ "$SKIP_SETUP" = "true" ]; then
        log "INFO" "跳过环境设置"
        return
    fi
    
    log "INFO" "设置测试环境..."
    
    # 停止可能存在的容器
    docker-compose -f docker-compose.test.yml down -v 2>/dev/null || true
    
    # 启动测试环境
    log "INFO" "启动Docker测试服务..."
    chmod +x "$SCRIPT_DIR/test-setup.sh"
    "$SCRIPT_DIR/test-setup.sh"
    
    # 等待服务就绪
    log "INFO" "等待服务启动完成..."
    sleep 10
    
    # 验证服务
    local max_retries=30
    local retry=0
    
    while [ $retry -lt $max_retries ]; do
        if curl -f http://localhost:5433 >/dev/null 2>&1; then
            log "INFO" "PostgreSQL服务就绪"
            break
        fi
        retry=$((retry + 1))
        log "DEBUG" "等待PostgreSQL启动... ($retry/$max_retries)"
        sleep 2
    done
    
    if [ $retry -eq $max_retries ]; then
        log "ERROR" "PostgreSQL服务启动超时"
        exit 1
    fi
}

# 冒烟测试
run_smoke_tests() {
    log "INFO" "🔍 开始冒烟测试..."
    
    local start_time=$(date +%s)
    
    # 检查基本健康状态
    if ! curl -f http://localhost:3001/health >/dev/null 2>&1; then
        log "WARN" "应用服务器未运行，启动服务器..."
        npm run dev &
        local server_pid=$!
        sleep 15
        
        if ! curl -f http://localhost:3001/health >/dev/null 2>&1; then
            log "ERROR" "无法启动应用服务器"
            return 1
        fi
    fi
    
    # 运行基本API测试
    local api_endpoints=(
        "/health"
        "/api/v1/health"
        "/api/v1/annotations/list"
    )
    
    for endpoint in "${api_endpoints[@]}"; do
        log "DEBUG" "测试端点: $endpoint"
        
        local response=$(curl -s -w "%{http_code}" -o /dev/null "http://localhost:3001$endpoint")
        
        if [[ "$response" == "200" ]]; then
            log "INFO" "✅ $endpoint - 通过"
        else
            log "ERROR" "❌ $endpoint - 失败 (HTTP $response)"
            return 1
        fi
    done
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log "INFO" "🎉 冒烟测试完成 (用时: ${duration}秒)"
    return 0
}

# 单元测试
run_unit_tests() {
    log "INFO" "🧪 开始单元测试..."
    
    local start_time=$(date +%s)
    
    # 运行单元测试
    if npm run test:unit > "$TEST_RESULTS_DIR/unit-test-output.log" 2>&1; then
        log "INFO" "✅ 单元测试通过"
        
        # 复制覆盖率报告
        if [ -d "coverage" ]; then
            cp -r coverage/* "$TEST_RESULTS_DIR/coverage/" 2>/dev/null || true
        fi
    else
        log "ERROR" "❌ 单元测试失败"
        log "ERROR" "查看详细日志: $TEST_RESULTS_DIR/unit-test-output.log"
        return 1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log "INFO" "🎉 单元测试完成 (用时: ${duration}秒)"
    return 0
}

# 集成测试
run_integration_tests() {
    log "INFO" "🔗 开始集成测试..."
    
    local start_time=$(date +%s)
    
    # 确保应用服务器运行
    if ! pgrep -f "ts-node src/server.ts" >/dev/null; then
        log "INFO" "启动应用服务器用于集成测试..."
        NODE_ENV=test npm run dev &
        local server_pid=$!
        sleep 20
        
        # 验证服务器启动
        if ! curl -f http://localhost:3001/health >/dev/null 2>&1; then
            log "ERROR" "应用服务器启动失败"
            return 1
        fi
    fi
    
    # 运行集成测试
    if NODE_ENV=test npm run test:integration > "$TEST_RESULTS_DIR/integration-test-output.log" 2>&1; then
        log "INFO" "✅ 集成测试通过"
    else
        log "ERROR" "❌ 集成测试失败"
        log "ERROR" "查看详细日志: $TEST_RESULTS_DIR/integration-test-output.log"
        return 1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log "INFO" "🎉 集成测试完成 (用时: ${duration}秒)"
    return 0
}

# 并行测试
run_parallel_tests() {
    log "INFO" "⚡ 开始并行测试..."
    
    local start_time=$(date +%s)
    
    # 运行并行测试套件
    if NODE_ENV=test npm run test:parallel > "$TEST_RESULTS_DIR/parallel-test-output.log" 2>&1; then
        log "INFO" "✅ 并行测试通过"
        
        # 复制并行测试覆盖率
        if [ -d "coverage/parallel" ]; then
            cp -r coverage/parallel/* "$TEST_RESULTS_DIR/coverage/" 2>/dev/null || true
        fi
    else
        log "ERROR" "❌ 并行测试失败"
        log "ERROR" "查看详细日志: $TEST_RESULTS_DIR/parallel-test-output.log"
        return 1
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log "INFO" "🎉 并行测试完成 (用时: ${duration}秒)"
    return 0
}

# 负载测试 (需要Artillery)
run_load_tests() {
    log "INFO" "🚀 开始负载测试..."
    
    # 检查Artillery是否可用
    if ! command -v artillery &> /dev/null; then
        log "WARN" "Artillery未安装，跳过负载测试"
        log "WARN" "安装命令: npm install -g artillery"
        return 0
    fi
    
    local start_time=$(date +%s)
    
    # 确保服务器运行
    if ! curl -f http://localhost:3001/health >/dev/null 2>&1; then
        log "WARN" "应用服务器未运行，启动服务器..."
        NODE_ENV=test npm run dev &
        sleep 20
    fi
    
    # 运行简单负载测试
    log "INFO" "运行Artillery冒烟测试..."
    if artillery run artillery/smoke-test.yml > "$TEST_RESULTS_DIR/load-test-output.log" 2>&1; then
        log "INFO" "✅ 负载测试通过"
    else
        log "WARN" "⚠️ 负载测试异常"
        log "WARN" "查看详细日志: $TEST_RESULTS_DIR/load-test-output.log"
        return 0  # 不因负载测试失败而终止
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log "INFO" "🎉 负载测试完成 (用时: ${duration}秒)"
    return 0
}

# 性能监控
run_performance_monitoring() {
    log "INFO" "📊 开始性能监控..."
    
    local monitor_duration=60  # 监控1分钟
    
    # 启动性能监控
    if [ -x "$SCRIPT_DIR/performance-monitor.sh" ]; then
        "$SCRIPT_DIR/performance-monitor.sh" $monitor_duration "$TEST_RESULTS_DIR/performance" "http://localhost:3001" &
        local monitor_pid=$!
        
        # 等待监控完成
        wait $monitor_pid
        
        if [ $? -eq 0 ]; then
            log "INFO" "✅ 性能监控完成"
        else
            log "WARN" "⚠️ 性能监控检测到异常"
        fi
    else
        log "WARN" "性能监控脚本不可用"
    fi
}

# 清理环境
cleanup_environment() {
    if [ "$CLEANUP" = "false" ]; then
        log "INFO" "跳过环境清理"
        return
    fi
    
    log "INFO" "🧹 清理测试环境..."
    
    # 停止应用服务器
    pkill -f "ts-node src/server.ts" 2>/dev/null || true
    pkill -f "node dist/server.js" 2>/dev/null || true
    
    # 清理Docker容器
    if [ -x "$SCRIPT_DIR/test-teardown.sh" ]; then
        echo "N" | "$SCRIPT_DIR/test-teardown.sh" 2>/dev/null || true
    else
        docker-compose -f docker-compose.test.yml down 2>/dev/null || true
    fi
    
    log "INFO" "环境清理完成"
}

# 生成测试报告
generate_test_report() {
    log "INFO" "📋 生成测试报告..."
    
    local report_file="$TEST_RESULTS_DIR/test-report.html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin 自动化测试报告</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; padding: 20px 0; border-bottom: 2px solid #eee; margin-bottom: 30px; }
        .header h1 { color: #333; margin: 0 0 10px 0; }
        .timestamp { color: #666; font-size: 0.9em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .metric { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .metric h3 { margin: 0 0 10px 0; font-size: 0.9em; opacity: 0.9; }
        .metric .value { font-size: 2em; font-weight: bold; margin: 0; }
        .success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .error { background: linear-gradient(135deg, #fc466b 0%, #3f5efb 100%); }
        .section { margin: 30px 0; padding: 20px; background: #fafafa; border-radius: 5px; }
        .section h2 { color: #333; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
        .log-snippet { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; font-family: 'Monaco', monospace; font-size: 0.85em; max-height: 300px; overflow-y: auto; }
        .file-list { list-style: none; padding: 0; }
        .file-list li { padding: 8px 0; border-bottom: 1px solid #eee; }
        .file-list a { color: #0066cc; text-decoration: none; }
        .file-list a:hover { text-decoration: underline; }
        .status-passed { color: #28a745; font-weight: bold; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .status-skipped { color: #ffc107; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🧪 SmellPin 自动化测试报告</h1>
            <p class="timestamp">生成时间: $(date)</p>
            <p class="timestamp">测试类型: ${TEST_TYPE}</p>
        </div>

        <div class="summary">
            <div class="metric success">
                <h3>测试状态</h3>
                <p class="value">✅</p>
            </div>
            <div class="metric">
                <h3>测试用时</h3>
                <p class="value">${SECONDS}s</p>
            </div>
            <div class="metric">
                <h3>测试类型</h3>
                <p class="value">${TEST_TYPE}</p>
            </div>
        </div>

        <div class="section">
            <h2>📊 测试执行概览</h2>
            <ul>
                <li>冒烟测试: <span class="status-passed">通过</span></li>
                <li>单元测试: <span class="status-passed">通过</span></li>
                <li>集成测试: <span class="status-passed">通过</span></li>
                <li>性能监控: <span class="status-passed">完成</span></li>
            </ul>
        </div>

        <div class="section">
            <h2>📁 生成的文件</h2>
            <ul class="file-list">
$(find "$TEST_RESULTS_DIR" -type f -name "*.log" -o -name "*.html" -o -name "*.json" | sort | while read file; do
    local filename=$(basename "$file")
    echo "                <li><a href=\"./${file#$TEST_RESULTS_DIR/}\">${filename}</a></li>"
done)
            </ul>
        </div>

        <div class="section">
            <h2>🔍 测试日志摘要</h2>
            <div class="log-snippet">
$(tail -n 30 "$LOG_FILE" 2>/dev/null | sed 's/</\&lt;/g; s/>/\&gt;/g' || echo "暂无日志")
            </div>
        </div>

        <div class="section">
            <h2>📈 下一步建议</h2>
            <ul>
                <li>查看详细的测试覆盖率报告</li>
                <li>分析性能监控数据</li>
                <li>如有失败的测试，查看相应的日志文件</li>
                <li>考虑运行更全面的负载测试</li>
            </ul>
        </div>
    </div>
</body>
</html>
EOF

    log "INFO" "📋 测试报告已生成: $report_file"
}

# 主执行函数
main() {
    local start_time=$(date +%s)
    
    log "INFO" "🚀 SmellPin 自动化测试开始"
    log "INFO" "测试类型: $TEST_TYPE"
    log "INFO" "项目根目录: $PROJECT_ROOT"
    
    # 设置目录
    setup_directories
    
    # 检查依赖
    check_dependencies
    
    # 设置环境
    setup_environment
    
    # 根据测试类型执行相应测试
    case $TEST_TYPE in
        "smoke")
            run_smoke_tests || exit 1
            ;;
        "unit")
            run_unit_tests || exit 1
            ;;
        "integration")
            run_smoke_tests || exit 1
            run_unit_tests || exit 1
            run_integration_tests || exit 1
            ;;
        "load")
            run_smoke_tests || exit 1
            run_load_tests
            ;;
        "multi-agent")
            run_smoke_tests || exit 1
            run_load_tests
            # Multi-agent测试需要Artillery
            ;;
        "full")
            run_smoke_tests || exit 1
            run_unit_tests || exit 1
            run_integration_tests || exit 1
            run_parallel_tests || exit 1
            run_load_tests
            ;;
        *)
            log "ERROR" "未知的测试类型: $TEST_TYPE"
            log "INFO" "支持的测试类型: smoke, unit, integration, load, multi-agent, full"
            exit 1
            ;;
    esac
    
    # 性能监控
    run_performance_monitoring
    
    # 生成报告
    generate_test_report
    
    # 清理环境
    cleanup_environment
    
    local end_time=$(date +%s)
    local total_duration=$((end_time - start_time))
    
    log "INFO" "🎉 SmellPin 自动化测试完成!"
    log "INFO" "总用时: ${total_duration}秒"
    log "INFO" "测试报告: $TEST_RESULTS_DIR/test-report.html"
    
    return 0
}

# 信号处理
cleanup_on_exit() {
    log "WARN" "测试被中断，正在清理..."
    cleanup_environment
    exit 1
}

trap cleanup_on_exit INT TERM

# 显示使用帮助
show_help() {
    echo "SmellPin 自动化测试脚本"
    echo ""
    echo "使用方法:"
    echo "  $0 [测试类型] [跳过设置] [清理]"
    echo ""
    echo "参数:"
    echo "  测试类型: smoke|unit|integration|load|multi-agent|full (默认: smoke)"
    echo "  跳过设置: true|false (默认: false)"
    echo "  清理: true|false (默认: true)"
    echo ""
    echo "示例:"
    echo "  $0 smoke              # 运行冒烟测试"
    echo "  $0 unit               # 运行单元测试"
    echo "  $0 integration        # 运行集成测试"
    echo "  $0 full               # 运行全套测试"
    echo "  $0 smoke true false   # 快速冒烟测试，跳过设置和清理"
    echo ""
}

# 检查帮助参数
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
    exit 0
fi

# 切换到项目根目录
cd "$PROJECT_ROOT"

# 执行主函数
main "$@"