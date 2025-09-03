#!/bin/bash
# SmellPin 测试执行器 - 增强版
# 支持多种测试场景和实时监控

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置
TEST_TYPE=${1:-"smoke"}
ENABLE_DASHBOARD=${2:-"true"}
PARALLEL_WORKERS=${3:-4}
REPORT_DIR="./test-results"
DATE_STAMP=$(date '+%Y%m%d-%H%M%S')

# 显示横幅
show_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║           🧪 SmellPin 测试执行器 2.0             ║"
    echo "║                  多代理并发测试                   ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${PURPLE}📅 执行时间: $(date)${NC}"
    echo -e "${PURPLE}🔧 测试类型: ${TEST_TYPE}${NC}"
    echo -e "${PURPLE}📊 仪表盘: ${ENABLE_DASHBOARD}${NC}"
    echo -e "${PURPLE}⚡ 并发数: ${PARALLEL_WORKERS}${NC}"
    echo
}

# 日志函数
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%H:%M:%S')
    
    case $level in
        "INFO")  echo -e "${GREEN}[${timestamp}] ℹ️  ${message}${NC}" ;;
        "WARN")  echo -e "${YELLOW}[${timestamp}] ⚠️  ${message}${NC}" ;;
        "ERROR") echo -e "${RED}[${timestamp}] ❌ ${message}${NC}" ;;
        "DEBUG") echo -e "${BLUE}[${timestamp}] 🔍 ${message}${NC}" ;;
        "SUCCESS") echo -e "${GREEN}[${timestamp}] ✅ ${message}${NC}" ;;
    esac
}

# 检查依赖
check_dependencies() {
    log "INFO" "检查系统依赖..."
    
    local required_tools=("node" "npm" "docker" "curl" "jq")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log "ERROR" "缺少必要工具: ${missing_tools[*]}"
        exit 1
    fi
    
    # 检查Node.js版本
    local node_version=$(node -v | sed 's/v//')
    local major_version=$(echo $node_version | cut -d. -f1)
    
    if [ "$major_version" -lt 18 ]; then
        log "ERROR" "Node.js版本过低，需要18+，当前: $node_version"
        exit 1
    fi
    
    log "SUCCESS" "所有依赖检查通过"
}

# 设置测试环境
setup_test_environment() {
    log "INFO" "设置测试环境..."
    
    # 创建报告目录
    mkdir -p "$REPORT_DIR"
    mkdir -p "$REPORT_DIR/logs"
    mkdir -p "$REPORT_DIR/reports"
    mkdir -p "$REPORT_DIR/artifacts"
    
    # 安装依赖
    if [ ! -d "node_modules" ]; then
        log "INFO" "安装Node.js依赖..."
        npm ci
    fi
    
    # 构建项目
    log "INFO" "构建项目..."
    npm run build
    
    log "SUCCESS" "测试环境设置完成"
}

# 启动仪表盘
start_dashboard() {
    if [ "$ENABLE_DASHBOARD" = "true" ]; then
        log "INFO" "启动测试仪表盘..."
        
        # 检查端口是否被占用
        if lsof -i :3333 >/dev/null 2>&1; then
            log "WARN" "端口3333已被占用，尝试杀死现有进程..."
            pkill -f "dashboard-server.ts" || true
            sleep 2
        fi
        
        # 启动仪表盘服务器
        npx ts-node tests/dashboard/dashboard-server.ts 3333 "$REPORT_DIR" &
        DASHBOARD_PID=$!
        echo $DASHBOARD_PID > "$REPORT_DIR/dashboard.pid"
        
        # 等待仪表盘启动
        local timeout=10
        while [ $timeout -gt 0 ]; do
            if curl -f http://localhost:3333 >/dev/null 2>&1; then
                log "SUCCESS" "测试仪表盘已启动: http://localhost:3333"
                break
            fi
            sleep 1
            timeout=$((timeout-1))
        done
        
        if [ $timeout -eq 0 ]; then
            log "WARN" "仪表盘启动超时，继续执行测试..."
        fi
    fi
}

# 执行测试
run_tests() {
    log "INFO" "开始执行测试套件: $TEST_TYPE"
    
    case $TEST_TYPE in
        "smoke")
            run_smoke_tests
            ;;
        "parallel")
            run_parallel_tests
            ;;
        "comprehensive")
            run_comprehensive_tests
            ;;
        "multi-agent")
            run_multi_agent_tests
            ;;
        "performance")
            run_performance_tests
            ;;
        "all")
            run_all_tests
            ;;
        *)
            log "ERROR" "未知的测试类型: $TEST_TYPE"
            show_help
            exit 1
            ;;
    esac
}

# 冒烟测试
run_smoke_tests() {
    log "INFO" "执行冒烟测试..."
    
    # 启动基础服务
    ./scripts/test-setup.sh
    
    # 等待服务就绪
    wait_for_services
    
    # 执行冒烟测试场景
    npx ts-node tests/parallel/multi-agent-simulator.ts smoke 2>&1 | tee "$REPORT_DIR/logs/smoke-test.log"
    
    log "SUCCESS" "冒烟测试完成"
}

# 并行测试
run_parallel_tests() {
    log "INFO" "执行并行测试..."
    
    # 启动测试环境
    ./scripts/test-setup.sh
    
    # 等待服务就绪
    wait_for_services
    
    # 并行执行多个场景
    local scenarios=("smoke" "full")
    local pids=()
    
    for scenario in "${scenarios[@]}"; do
        log "INFO" "启动场景: $scenario"
        (
            npx ts-node tests/parallel/multi-agent-simulator.ts "$scenario" \
                2>&1 | tee "$REPORT_DIR/logs/parallel-${scenario}.log"
        ) &
        pids+=($!)
    done
    
    # 等待所有场景完成
    local failed_count=0
    for pid in "${pids[@]}"; do
        if ! wait $pid; then
            failed_count=$((failed_count + 1))
        fi
    done
    
    if [ $failed_count -eq 0 ]; then
        log "SUCCESS" "所有并行测试场景通过"
    else
        log "ERROR" "$failed_count 个并行测试场景失败"
        return 1
    fi
}

# 综合测试
run_comprehensive_tests() {
    log "INFO" "执行综合测试套件..."
    
    # 启动完整测试环境
    ./scripts/test-setup.sh
    
    # 等待服务就绪
    wait_for_services
    
    # 执行综合测试
    npx ts-node tests/comprehensive/comprehensive-test-runner.ts comprehensive \
        2>&1 | tee "$REPORT_DIR/logs/comprehensive-test.log"
    
    log "SUCCESS" "综合测试完成"
}

# 多代理测试
run_multi_agent_tests() {
    log "INFO" "执行多代理用户行为模拟..."
    
    # 启动测试环境
    ./scripts/test-setup.sh
    
    # 等待服务就绪
    wait_for_services
    
    # 执行多代理测试
    local agent_counts=(5 10 20)
    
    for count in "${agent_counts[@]}"; do
        log "INFO" "运行 $count 个代理的测试..."
        
        # 修改配置文件中的代理数量
        npx ts-node tests/parallel/multi-agent-simulator.ts full \
            2>&1 | tee "$REPORT_DIR/logs/multi-agent-${count}.log"
        
        # 等待系统恢复
        sleep 10
    done
    
    log "SUCCESS" "多代理测试完成"
}

# 性能测试
run_performance_tests() {
    log "INFO" "执行性能测试..."
    
    # 启动测试环境
    ./scripts/test-setup.sh
    
    # 启动性能监控
    ./scripts/performance-monitor.sh 300 "$REPORT_DIR/performance" "http://localhost:3001" &
    MONITOR_PID=$!
    
    # 等待服务就绪
    wait_for_services
    
    # 执行性能测试
    npx ts-node tests/comprehensive/comprehensive-test-runner.ts performance \
        2>&1 | tee "$REPORT_DIR/logs/performance-test.log"
    
    # 停止性能监控
    kill $MONITOR_PID 2>/dev/null || true
    
    log "SUCCESS" "性能测试完成"
}

# 执行所有测试
run_all_tests() {
    log "INFO" "执行完整测试套件..."
    
    local test_types=("smoke" "parallel" "multi-agent" "performance")
    local failed_tests=()
    
    for test_type in "${test_types[@]}"; do
        log "INFO" "开始执行: $test_type"
        
        if ! TEST_TYPE=$test_type run_tests; then
            failed_tests+=("$test_type")
            log "ERROR" "测试失败: $test_type"
        else
            log "SUCCESS" "测试通过: $test_type"
        fi
        
        # 测试间隔
        sleep 5
    done
    
    if [ ${#failed_tests[@]} -eq 0 ]; then
        log "SUCCESS" "所有测试套件通过！"
    else
        log "ERROR" "以下测试套件失败: ${failed_tests[*]}"
        return 1
    fi
}

# 等待服务就绪
wait_for_services() {
    log "INFO" "等待服务启动..."
    
    local services=("http://localhost:3001/health" "http://localhost:5433")
    local timeout=60
    
    for service in "${services[@]}"; do
        local count=0
        while [ $count -lt $timeout ]; do
            if curl -f "$service" >/dev/null 2>&1; then
                log "SUCCESS" "服务就绪: $service"
                break
            fi
            sleep 2
            count=$((count + 2))
        done
        
        if [ $count -ge $timeout ]; then
            log "ERROR" "服务启动超时: $service"
            return 1
        fi
    done
}

# 生成测试报告
generate_reports() {
    log "INFO" "生成测试报告..."
    
    local summary_file="$REPORT_DIR/test-summary-${DATE_STAMP}.md"
    
    cat > "$summary_file" << EOF
# 🧪 SmellPin 测试执行报告

## 📊 测试概要

- **执行时间**: $(date)
- **测试类型**: $TEST_TYPE
- **仪表盘**: $ENABLE_DASHBOARD
- **并发数**: $PARALLEL_WORKERS

## 📁 生成的文件

EOF

    # 列出所有生成的文件
    find "$REPORT_DIR" -name "*.json" -o -name "*.html" -o -name "*.log" | sort | while read file; do
        echo "- [$file](./${file#$REPORT_DIR/})" >> "$summary_file"
    done
    
    cat >> "$summary_file" << EOF

## 🔗 相关链接

- [测试仪表盘](http://localhost:3333) (如果启用)
- [GitHub Actions 日志](https://github.com/your-org/smellpin/actions)

## 📈 下一步建议

1. 查看详细的测试日志文件
2. 分析性能指标和趋势
3. 根据失败的测试调整代码
4. 考虑增加更多的测试场景

EOF

    log "SUCCESS" "测试报告已生成: $summary_file"
}

# 清理资源
cleanup() {
    log "INFO" "清理测试环境..."
    
    # 停止仪表盘
    if [ -f "$REPORT_DIR/dashboard.pid" ]; then
        local dashboard_pid=$(cat "$REPORT_DIR/dashboard.pid")
        kill $dashboard_pid 2>/dev/null || true
        rm -f "$REPORT_DIR/dashboard.pid"
    fi
    
    # 停止测试服务
    ./scripts/test-teardown.sh 2>/dev/null || true
    
    # 清理进程
    pkill -f "ts-node" 2>/dev/null || true
    pkill -f "dashboard-server" 2>/dev/null || true
    
    log "SUCCESS" "清理完成"
}

# 显示帮助
show_help() {
    echo -e "${CYAN}SmellPin 测试执行器 - 使用说明${NC}"
    echo
    echo -e "${YELLOW}用法:${NC}"
    echo "  $0 [测试类型] [启用仪表盘] [并发数]"
    echo
    echo -e "${YELLOW}参数:${NC}"
    echo "  测试类型     - smoke, parallel, comprehensive, multi-agent, performance, all"
    echo "  启用仪表盘   - true/false (默认: true)"
    echo "  并发数       - 1-20 (默认: 4)"
    echo
    echo -e "${YELLOW}示例:${NC}"
    echo "  $0 smoke true 2           # 冒烟测试，启用仪表盘，2个并发"
    echo "  $0 comprehensive false 8  # 综合测试，不启用仪表盘，8个并发"
    echo "  $0 all true 4             # 所有测试，启用仪表盘，4个并发"
    echo
    echo -e "${YELLOW}测试类型说明:${NC}"
    echo "  smoke         - 快速验证核心功能"
    echo "  parallel      - 并行执行多个场景"
    echo "  comprehensive - 完整的功能测试"
    echo "  multi-agent   - 多代理用户行为模拟"
    echo "  performance   - 性能和负载测试"
    echo "  all           - 执行所有测试类型"
    echo
}

# 信号处理
trap cleanup EXIT INT TERM

# 主函数
main() {
    # 检查帮助参数
    if [[ "$1" == "-h" || "$1" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    # 显示横幅
    show_banner
    
    # 记录开始时间
    local start_time=$(date +%s)
    
    # 执行测试流程
    check_dependencies
    setup_test_environment
    start_dashboard
    
    local test_result=0
    if ! run_tests; then
        test_result=1
    fi
    
    # 生成报告
    generate_reports
    
    # 计算执行时间
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local hours=$((duration / 3600))
    local minutes=$(((duration % 3600) / 60))
    local seconds=$((duration % 60))
    
    # 显示结果
    echo
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   📊 测试完成                    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    
    if [ $test_result -eq 0 ]; then
        log "SUCCESS" "所有测试执行成功！"
    else
        log "ERROR" "部分测试执行失败，请查看详细日志"
    fi
    
    printf "${PURPLE}⏱️  总执行时间: "
    [ $hours -gt 0 ] && printf "%d小时 " $hours
    [ $minutes -gt 0 ] && printf "%d分钟 " $minutes
    printf "%d秒${NC}\n" $seconds
    
    echo -e "${PURPLE}📁 报告目录: $REPORT_DIR${NC}"
    
    if [ "$ENABLE_DASHBOARD" = "true" ]; then
        echo -e "${PURPLE}📊 仪表盘: http://localhost:3333${NC}"
    fi
    
    echo
    
    exit $test_result
}

# 执行主函数
main "$@"
