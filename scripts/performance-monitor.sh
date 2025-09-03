#!/bin/bash
# SmellPin 性能监控脚本
# 自动化测试方案2.0 - 实时性能指标收集

set -e

MONITOR_DURATION=${1:-300}  # 默认监控5分钟
OUTPUT_DIR=${2:-"test-results/performance"}
SERVER_URL=${3:-"http://localhost:3001"}

echo "🔍 启动SmellPin性能监控..."
echo "监控时长: ${MONITOR_DURATION}秒"
echo "输出目录: ${OUTPUT_DIR}"
echo "服务器地址: ${SERVER_URL}"

# 创建输出目录
mkdir -p "${OUTPUT_DIR}"

# 性能监控文件
SYSTEM_METRICS="${OUTPUT_DIR}/system-metrics.txt"
API_METRICS="${OUTPUT_DIR}/api-metrics.txt"
DATABASE_METRICS="${OUTPUT_DIR}/database-metrics.txt"
ERROR_METRICS="${OUTPUT_DIR}/error-metrics.txt"

# 清理旧的监控文件
rm -f "${SYSTEM_METRICS}" "${API_METRICS}" "${DATABASE_METRICS}" "${ERROR_METRICS}"

# 开始时间
START_TIME=$(date +%s)
echo "监控开始时间: $(date)" >> "${SYSTEM_METRICS}"

# 后台监控系统资源
monitor_system_resources() {
    local duration=$1
    local output_file=$2
    
    echo "=== 系统资源监控 ===" >> "${output_file}"
    
    for ((i=1; i<=duration; i++)); do
        echo "--- 时间点: $(date) (${i}/${duration}) ---" >> "${output_file}"
        
        # CPU使用率
        echo "CPU使用率:" >> "${output_file}"
        top -bn1 | grep "Cpu(s)" >> "${output_file}"
        
        # 内存使用
        echo "内存使用:" >> "${output_file}"
        free -h >> "${output_file}"
        
        # 磁盘IO
        echo "磁盘IO:" >> "${output_file}"
        iostat -x 1 1 >> "${output_file}" 2>/dev/null || echo "iostat不可用" >> "${output_file}"
        
        # 网络连接
        echo "网络连接:" >> "${output_file}"
        ss -tuln | wc -l >> "${output_file}"
        
        # Node.js进程状态
        echo "Node.js进程:" >> "${output_file}"
        ps aux | grep -E "(node|ts-node)" | grep -v grep >> "${output_file}"
        
        echo "" >> "${output_file}"
        sleep 1
    done
}

# 监控API性能
monitor_api_performance() {
    local duration=$1
    local output_file=$2
    local server_url=$3
    
    echo "=== API性能监控 ===" >> "${output_file}"
    
    # API端点列表
    local endpoints=(
        "/health"
        "/api/v1/health"
        "/api/v1/annotations/list"
        "/api/v1/annotations/nearby?latitude=39.9042&longitude=116.4074&radius=1000"
        "/api/v1/search?q=test&limit=5"
    )
    
    local interval=$((duration / 10)) # 每10%的时间测试一次
    if [ $interval -lt 5 ]; then
        interval=5  # 最小间隔5秒
    fi
    
    for ((i=1; i<=duration; i+=interval)); do
        echo "--- API测试时间: $(date) ---" >> "${output_file}"
        
        for endpoint in "${endpoints[@]}"; do
            echo "测试端点: ${endpoint}" >> "${output_file}"
            
            # 使用curl测试响应时间
            local response_time=$(curl -w "%{time_total}" -s -o /dev/null "${server_url}${endpoint}" 2>/dev/null || echo "ERROR")
            local http_code=$(curl -w "%{http_code}" -s -o /dev/null "${server_url}${endpoint}" 2>/dev/null || echo "000")
            
            echo "  响应时间: ${response_time}s" >> "${output_file}"
            echo "  HTTP状态码: ${http_code}" >> "${output_file}"
            
            # 检查是否有错误
            if [[ "$http_code" != "200" && "$http_code" != "201" ]]; then
                echo "  ❌ 异常响应" >> "${output_file}"
                echo "$(date): ${endpoint} - HTTP ${http_code}" >> "${ERROR_METRICS}"
            fi
        done
        
        echo "" >> "${output_file}"
        sleep $interval
    done
}

# 监控数据库性能
monitor_database_performance() {
    local duration=$1
    local output_file=$2
    
    echo "=== 数据库性能监控 ===" >> "${output_file}"
    
    # 检查数据库连接
    if ! docker-compose -f docker-compose.test.yml exec -T postgres-test pg_isready -U test -d smellpin_test >/dev/null 2>&1; then
        echo "数据库不可用，跳过数据库监控" >> "${output_file}"
        return
    fi
    
    local interval=30  # 每30秒检查一次
    local iterations=$((duration / interval))
    
    for ((i=1; i<=iterations; i++)); do
        echo "--- 数据库检查: $(date) (${i}/${iterations}) ---" >> "${output_file}"
        
        # 数据库连接数
        local connections=$(docker-compose -f docker-compose.test.yml exec -T postgres-test psql -U test -d smellpin_test -t -c "SELECT count(*) FROM pg_stat_activity;" 2>/dev/null || echo "N/A")
        echo "活跃连接数: ${connections}" >> "${output_file}"
        
        # 数据库大小
        local db_size=$(docker-compose -f docker-compose.test.yml exec -T postgres-test psql -U test -d smellpin_test -t -c "SELECT pg_size_pretty(pg_database_size('smellpin_test'));" 2>/dev/null || echo "N/A")
        echo "数据库大小: ${db_size}" >> "${output_file}"
        
        # 慢查询检查
        local slow_queries=$(docker-compose -f docker-compose.test.yml exec -T postgres-test psql -U test -d smellpin_test -t -c "SELECT count(*) FROM pg_stat_statements WHERE mean_time > 100;" 2>/dev/null || echo "N/A")
        echo "慢查询数量(>100ms): ${slow_queries}" >> "${output_file}"
        
        echo "" >> "${output_file}"
        sleep $interval
    done
}

# 监控应用错误
monitor_application_errors() {
    local duration=$1
    local output_file=$2
    local server_url=$3
    
    echo "=== 应用错误监控 ===" >> "${output_file}"
    
    local interval=15  # 每15秒检查一次
    local iterations=$((duration / interval))
    
    for ((i=1; i<=iterations; i++)); do
        echo "--- 错误检查: $(date) ---" >> "${output_file}"
        
        # 检查错误监控端点
        local error_stats=$(curl -s "${server_url}/api/v1/errors/stats" 2>/dev/null)
        if [[ $? -eq 0 && "$error_stats" != "" ]]; then
            echo "错误统计: ${error_stats}" >> "${output_file}"
            
            # 解析错误数据 (简单处理)
            local error_count=$(echo "$error_stats" | grep -o '"totalErrors":[0-9]*' | cut -d':' -f2 || echo "0")
            if [[ "$error_count" -gt 0 ]]; then
                echo "检测到 ${error_count} 个错误" >> "${ERROR_METRICS}"
            fi
        else
            echo "无法获取错误统计" >> "${output_file}"
        fi
        
        # 检查应用健康状态
        local health_status=$(curl -s "${server_url}/api/v1/health" | grep -o '"success":[^,]*' | cut -d':' -f2 || echo "false")
        echo "健康状态: ${health_status}" >> "${output_file}"
        
        if [[ "$health_status" != "true" ]]; then
            echo "$(date): 应用健康检查失败" >> "${ERROR_METRICS}"
        fi
        
        echo "" >> "${output_file}"
        sleep $interval
    done
}

# 生成性能报告
generate_performance_report() {
    local output_dir=$1
    local report_file="${output_dir}/performance-report.html"
    
    echo "📊 生成性能报告..."
    
    cat > "${report_file}" << EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin 性能监控报告</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .metric { margin: 20px 0; padding: 15px; border-left: 4px solid #007cba; background: #f9f9f9; }
        .error { border-left-color: #dc3545; background: #f8d7da; }
        .success { border-left-color: #28a745; background: #d4edda; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 SmellPin 性能监控报告</h1>
        <p class="timestamp">生成时间: $(date)</p>
        <p>监控时长: ${MONITOR_DURATION}秒</p>
        <p>服务器地址: ${SERVER_URL}</p>
    </div>

    <div class="metric">
        <h2>📈 系统资源使用情况</h2>
        <pre>$(tail -n 50 "${SYSTEM_METRICS}" 2>/dev/null || echo "无系统资源数据")</pre>
    </div>

    <div class="metric">
        <h2>🌐 API性能指标</h2>
        <pre>$(tail -n 100 "${API_METRICS}" 2>/dev/null || echo "无API性能数据")</pre>
    </div>

    <div class="metric">
        <h2>🗄️ 数据库性能</h2>
        <pre>$(tail -n 50 "${DATABASE_METRICS}" 2>/dev/null || echo "无数据库性能数据")</pre>
    </div>

    <div class="metric error">
        <h2>❌ 错误统计</h2>
        <pre>$(cat "${ERROR_METRICS}" 2>/dev/null || echo "暂无错误记录")</pre>
    </div>

    <div class="metric success">
        <h2>✅ 监控完成</h2>
        <p>性能监控已完成，详细数据请查看各个指标文件。</p>
    </div>
</body>
</html>
EOF

    echo "📋 性能报告已生成: ${report_file}"
}

# 主监控逻辑
main() {
    echo "开始并行监控..."
    
    # 启动后台监控进程
    monitor_system_resources $MONITOR_DURATION "$SYSTEM_METRICS" &
    local system_pid=$!
    
    monitor_api_performance $MONITOR_DURATION "$API_METRICS" "$SERVER_URL" &
    local api_pid=$!
    
    monitor_database_performance $MONITOR_DURATION "$DATABASE_METRICS" &
    local db_pid=$!
    
    monitor_application_errors $MONITOR_DURATION "$ERROR_METRICS" "$SERVER_URL" &
    local error_pid=$!
    
    # 等待所有监控进程完成
    wait $system_pid
    wait $api_pid  
    wait $db_pid
    wait $error_pid
    
    # 生成报告
    generate_performance_report "$OUTPUT_DIR"
    
    # 输出摘要
    echo ""
    echo "🎉 性能监控完成！"
    echo "监控时长: ${MONITOR_DURATION}秒"
    echo "结束时间: $(date)"
    
    local end_time=$(date +%s)
    local elapsed=$((end_time - START_TIME))
    echo "实际用时: ${elapsed}秒"
    
    echo ""
    echo "📁 生成的文件："
    ls -la "$OUTPUT_DIR"
    
    # 检查是否有错误
    if [[ -s "$ERROR_METRICS" ]]; then
        echo ""
        echo "⚠️ 发现错误，请查看: $ERROR_METRICS"
        return 1
    else
        echo ""
        echo "✅ 监控期间无错误发生"
        return 0
    fi
}

# 清理函数
cleanup() {
    echo ""
    echo "🧹 清理后台进程..."
    jobs -p | xargs -r kill 2>/dev/null || true
    exit 0
}

# 设置清理钩子
trap cleanup INT TERM EXIT

# 执行主函数
main "$@"