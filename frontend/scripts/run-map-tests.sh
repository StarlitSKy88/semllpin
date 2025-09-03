#!/bin/bash

# SmellPin OpenStreetMap Testing Suite
# Comprehensive test execution script for all map functionality

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test results directory
RESULTS_DIR="test-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="$RESULTS_DIR/map_tests_$TIMESTAMP"

# Create results directory
mkdir -p "$REPORT_DIR"

echo -e "${BLUE}🗺️  SmellPin OpenStreetMap Testing Suite${NC}"
echo -e "${BLUE}=======================================${NC}"
echo -e "Started at: $(date)"
echo -e "Results directory: $REPORT_DIR"
echo ""

# Function to log test results
log_test_result() {
    local test_type="$1"
    local status="$2"
    local message="$3"
    
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $test_type | $status | $message" >> "$REPORT_DIR/test_summary.log"
}

# Function to run tests with error handling
run_test_suite() {
    local test_name="$1"
    local test_command="$2"
    local output_file="$3"
    
    echo -e "${YELLOW}📋 Running $test_name...${NC}"
    
    if eval "$test_command" > "$REPORT_DIR/$output_file" 2>&1; then
        echo -e "${GREEN}✅ $test_name: PASSED${NC}"
        log_test_result "$test_name" "PASSED" "All tests completed successfully"
        return 0
    else
        echo -e "${RED}❌ $test_name: FAILED${NC}"
        log_test_result "$test_name" "FAILED" "Some tests failed - check $output_file for details"
        return 1
    fi
}

# Initialize test results
echo "SmellPin OpenStreetMap Test Execution Report" > "$REPORT_DIR/test_summary.log"
echo "=============================================" >> "$REPORT_DIR/test_summary.log"
echo "Start Time: $(date)" >> "$REPORT_DIR/test_summary.log"
echo "" >> "$REPORT_DIR/test_summary.log"

total_suites=0
passed_suites=0
failed_suites=0

# 1. Unit Tests - Map Components
echo -e "\n${PURPLE}🧪 UNIT TESTS${NC}"
echo -e "${PURPLE}==============${NC}"

((total_suites++))
if run_test_suite "Map Components Unit Tests" "npm test -- --testPathPattern=components/map --coverage --watchAll=false --verbose" "unit_map_components.log"; then
    ((passed_suites++))
else
    ((failed_suites++))
fi

# 2. Unit Tests - Services
((total_suites++))
if run_test_suite "Services Unit Tests" "npm test -- --testPathPattern=services --coverage --watchAll=false --verbose" "unit_services.log"; then
    ((passed_suites++))
else
    ((failed_suites++))
fi

# 3. Integration Tests
echo -e "\n${PURPLE}🔗 INTEGRATION TESTS${NC}"
echo -e "${PURPLE}===================${NC}"

((total_suites++))
if run_test_suite "API Integration Tests" "npm test -- --testPathPattern=api-integration --coverage --watchAll=false --verbose" "integration_api.log"; then
    ((passed_suites++))
else
    ((failed_suites++))
fi

# 4. E2E Tests
echo -e "\n${PURPLE}🌍 END-TO-END TESTS${NC}"
echo -e "${PURPLE}===================${NC}"

# Start the development server if not running
echo -e "${YELLOW}🚀 Starting development server...${NC}"
if ! curl -s http://localhost:3001 > /dev/null 2>&1; then
    echo -e "${BLUE}Starting Next.js development server...${NC}"
    npm run dev > "$REPORT_DIR/dev_server.log" 2>&1 &
    DEV_SERVER_PID=$!
    
    # Wait for server to be ready
    echo -e "${BLUE}Waiting for server to be ready...${NC}"
    for i in {1..30}; do
        if curl -s http://localhost:3001 > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Development server is ready${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}❌ Server failed to start within 30 seconds${NC}"
            log_test_result "E2E Setup" "FAILED" "Development server failed to start"
            exit 1
        fi
        sleep 1
    done
else
    echo -e "${GREEN}✅ Development server is already running${NC}"
    DEV_SERVER_PID=""
fi

# Run E2E functionality tests
((total_suites++))
if run_test_suite "E2E Map Functionality Tests" "npx playwright test e2e/map-functionality.spec.ts --reporter=html --output-dir=$REPORT_DIR/playwright-report" "e2e_functionality.log"; then
    ((passed_suites++))
else
    ((failed_suites++))
fi

# Run E2E performance tests
((total_suites++))
if run_test_suite "E2E Map Performance Tests" "npx playwright test e2e/map-performance.spec.ts --reporter=html --output-dir=$REPORT_DIR/playwright-performance-report" "e2e_performance.log"; then
    ((passed_suites++))
else
    ((failed_suites++))
fi

# Cleanup development server
if [ ! -z "$DEV_SERVER_PID" ]; then
    echo -e "${YELLOW}🛑 Stopping development server...${NC}"
    kill $DEV_SERVER_PID 2>/dev/null || true
    wait $DEV_SERVER_PID 2>/dev/null || true
fi

# 5. Generate Coverage Report
echo -e "\n${PURPLE}📊 COVERAGE ANALYSIS${NC}"
echo -e "${PURPLE}===================${NC}"

echo -e "${YELLOW}📈 Generating comprehensive coverage report...${NC}"
if npm run test:coverage > "$REPORT_DIR/coverage_report.log" 2>&1; then
    echo -e "${GREEN}✅ Coverage report generated${NC}"
    log_test_result "Coverage Analysis" "PASSED" "Coverage report generated successfully"
    
    # Copy coverage files
    if [ -d "coverage" ]; then
        cp -r coverage "$REPORT_DIR/"
        echo -e "${BLUE}📋 Coverage files copied to $REPORT_DIR/coverage${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Coverage report generation had issues${NC}"
    log_test_result "Coverage Analysis" "WARNING" "Coverage report generation completed with warnings"
fi

# 6. Generate Final Report
echo -e "\n${PURPLE}📋 GENERATING FINAL REPORT${NC}"
echo -e "${PURPLE}==========================${NC}"

# Create comprehensive HTML report
cat > "$REPORT_DIR/index.html" << EOF
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin OpenStreetMap 测试报告</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary {
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            color: #6c757d;
            font-size: 0.9em;
        }
        .passed { color: #28a745; }
        .failed { color: #dc3545; }
        .warning { color: #ffc107; }
        .info { color: #17a2b8; }
        .content {
            padding: 30px;
        }
        .test-suite {
            margin-bottom: 30px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }
        .test-suite-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            font-weight: bold;
        }
        .test-suite-content {
            padding: 20px;
        }
        .feature-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }
        .feature-item {
            padding: 15px;
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            border-radius: 0 4px 4px 0;
        }
        .feature-title {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .feature-desc {
            color: #6c757d;
            font-size: 0.9em;
        }
        .links {
            margin-top: 20px;
        }
        .link-button {
            display: inline-block;
            padding: 10px 20px;
            margin: 5px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            transition: background 0.3s;
        }
        .link-button:hover {
            background: #5a6fd8;
        }
        .footer {
            padding: 20px 30px;
            background: #f8f9fa;
            border-top: 1px solid #dee2e6;
            text-align: center;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🗺️ SmellPin OpenStreetMap</h1>
            <h2>功能测试报告</h2>
            <p>生成时间: $(date '+%Y年%m月%d日 %H:%M:%S')</p>
        </div>

        <div class="summary">
            <h3>测试执行摘要</h3>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number info">$total_suites</div>
                    <div class="stat-label">测试套件总数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number passed">$passed_suites</div>
                    <div class="stat-label">通过的测试套件</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number failed">$failed_suites</div>
                    <div class="stat-label">失败的测试套件</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number info">$(echo "scale=1; $passed_suites * 100 / $total_suites" | bc -l 2>/dev/null || echo "N/A")%</div>
                    <div class="stat-label">测试通过率</div>
                </div>
            </div>
        </div>

        <div class="content">
            <h3>测试功能覆盖</h3>
            
            <div class="test-suite">
                <div class="test-suite-header">
                    🧪 单元测试 (Unit Tests)
                </div>
                <div class="test-suite-content">
                    <div class="feature-list">
                        <div class="feature-item">
                            <div class="feature-title">OSMMap 组件测试</div>
                            <div class="feature-desc">OpenStreetMap 地图组件的渲染、交互和功能测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">InteractiveMap 组件测试</div>
                            <div class="feature-desc">交互式地图组件的用户交互和状态管理测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">EnhancedInteractiveMap 组件测试</div>
                            <div class="feature-desc">增强交互式地图的高级功能和动画测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">LBS 服务测试</div>
                            <div class="feature-desc">位置服务、地理围栏和奖励系统测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">地理编码服务测试</div>
                            <div class="feature-desc">地址转坐标、坐标转地址和 Nominatim API 测试</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="test-suite">
                <div class="test-suite-header">
                    🔗 集成测试 (Integration Tests)
                </div>
                <div class="test-suite-content">
                    <div class="feature-list">
                        <div class="feature-item">
                            <div class="feature-title">标注 API 集成</div>
                            <div class="feature-desc">地图标注的创建、获取、更新和删除 API 测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">LBS API 集成</div>
                            <div class="feature-desc">位置上报、奖励领取和附近标注查询 API 测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">地理编码 API 集成</div>
                            <div class="feature-desc">地理编码和反向地理编码 API 集成测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">错误处理测试</div>
                            <div class="feature-desc">网络错误、超时、限流等异常情况处理测试</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="test-suite">
                <div class="test-suite-header">
                    🌍 端到端测试 (End-to-End Tests)
                </div>
                <div class="test-suite-content">
                    <div class="feature-list">
                        <div class="feature-item">
                            <div class="feature-title">地图加载和显示</div>
                            <div class="feature-desc">OpenStreetMap 瓦片加载、用户位置显示和基础交互</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">标注功能流程</div>
                            <div class="feature-desc">标注创建、查看、发现和奖励领取完整流程</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">地图交互操作</div>
                            <div class="feature-desc">缩放、平移、点击和移动端手势操作</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">响应式设计</div>
                            <div class="feature-desc">移动设备适配和屏幕旋转支持</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">跨浏览器兼容性</div>
                            <div class="feature-desc">Chrome、Firefox、Safari 浏览器兼容性测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">错误场景处理</div>
                            <div class="feature-desc">离线模式、慢网络和 API 故障处理</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="test-suite">
                <div class="test-suite-header">
                    ⚡ 性能测试 (Performance Tests)
                </div>
                <div class="test-suite-content">
                    <div class="feature-list">
                        <div class="feature-item">
                            <div class="feature-title">加载性能</div>
                            <div class="feature-desc">页面加载时间、地图渲染时间和瓦片加载效率</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">交互响应性能</div>
                            <div class="feature-desc">缩放、平移、点击操作的响应时间测试</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">内存使用</div>
                            <div class="feature-desc">内存占用、内存泄漏和大数据集处理能力</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">渲染性能</div>
                            <div class="feature-desc">帧率测试和大量标注渲染性能</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">网络性能</div>
                            <div class="feature-desc">API 调用优化、缓存策略和请求效率</div>
                        </div>
                        <div class="feature-item">
                            <div class="feature-title">移动端性能</div>
                            <div class="feature-desc">移动设备性能和触摸交互响应测试</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="links">
                <h4>详细报告链接</h4>
                <a href="coverage/lcov-report/index.html" class="link-button">📊 代码覆盖率报告</a>
                <a href="playwright-report/index.html" class="link-button">🎭 E2E 测试报告</a>
                <a href="playwright-performance-report/index.html" class="link-button">⚡ 性能测试报告</a>
                <a href="test_summary.log" class="link-button">📋 详细日志</a>
            </div>
        </div>

        <div class="footer">
            <p>
                SmellPin OpenStreetMap 测试套件 - 确保地图功能的可靠性和性能<br>
                测试框架: Jest, React Testing Library, Playwright<br>
                地图服务: OpenStreetMap + Leaflet
            </p>
        </div>
    </div>
</body>
</html>
EOF

# Generate markdown report
cat > "$REPORT_DIR/README.md" << EOF
# SmellPin OpenStreetMap 测试报告

## 测试执行摘要

- **测试时间**: $(date '+%Y年%m月%d日 %H:%M:%S')
- **测试套件总数**: $total_suites
- **通过的测试套件**: $passed_suites  
- **失败的测试套件**: $failed_suites
- **测试通过率**: $(echo "scale=1; $passed_suites * 100 / $total_suites" | bc -l 2>/dev/null || echo "N/A")%

## 测试覆盖范围

### 🧪 单元测试 (Unit Tests)

1. **OSMMap 组件测试**
   - OpenStreetMap 地图组件渲染
   - 用户位置显示和地理位置权限处理
   - 标注标记显示和弹窗功能
   - 地图交互操作（点击、缩放）
   - 错误处理和边界情况

2. **InteractiveMap 组件测试**
   - 交互式地图组件基础功能
   - 用户交互和状态管理
   - 标注发现和奖励机制

3. **EnhancedInteractiveMap 组件测试**
   - 高级地图交互功能
   - 动画和性能优化
   - 多主题支持和热力图模式
   - 坐标转换和可视区域计算

4. **LBS 服务测试**
   - 地理位置获取和监听
   - 距离计算和地理围栏检测
   - 附近标注查询
   - 奖励领取和验证
   - 位置数据验证和防作弊

5. **地理编码服务测试**
   - 地址转坐标功能
   - 坐标转地址功能
   - Nominatim API 集成
   - 中文地址处理
   - 错误处理和降级策略

### 🔗 集成测试 (Integration Tests)

1. **标注 API 集成**
   - 地图标注获取（边界范围查询）
   - 附近标注查询（半径搜索）
   - 标注创建、更新、删除
   - 点赞和评论功能
   - 权限验证和错误处理

2. **LBS API 集成**
   - 位置上报和附近奖励检查
   - 奖励领取和距离验证
   - 用户奖励历史查询
   - 地理围栏和实时通知

3. **地理编码 API 集成**
   - 地址地理编码服务
   - 坐标反向地理编码
   - 多语言地址支持
   - API 限流和错误恢复

### 🌍 端到端测试 (End-to-End Tests)

1. **地图加载和显示**
   - OpenStreetMap 瓦片正常加载
   - 地图加载状态和用户反馈
   - 地理位置权限处理
   - 地图控件和图例显示

2. **标注功能完整流程**
   - 标注标记显示和点击交互
   - 标注详情弹窗和信息展示
   - 标注创建表单和提交流程
   - 标注发现和奖励领取

3. **地图交互操作**
   - 鼠标滚轮缩放功能
   - 地图拖拽平移操作
   - 移动端触摸手势支持
   - 键盘导航和无障碍访问

4. **用户位置功能**
   - 用户位置标记显示
   - 定位到用户位置功能
   - 位置更新和移动处理

5. **响应式设计**
   - 移动设备适配
   - 屏幕方向变化处理
   - 不同屏幕尺寸支持

6. **跨浏览器兼容性**
   - Chrome 浏览器兼容性
   - Firefox 浏览器兼容性
   - Safari/WebKit 兼容性

7. **错误场景处理**
   - 离线状态处理
   - 慢网络条件适配
   - API 服务故障处理
   - 恶意数据输入防护

### ⚡ 性能测试 (Performance Tests)

1. **加载性能**
   - 页面加载时间 (< 3秒)
   - 地图渲染时间 (< 5秒)
   - OpenStreetMap 瓦片加载效率
   - 慢网络条件适应

2. **交互响应性能**
   - 缩放操作响应时间 (< 200ms)
   - 平移操作响应时间 (< 300ms)
   - 标注点击响应时间 (< 500ms)

3. **内存使用**
   - 内存占用监测 (< 150MB)
   - 内存泄漏检测
   - 大数据集处理能力 (1000+ 标注)
   - 长时间使用稳定性

4. **渲染性能**
   - 帧率维持 (> 30 FPS)
   - 大量标注渲染性能
   - 不同缩放级别性能
   - 视觉效果和动画流畅度

5. **网络性能**
   - API 调用次数优化
   - 响应时间监测 (< 1秒)
   - 数据缓存策略
   - 并发请求处理

6. **移动端性能**
   - 移动设备加载时间 (< 6秒)
   - 触摸交互响应 (< 400ms)
   - 屏幕旋转适应

## 技术栈和工具

- **前端框架**: Next.js 15 + React 18 + TypeScript
- **地图组件**: Leaflet + React Leaflet
- **地图数据**: OpenStreetMap
- **测试框架**: 
  - Jest + React Testing Library (单元测试)
  - Playwright (端到端测试)
  - 自定义性能监测工具

## 文件结构

\`\`\`
test-results/map_tests_$TIMESTAMP/
├── index.html                    # 主要测试报告 (HTML)
├── README.md                     # 测试报告 (Markdown)
├── test_summary.log              # 测试执行日志
├── unit_map_components.log       # 地图组件单元测试日志
├── unit_services.log             # 服务单元测试日志
├── integration_api.log           # API 集成测试日志
├── e2e_functionality.log         # E2E 功能测试日志
├── e2e_performance.log           # E2E 性能测试日志
├── coverage_report.log           # 覆盖率报告日志
├── coverage/                     # 代码覆盖率报告目录
├── playwright-report/            # Playwright E2E 测试报告
└── playwright-performance-report/ # Playwright 性能测试报告
\`\`\`

## 测试结果总结

EOF

# Append test results to markdown
echo "" >> "$REPORT_DIR/README.md"

if [ $failed_suites -eq 0 ]; then
    echo "✅ **所有测试套件均通过！SmellPin OpenStreetMap 功能运行正常。**" >> "$REPORT_DIR/README.md"
    echo "" >> "$REPORT_DIR/README.md"
    echo "- 地图加载和显示功能正常" >> "$REPORT_DIR/README.md"
    echo "- 用户位置和地理编码服务稳定" >> "$REPORT_DIR/README.md"
    echo "- 标注系统和 LBS 奖励功能完整" >> "$REPORT_DIR/README.md"
    echo "- 性能指标符合预期标准" >> "$REPORT_DIR/README.md"
    echo "- 跨浏览器和移动端兼容性良好" >> "$REPORT_DIR/README.md"
else
    echo "⚠️ **部分测试套件存在问题，需要关注以下方面：**" >> "$REPORT_DIR/README.md"
    echo "" >> "$REPORT_DIR/README.md"
    echo "- 查看详细日志文件了解具体失败原因" >> "$REPORT_DIR/README.md"
    echo "- 重点检查失败的测试用例" >> "$REPORT_DIR/README.md"
    echo "- 验证相关功能的实际表现" >> "$REPORT_DIR/README.md"
fi

# Final summary
echo "" >> "$REPORT_DIR/test_summary.log"
echo "=============================================" >> "$REPORT_DIR/test_summary.log"
echo "End Time: $(date)" >> "$REPORT_DIR/test_summary.log"
echo "Total Test Suites: $total_suites" >> "$REPORT_DIR/test_summary.log"
echo "Passed: $passed_suites" >> "$REPORT_DIR/test_summary.log"
echo "Failed: $failed_suites" >> "$REPORT_DIR/test_summary.log"

# Display final results
echo ""
echo -e "${BLUE}📋 FINAL REPORT${NC}"
echo -e "${BLUE}===============${NC}"
echo -e "Test Results Summary:"
echo -e "  Total Suites: $total_suites"
echo -e "  Passed: ${GREEN}$passed_suites${NC}"
echo -e "  Failed: ${RED}$failed_suites${NC}"

success_rate=$(echo "scale=1; $passed_suites * 100 / $total_suites" | bc -l 2>/dev/null || echo "0")
echo -e "  Success Rate: ${BLUE}$success_rate%${NC}"

echo ""
echo -e "${PURPLE}📁 Report Location: $REPORT_DIR${NC}"
echo -e "${PURPLE}🌐 Open HTML Report: file://$(pwd)/$REPORT_DIR/index.html${NC}"
echo ""

if [ $failed_suites -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! SmellPin OpenStreetMap is ready for production.${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests failed. Please review the detailed reports.${NC}"
    exit 1
fi
EOF

chmod +x /Users/xiaoyang/Downloads/臭味/frontend/scripts/run-map-tests.sh