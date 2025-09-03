# 🧪 SmellPin 自动化测试系统 2.0

欢迎使用SmellPin先进的自动化测试系统！这套系统支持多代理并行测试、实时监控仪表盘和CI/CD自动化。

## ✨ 主要特性

### 🚀 多代理并行测试
- **真实用户行为模拟**: 支持探索者、标注者、社交用户、商户、验证者五种角色
- **可配置并发数**: 1-100个代理同时运行
- **智能负载均衡**: 自动分配测试负载
- **全面指标收集**: 响应时间、成功率、错误率等

### 📈 实时监控仪表盘
- **实时数据显示**: 测试进度、系统指标、错误统计
- **交互式图表**: 性能趋势分析
- **多终端支持**: PC、手机、平板都能完美显示
- **实时通知**: WebSocket实时推送测试状态

### 🔄 CI/CD 集成
- **GitHub Actions 自动化**: 支持多种触发方式
- **灵活的测试策略**: 根据分支和事件类型自动选择测试
- **多环境支持**: 测试、预发布、生产环境
- **自动报告**: PR评论、失败通知

## 🛠️ 快速开始

### 安装依赖
```bash
npm install
npm run build
```

### 基础使用

#### 1. 冒烟测试 (推荐新手)
```bash
# 方式1: 使用npm命令
npm run test:enhanced:smoke

# 方式2: 直接运行脚本
./scripts/run-enhanced-tests.sh smoke true 2

# 方式3: 单独运行多代理模拟器
npm run test:parallel:smoke
```

#### 2. 并行测试
```bash
# 中等规模并行测试
npm run test:enhanced:parallel

# 自定义并发数
./scripts/run-enhanced-tests.sh parallel true 8
```

#### 3. 综合测试
```bash
# 完整功能测试
npm run test:enhanced:comprehensive

# 所有测试类型
npm run test:enhanced:all
```

## 📈 仪表盘使用

### 启动独立仪表盘
```bash
# 启动仪表盘服务器
npm run dashboard:start

# 或者指定端口和报告目录
npx ts-node tests/dashboard/dashboard-server.ts 3333 ./test-results
```

### 访问仪表盘
在浏览器中打开: http://localhost:3333

### 仪表盘功能
- ⚙️ **实时状态**: 测试进度、当前正在执行的场景
- 📈 **指标监控**: CPU、内存、网络连接数、响应时间
- 🕰️ **时间线**: 测试执行历史和关键事件
- 📁 **报告管理**: 在线查看和下载测试报告

## 📊 测试类型详解

### 1. 冒烟测试 (smoke)
**目的**: 快速验证系统基本功能
**耗时**: 2-5分钟
**适用场景**: 代码提交、快速验证

```bash
# 基本冒烟测试
./scripts/run-enhanced-tests.sh smoke

# 带仪表盘的冒烟测试
./scripts/run-enhanced-tests.sh smoke true 2
```

**测试包含**:
- ✅ API健康检查
- ✅ 用户注册登录
- ✅ 基础数据库操作
- ✅ 缓存系统访问

### 2. 并行测试 (parallel)
**目的**: 测试系统在并发情况下的稳定性
**耗时**: 8-15分钟
**适用场景**: 性能测试、压力测试

```bash
# 基础并行测试
./scripts/run-enhanced-tests.sh parallel

# 高并发测试 (最大2-3个CPU核心)
./scripts/run-enhanced-tests.sh parallel true 8
```

**测试包含**:
- ⚡ 多个场景并行执行
- ⚡ 数据库连接池测试
- ⚡ Redis并发访问
- ⚡ API限流测试

### 3. 多代理测试 (multi-agent)
**目的**: 模拟真实用户行为场景
**耗时**: 10-25分钟
**适用场景**: 用户体验测试、业务流程验证

```bash
# 多代理模拟测试
./scripts/run-enhanced-tests.sh multi-agent
```

**代理角色**:
- 🔍 **探索者**: 浏览地图、查看标注、领取奖励
- 📝 **标注者**: 创建标注、上传图片、支付费用
- 👥 **社交用户**: 点赞、分享、评论、关注
- 💰 **商户**: 处理支付、查看收益、提现
- ✅ **验证者**: 审核内容、举报垃圾信息

### 4. 综合测试 (comprehensive)
**目的**: 全面的端到端功能验证
**耗时**: 15-45分钟
**适用场景**: 版本发布前、回归测试

```bash
# 综合测试套件
./scripts/run-enhanced-tests.sh comprehensive
```

**测试包含**:
- 📊 所有上述测试类型
- 📊 数据库完整性检查
- 📊 API端点全覆盖
- 📊 安全性基础测试

### 5. 性能测试 (performance)
**目的**: 系统性能和资源使用分析
**耗时**: 20-60分钟
**适用场景**: 性能优化、容量计划

```bash
# 性能压力测试
./scripts/run-enhanced-tests.sh performance
```

## 🔧 高级配置

### 环境变量
```bash
# API基础URL
export API_BASE_URL="http://localhost:3001"

# 数据库连接
export DATABASE_URL="postgres://user:pass@localhost:5432/smellpin_test"

# Redis连接
export REDIS_URL="redis://localhost:6379"

# JWT密钥
export JWT_SECRET="your-test-jwt-secret"

# 测试环境标识
export NODE_ENV="test"
```

### 自定义测试场景

你可以创建自己的测试场景:

```typescript
// tests/custom/my-scenario.ts
import { simulator } from '../parallel/multi-agent-simulator';

// 添加自定义场景
simulator.addCustomScenario('my-custom-test', {
  name: '我的自定义测试',
  description: '专为我的业务需求设计',
  concurrency: 3,
  expectedOutcomes: ['业务需求A满足', '业务需求B满足'],
  agents: [
    {
      id: 'custom-1',
      name: '自定义代理',
      behavior: 'explorer',
      intensity: 'medium',
      duration: 5,
      baseUrl: 'http://localhost:3001'
    }
  ]
});

// 运行自定义场景
simulator.runScenario('my-custom-test');
```

### 仪表盘自定义

```typescript
// tests/dashboard/custom-dashboard.ts
import { TestDashboard } from './dashboard-server';

const customDashboard = new TestDashboard(8080, './my-reports');
customDashboard.start();
```

## 📁 报告系统

### 报告类型

所有测试都会生成以下报告:

1. **JSON报告** (`test-results/*.json`)
   - 详细的数据结构
   - 适合自动化分析

2. **HTML报告** (`test-results/*.html`)
   - 可视化的网页报告
   - 包含图表和统计信息

3. **日志文件** (`test-results/logs/*.log`)
   - 详细的执行日志
   - 错误诊断信息

### 报告分析

```bash
# 查看最新的测试报告
ls -la test-results/ | head -10

# 打开HTML报告
open test-results/comprehensive-report-*.html

# 分析日志文件
grep "ERROR\|FAIL" test-results/logs/*.log
```

## 🔄 CI/CD 集成

### GitHub Actions

项目已配置了完整的GitHub Actions工作流:

**.github/workflows/automated-testing.yml**

**触发条件**:
- 📤 `push` 到 `main`, `develop`, `feature/*`
- 🗒️ `pull_request` 面向 `main`, `develop`
- ⏰ 定时任务 (每日凌晨2点)
- 🚀 手动触发 (workflow_dispatch)

**自动选择测试类型**:
- `feature/*` 分支 → 冒烟测试
- `main` 分支 → 集成测试
- `schedule` 触发 → 全面测试
- 手动触发 → 用户选择

### 手动触发测试

1. 进入 GitHub 仓库的 Actions 页面
2. 选择 "SmellPin 自动化测试 CI/CD"
3. 点击 "Run workflow"
4. 选择测试类型和环境
5. 点击 "Run workflow" 执行

### 本地模拟CI环境

```bash
# 模拟GitHub Actions环境
export GITHUB_ACTIONS=true
export CI=true

# 运行完整的CI测试流程
./scripts/run-enhanced-tests.sh all true 4
```

## 🔍 故障排除

### 常见问题

#### 1. 测试环境启动失败
```bash
# 检查Docker服务
docker ps

# 重新启动测试环境
./scripts/test-teardown.sh
./scripts/test-setup.sh

# 检查端口占用
lsof -i :3001
lsof -i :5433
lsof -i :6379
```

#### 2. 仪表盘无法访问
```bash
# 检查仪表盘服务
curl http://localhost:3333

# 重新启动仪表盘
pkill -f dashboard-server
npm run dashboard:start
```

#### 3. 测试执行超时
```bash
# 检查系统资源
top
df -h

# 降低并发数
./scripts/run-enhanced-tests.sh smoke true 1
```

#### 4. 数据库连接问题
```bash
# 检查数据库状态
docker logs smellpin-postgres-test

# 重置数据库
npm run db:reset:test
```

### 日志分析

```bash
# 查看最新的错误日志
tail -f test-results/logs/*.log | grep -E "ERROR|FAIL|Exception"

# 分析性能问题
grep -r "timeout\|slow" test-results/logs/

# 查看成功率
grep -r "success.*rate" test-results/*.json
```

## 📚 参考资料

### 相关文件
- `tests/parallel/multi-agent-simulator.ts` - 多代理模拟器
- `tests/comprehensive/comprehensive-test-runner.ts` - 综合测试运行器
- `tests/dashboard/dashboard-server.ts` - 测试仪表盘
- `scripts/run-enhanced-tests.sh` - 增强测试执行器
- `.github/workflows/automated-testing.yml` - CI/CD配置

### NPM命令列表
```bash
# 基础测试
npm run test                      # 基础测试
npm run test:parallel            # 并行测试
npm run test:integration         # 集成测试

# 多代理测试
npm run test:parallel:smoke      # 冒烟场景
npm run test:parallel:full       # 完整场景

# 综合测试
npm run test:comprehensive:smoke      # 冒烟测试套件
npm run test:comprehensive:regression # 回归测试套件
npm run test:comprehensive:performance # 性能测试套件
npm run test:comprehensive:all        # 综合测试套件

# 增强测试
npm run test:enhanced            # 默认增强测试
npm run test:enhanced:smoke      # 增强冒烟测试
npm run test:enhanced:parallel   # 增强并行测试
npm run test:enhanced:comprehensive # 增强综合测试
npm run test:enhanced:all        # 所有增强测试

# 仪表盘
npm run dashboard:start          # 启动仪表盘
```

### 技术栈
- **前端**: Next.js 15 + React 18 + TypeScript + Tailwind CSS
- **后端**: Node.js + Express.js + TypeScript
- **数据库**: PostgreSQL + PostGIS (Neon)
- **缓存**: Redis
- **测试**: Jest + Playwright + Artillery
- **监控**: Socket.io + Chart.js
- **CI/CD**: GitHub Actions

## 🎆 贡献指南

1. Fork 本仓库
2. 创建特性分支: `git checkout -b feature/new-test-scenario`
3. 提交更改: `git commit -am 'Add new test scenario'`
4. 推送分支: `git push origin feature/new-test-scenario`
5. 创建Pull Request

### 测试贡献
- 添加新的用户角色和行为模式
- 优化测试场景和算法
- 扩展仪表盘功能
- 改善CI/CD流程

---

🎉 **现在就可以开始体验先进的自动化测试了！**

如有问题或建议，请创建 GitHub Issue 或联系开发团队。
