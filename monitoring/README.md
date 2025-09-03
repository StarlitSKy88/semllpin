# SmellPin 监控系统

## 概述

SmellPin 监控系统是一个基于 Prometheus + Grafana + AlertManager 的完整监控解决方案，为 SmellPin 应用提供全方位的性能监控、日志收集和告警机制。

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SmellPin App  │───▶│   Prometheus    │───▶│     Grafana     │
│                 │    │                 │    │                 │
│ - HTTP Metrics  │    │ - 指标收集       │    │ - 数据可视化     │
│ - Business Data │    │ - 数据存储       │    │ - 仪表板展示     │
│ - System Info   │    │ - 告警规则       │    │ - 用户界面       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         │              │  AlertManager   │              │
         │              │                 │              │
         └──────────────│ - 告警管理       │──────────────┘
                        │ - 通知发送       │
                        │ - 告警抑制       │
                        └─────────────────┘
```

## 功能特性

### 🔍 性能监控
- **HTTP 请求监控**: 请求总数、响应时间、错误率
- **系统资源监控**: CPU、内存、磁盘、网络使用率
- **数据库监控**: 连接数、查询性能、慢查询统计
- **Redis 监控**: 内存使用、连接数、命令执行统计
- **WebSocket 监控**: 连接数、消息传输统计

### 📊 业务指标
- **用户行为**: 注册数、活跃用户、留存率
- **标注数据**: 创建数量、地理分布、热门区域
- **支付统计**: 成功率、收入统计、异常监控
- **LBS 奖励**: 发放统计、用户参与度

### 🚨 告警机制
- **系统告警**: 服务宕机、资源使用过高
- **业务告警**: 关键指标异常、用户行为异常
- **安全告警**: 可疑登录、攻击检测
- **多渠道通知**: 邮件、Slack、短信、钉钉

### 📈 数据可视化
- **系统概览仪表板**: 整体健康状态和关键指标
- **业务监控仪表板**: 业务数据和用户行为分析
- **性能分析仪表板**: 详细的性能指标和趋势
- **告警管理界面**: 告警历史和状态管理

## 快速开始

### 前置要求

- Docker >= 20.10
- Docker Compose >= 2.0
- 至少 4GB 可用内存
- 至少 10GB 可用磁盘空间

### 安装部署

1. **克隆项目并进入监控目录**
   ```bash
   cd /path/to/smellpin/monitoring
   ```

2. **配置环境变量**
   ```bash
   # 编辑 .env 文件，配置数据库连接等信息
   cp .env.example .env
   vim .env
   ```

3. **一键部署**
   ```bash
   ./deploy.sh deploy
   ```

4. **访问服务**
   - Grafana: http://localhost:3001 (admin/admin123)
   - Prometheus: http://localhost:9090
   - AlertManager: http://localhost:9093

### 常用命令

```bash
# 启动服务
./deploy.sh start

# 停止服务
./deploy.sh stop

# 重启服务
./deploy.sh restart

# 查看状态
./deploy.sh status

# 健康检查
./deploy.sh health

# 查看日志
./deploy.sh logs [service_name]

# 更新服务
./deploy.sh update

# 清理数据
./deploy.sh clean
```

## 配置说明

### Prometheus 配置

**文件位置**: `prometheus/prometheus.yml`

主要配置项：
- `global.scrape_interval`: 全局抓取间隔 (默认 15s)
- `global.evaluation_interval`: 规则评估间隔 (默认 15s)
- `scrape_configs`: 抓取目标配置
- `rule_files`: 告警规则文件

### Grafana 配置

**数据源配置**: `grafana/datasources/prometheus.yml`
**仪表板配置**: `grafana/dashboards/`

默认仪表板：
- **SmellPin 系统概览**: 整体系统状态和关键指标
- **SmellPin 业务监控**: 业务数据和用户行为
- **系统资源监控**: 服务器资源使用情况

### AlertManager 配置

**文件位置**: `alertmanager/alertmanager.yml`

配置项说明：
- `global`: 全局配置 (SMTP 等)
- `route`: 告警路由规则
- `receivers`: 告警接收器配置
- `inhibit_rules`: 告警抑制规则

## 监控指标

### 系统指标

| 指标名称 | 描述 | 标签 |
|---------|------|------|
| `http_requests_total` | HTTP 请求总数 | method, status, endpoint |
| `http_request_duration_seconds` | HTTP 请求持续时间 | method, status, endpoint |
| `system_cpu_usage` | CPU 使用率 | - |
| `system_memory_usage` | 内存使用率 | - |
| `database_connections_active` | 活跃数据库连接数 | - |
| `redis_connected_clients` | Redis 连接数 | - |

### 业务指标

| 指标名称 | 描述 | 标签 |
|---------|------|------|
| `user_registrations_total` | 用户注册总数 | - |
| `annotations_created_total` | 标注创建总数 | category, location |
| `payments_total` | 支付总数 | status, method |
| `lbs_rewards_distributed_total` | LBS 奖励发放总数 | - |
| `websocket_connections_active` | 活跃 WebSocket 连接数 | - |

## 告警规则

### 系统告警

- **服务宕机**: 服务无响应超过 1 分钟
- **高错误率**: 5xx 错误率超过 5%
- **响应时间慢**: 95% 响应时间超过 1 秒
- **CPU 使用率高**: CPU 使用率超过 80%
- **内存使用率高**: 内存使用率超过 85%

### 业务告警

- **用户注册骤降**: 1 小时内注册数低于正常值 50%
- **标注创建异常**: 1 小时内标注创建数异常
- **支付失败率高**: 支付失败率超过 10%
- **LBS 奖励异常**: LBS 奖励发放异常

### 安全告警

- **可疑登录**: 短时间内大量登录失败
- **限流触发**: 限流触发次数过多
- **异常访问**: 异常 IP 访问模式

## 故障排查

### 常见问题

1. **服务无法启动**
   ```bash
   # 检查端口占用
   netstat -tulpn | grep :9090
   
   # 检查 Docker 状态
   docker ps -a
   
   # 查看服务日志
   ./deploy.sh logs prometheus
   ```

2. **数据源连接失败**
   ```bash
   # 检查网络连接
   docker exec -it smellpin-grafana ping prometheus
   
   # 检查 Prometheus 状态
   curl http://localhost:9090/-/healthy
   ```

3. **告警不生效**
   ```bash
   # 检查告警规则
   curl http://localhost:9090/api/v1/rules
   
   # 检查 AlertManager 配置
   curl http://localhost:9093/api/v1/status
   ```

### 日志查看

```bash
# 查看所有服务日志
docker-compose logs -f

# 查看特定服务日志
docker-compose logs -f prometheus
docker-compose logs -f grafana
docker-compose logs -f alertmanager

# 查看最近的日志
docker-compose logs --tail=100 prometheus
```

## 性能优化

### Prometheus 优化

1. **存储优化**
   - 调整数据保留时间: `--storage.tsdb.retention.time=30d`
   - 配置存储压缩: `--storage.tsdb.wal-compression`

2. **查询优化**
   - 使用记录规则预计算复杂查询
   - 合理设置抓取间隔
   - 避免高基数标签

### Grafana 优化

1. **仪表板优化**
   - 减少面板数量
   - 使用合适的时间范围
   - 启用查询缓存

2. **数据源优化**
   - 配置连接池
   - 设置查询超时
   - 使用代理模式

## 安全配置

### 访问控制

1. **Grafana 安全**
   ```bash
   # 修改默认密码
   docker exec -it smellpin-grafana grafana-cli admin reset-admin-password newpassword
   
   # 启用 HTTPS
   # 在 docker-compose.yml 中配置 SSL 证书
   ```

2. **Prometheus 安全**
   - 配置基本认证
   - 限制网络访问
   - 使用 TLS 加密

### 网络安全

```yaml
# docker-compose.yml 网络配置示例
networks:
  monitoring:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## 备份与恢复

### 数据备份

```bash
# 备份 Prometheus 数据
docker run --rm -v monitoring_prometheus_data:/data -v $(pwd):/backup alpine tar czf /backup/prometheus-backup.tar.gz /data

# 备份 Grafana 数据
docker run --rm -v monitoring_grafana_data:/data -v $(pwd):/backup alpine tar czf /backup/grafana-backup.tar.gz /data
```

### 数据恢复

```bash
# 恢复 Prometheus 数据
docker run --rm -v monitoring_prometheus_data:/data -v $(pwd):/backup alpine tar xzf /backup/prometheus-backup.tar.gz -C /

# 恢复 Grafana 数据
docker run --rm -v monitoring_grafana_data:/data -v $(pwd):/backup alpine tar xzf /backup/grafana-backup.tar.gz -C /
```

## 扩展功能

### 添加新的监控目标

1. **修改 Prometheus 配置**
   ```yaml
   # prometheus/prometheus.yml
   scrape_configs:
     - job_name: 'new-service'
       static_configs:
         - targets: ['new-service:port']
   ```

2. **重新加载配置**
   ```bash
   curl -X POST http://localhost:9090/-/reload
   ```

### 自定义仪表板

1. **导出现有仪表板**
   - 在 Grafana 中导出 JSON 配置
   - 保存到 `grafana/dashboards/` 目录

2. **创建新仪表板**
   - 使用 Grafana UI 创建
   - 或直接编写 JSON 配置文件

## 维护指南

### 定期维护任务

1. **每日检查**
   - 服务健康状态
   - 告警状态
   - 磁盘空间使用

2. **每周维护**
   - 清理过期数据
   - 更新监控规则
   - 检查性能指标

3. **每月维护**
   - 备份监控数据
   - 更新服务版本
   - 优化配置参数

### 监控系统监控

```bash
# 监控 Prometheus 自身
curl http://localhost:9090/metrics | grep prometheus_

# 监控 Grafana 状态
curl http://localhost:3001/api/health

# 监控 AlertManager 状态
curl http://localhost:9093/api/v1/status
```

## 联系支持

如果您在使用过程中遇到问题，请通过以下方式联系我们：

- **技术支持**: tech@smellpin.com
- **问题反馈**: https://github.com/smellpin/issues
- **文档更新**: docs@smellpin.com

---

**版本**: v1.0.0  
**最后更新**: 2024年12月  
**维护团队**: SmellPin DevOps Team