#!/usr/bin/env ts-node
/**
 * SmellPin 测试仪表盘系统
 * 实时监控测试进度和结果
 */

import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import * as fs from 'fs/promises';
import * as path from 'path';
import chalk from 'chalk';
import { watch } from 'fs';

interface DashboardData {
  status: 'idle' | 'running' | 'passed' | 'failed';
  currentSuite: any;
  progress: number;
  results: any[];
  metrics: {
    totalTests: number;
    passedTests: number;
    failedTests: number;
    totalDuration: number;
  };
  liveMetrics: {
    timestamp: number;
    cpu: number;
    memory: number;
    activeConnections: number;
    responseTime: number;
  }[];
}

class TestDashboard {
  private app: express.Application;
  private server: any;
  private io: Server;
  private port: number;
  private reportDir: string;
  private dashboardData: DashboardData;
  private clients: Set<any> = new Set();

  constructor(port: number = 3333, reportDir: string = './test-results') {
    this.port = port;
    this.reportDir = reportDir;
    this.app = express();
    this.server = createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: "*",
        methods: ["GET", "POST"]
      }
    });
    
    this.dashboardData = {
      status: 'idle',
      currentSuite: null,
      progress: 0,
      results: [],
      metrics: {
        totalTests: 0,
        passedTests: 0,
        failedTests: 0,
        totalDuration: 0
      },
      liveMetrics: []
    };
    
    this.setupRoutes();
    this.setupSocketHandlers();
    this.startMetricsCollection();
  }

  private setupRoutes(): void {
    // 静态资源
    this.app.use('/static', express.static(path.join(__dirname, 'dashboard-assets')));
    
    // API路由
    this.app.get('/api/status', (req, res) => {
      res.json(this.dashboardData);
    });
    
    this.app.get('/api/reports', async (req, res) => {
      try {
        const files = await fs.readdir(this.reportDir);
        const reports = files
          .filter(f => f.endsWith('.json') && f.includes('report'))
          .map(f => ({
            name: f,
            path: `/reports/${f}`,
            timestamp: f.match(/\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}/)?.[0] || 'unknown'
          }))
          .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
        
        res.json(reports);
      } catch (error) {
        res.status(500).json({ error: '无法获取报告列表' });
      }
    });
    
    this.app.get('/reports/:filename', async (req, res) => {
      try {
        const filepath = path.join(this.reportDir, req.params.filename);
        const content = await fs.readFile(filepath, 'utf8');
        res.json(JSON.parse(content));
      } catch (error) {
        res.status(404).json({ error: '报告不存在' });
      }
    });
    
    // 主页面
    this.app.get('/', (req, res) => {
      res.send(this.generateDashboardHtml());
    });
  }

  private setupSocketHandlers(): void {
    this.io.on('connection', (socket) => {
      console.log(chalk.green(`🔗 客户端连接: ${socket.id}`));
      this.clients.add(socket);
      
      // 发送初始数据
      socket.emit('dashboard-update', this.dashboardData);
      
      socket.on('disconnect', () => {
        console.log(chalk.yellow(`🔌 客户端断开: ${socket.id}`));
        this.clients.delete(socket);
      });
      
      socket.on('request-update', () => {
        socket.emit('dashboard-update', this.dashboardData);
      });
    });
  }

  private generateDashboardHtml(): string {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin 测试仪表盘</title>
    <script src="/socket.io/socket.io.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #f1f5f9; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1e40af 0%, #7c3aed 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
        .title { font-size: 2.5em; font-weight: 700; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.5); }
        .subtitle { font-size: 1.2em; opacity: 0.9; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .status-idle { background: #64748b; }
        .status-running { background: #f59e0b; animation: pulse 2s infinite; }
        .status-passed { background: #10b981; }
        .status-failed { background: #ef4444; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        
        .dashboard-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .dashboard-card { background: #1e293b; border-radius: 12px; padding: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border: 1px solid #334155; }
        .card-title { font-size: 1.1em; font-weight: 600; margin-bottom: 20px; color: #94a3b8; }
        
        .metric-large { font-size: 3em; font-weight: bold; text-align: center; margin: 20px 0; }
        .metric-label { text-align: center; color: #64748b; }
        .progress-container { margin: 20px 0; }
        .progress-bar { width: 100%; height: 8px; background: #334155; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #10b981 0%, #34d399 100%); transition: width 0.5s ease; }
        .progress-text { text-align: center; margin-top: 10px; color: #94a3b8; }
        
        .timeline { max-height: 400px; overflow-y: auto; padding: 10px 0; }
        .timeline-item { display: flex; align-items: center; padding: 12px 0; border-left: 2px solid #334155; padding-left: 20px; position: relative; }
        .timeline-item.active { border-left-color: #10b981; }
        .timeline-item::before { content: ''; position: absolute; left: -6px; width: 10px; height: 10px; border-radius: 50%; background: #334155; }
        .timeline-item.active::before { background: #10b981; }
        .timeline-time { font-size: 0.8em; color: #64748b; margin-right: 15px; min-width: 80px; }
        .timeline-content { flex: 1; }
        .timeline-title { font-weight: 500; }
        .timeline-desc { font-size: 0.9em; color: #94a3b8; margin-top: 4px; }
        
        .chart-container { height: 300px; position: relative; }
        .metrics-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        .metric-item { display: flex; justify-content: space-between; align-items: center; padding: 15px; background: #0f172a; border-radius: 8px; }
        .metric-name { color: #94a3b8; }
        .metric-value { font-weight: 600; color: #f1f5f9; }
        
        .full-width { grid-column: 1 / -1; }
        .reports-list { max-height: 300px; overflow-y: auto; }
        .report-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid #334155; }
        .report-name { font-weight: 500; }
        .report-time { font-size: 0.9em; color: #64748b; }
        .report-link { color: #3b82f6; text-decoration: none; font-size: 0.9em; }
        .report-link:hover { text-decoration: underline; }
        
        .connection-status { position: fixed; top: 20px; right: 20px; padding: 10px 15px; border-radius: 6px; font-size: 0.9em; font-weight: 500; }
        .connected { background: #065f46; color: #d1fae5; }
        .disconnected { background: #991b1b; color: #fee2e2; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">📈 SmellPin 测试仪表盘</h1>
            <p class="subtitle">
                <span class="status-indicator status-idle" id="statusIndicator"></span>
                <span id="statusText">系统就绪</span>
            </p>
        </div>
        
        <div class="connection-status connected" id="connectionStatus">
            🔗 已连接
        </div>
        
        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-title">📊 测试进度</div>
                <div class="metric-large" id="progressPercent">0%</div>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressBar" style="width: 0%"></div>
                    </div>
                    <div class="progress-text" id="progressText">等待开始...</div>
                </div>
            </div>
            
            <div class="dashboard-card">
                <div class="card-title">📈 测试结果</div>
                <div class="metrics-grid">
                    <div class="metric-item">
                        <span class="metric-name">总数</span>
                        <span class="metric-value" id="totalTests">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-name">通过</span>
                        <span class="metric-value" style="color: #10b981;" id="passedTests">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-name">失败</span>
                        <span class="metric-value" style="color: #ef4444;" id="failedTests">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-name">时长</span>
                        <span class="metric-value" id="duration">0s</span>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-card">
                <div class="card-title">🚀 实时指标</div>
                <div class="metrics-grid">
                    <div class="metric-item">
                        <span class="metric-name">CPU</span>
                        <span class="metric-value" id="cpuUsage">0%</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-name">内存</span>
                        <span class="metric-value" id="memoryUsage">0MB</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-name">连接</span>
                        <span class="metric-value" id="connections">0</span>
                    </div>
                    <div class="metric-item">
                        <span class="metric-name">响应</span>
                        <span class="metric-value" id="responseTime">0ms</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <div class="dashboard-card">
                <div class="card-title">🕰️ 测试时间线</div>
                <div class="timeline" id="timeline">
                    <div class="timeline-item">
                        <div class="timeline-time">--:--</div>
                        <div class="timeline-content">
                            <div class="timeline-title">等待测试开始...</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-card full-width">
                <div class="card-title">📈 性能趋势</div>
                <div class="chart-container">
                    <canvas id="metricsChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="dashboard-grid">
            <div class="dashboard-card full-width">
                <div class="card-title">📄 测试报告</div>
                <div class="reports-list" id="reportsList">
                    <div style="text-align: center; color: #64748b; padding: 20px;">暂无报告</div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const socket = io();
        let metricsChart;
        
        // 初始化图表
        const ctx = document.getElementById('metricsChart').getContext('2d');
        metricsChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'CPU使用率 (%)',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    tension: 0.4
                }, {
                    label: '内存使用 (MB)',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    tension: 0.4
                }, {
                    label: '响应时间 (ms)',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: '#94a3b8'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#64748b' },
                        grid: { color: '#334155' }
                    },
                    y: {
                        ticks: { color: '#64748b' },
                        grid: { color: '#334155' }
                    }
                }
            }
        });
        
        // Socket 事件处理
        socket.on('connect', () => {
            document.getElementById('connectionStatus').textContent = '🔗 已连接';
            document.getElementById('connectionStatus').className = 'connection-status connected';
        });
        
        socket.on('disconnect', () => {
            document.getElementById('connectionStatus').textContent = '❌ 连接断开';
            document.getElementById('connectionStatus').className = 'connection-status disconnected';
        });
        
        socket.on('dashboard-update', (data) => {
            updateDashboard(data);
        });
        
        function updateDashboard(data) {
            // 更新状态
            const statusIndicator = document.getElementById('statusIndicator');
            const statusText = document.getElementById('statusText');
            
            statusIndicator.className = `status-indicator status-${data.status}`;
            const statusMap = {
                idle: '系统就绪',
                running: '测试运行中',
                passed: '测试通过',
                failed: '测试失败'
            };
            statusText.textContent = statusMap[data.status] || '未知状态';
            
            // 更新进度
            document.getElementById('progressPercent').textContent = `${Math.round(data.progress)}%`;
            document.getElementById('progressBar').style.width = `${data.progress}%`;
            document.getElementById('progressText').textContent = 
                data.status === 'running' ? `正在执行: ${data.currentSuite?.name || '未知测试'}` : '测试完成';
            
            // 更新指标
            document.getElementById('totalTests').textContent = data.metrics.totalTests;
            document.getElementById('passedTests').textContent = data.metrics.passedTests;
            document.getElementById('failedTests').textContent = data.metrics.failedTests;
            document.getElementById('duration').textContent = `${Math.round(data.metrics.totalDuration / 1000)}s`;
            
            // 更新实时指标
            if (data.liveMetrics && data.liveMetrics.length > 0) {
                const latest = data.liveMetrics[data.liveMetrics.length - 1];
                document.getElementById('cpuUsage').textContent = `${latest.cpu}%`;
                document.getElementById('memoryUsage').textContent = `${latest.memory}MB`;
                document.getElementById('connections').textContent = latest.activeConnections;
                document.getElementById('responseTime').textContent = `${latest.responseTime}ms`;
                
                // 更新图表
                updateChart(data.liveMetrics);
            }
            
            // 更新时间线
            updateTimeline(data.results);
        }
        
        function updateChart(metrics) {
            const labels = metrics.map(m => new Date(m.timestamp).toLocaleTimeString());
            
            metricsChart.data.labels = labels.slice(-20); // 只显示最后20个数据点
            metricsChart.data.datasets[0].data = metrics.map(m => m.cpu).slice(-20);
            metricsChart.data.datasets[1].data = metrics.map(m => m.memory).slice(-20);
            metricsChart.data.datasets[2].data = metrics.map(m => m.responseTime).slice(-20);
            
            metricsChart.update('none');
        }
        
        function updateTimeline(results) {
            const timeline = document.getElementById('timeline');
            
            if (!results || results.length === 0) {
                return;
            }
            
            timeline.innerHTML = results.map((result, index) => `
                <div class="timeline-item ${result.status === 'running' ? 'active' : ''}">
                    <div class="timeline-time">${new Date().toLocaleTimeString()}</div>
                    <div class="timeline-content">
                        <div class="timeline-title">${result.name}</div>
                        <div class="timeline-desc">${result.description || '测试执行中...'}</div>
                    </div>
                </div>
            `).join('');
        }
        
        // 定时请求更新
        setInterval(() => {
            socket.emit('request-update');
        }, 2000);
        
        // 加载报告列表
        async function loadReports() {
            try {
                const response = await fetch('/api/reports');
                const reports = await response.json();
                
                const reportsList = document.getElementById('reportsList');
                
                if (reports.length === 0) {
                    reportsList.innerHTML = '<div style="text-align: center; color: #64748b; padding: 20px;">暂无报告</div>';
                    return;
                }
                
                reportsList.innerHTML = reports.map(report => `
                    <div class="report-item">
                        <div>
                            <div class="report-name">${report.name}</div>
                            <div class="report-time">${new Date(report.timestamp).toLocaleString()}</div>
                        </div>
                        <a href="${report.path}" class="report-link" target="_blank">查看</a>
                    </div>
                `).join('');
            } catch (error) {
                console.error('加载报告列表失败:', error);
            }
        }
        
        // 初始化加载
        loadReports();
        setInterval(loadReports, 10000); // 每10秒更新报告列表
    </script>
</body>
</html>
    `;
  }

  private startMetricsCollection(): void {
    // 模拟实时指标收集
    setInterval(() => {
      const timestamp = Date.now();
      const metric = {
        timestamp,
        cpu: Math.floor(Math.random() * 100),
        memory: Math.floor(Math.random() * 1024) + 500,
        activeConnections: this.clients.size,
        responseTime: Math.floor(Math.random() * 500) + 50
      };
      
      this.dashboardData.liveMetrics.push(metric);
      
      // 保持最近50个数据点
      if (this.dashboardData.liveMetrics.length > 50) {
        this.dashboardData.liveMetrics.shift();
      }
      
      // 广播更新
      this.io.emit('dashboard-update', this.dashboardData);
    }, 2000);
    
    // 监听报告文件变化
    this.watchReportFiles();
  }

  private async watchReportFiles(): Promise<void> {
    try {
      await fs.mkdir(this.reportDir, { recursive: true });
      
      watch(this.reportDir, (eventType, filename) => {
        if (filename && filename.includes('dashboard.json')) {
          this.loadDashboardData();
        }
      });
    } catch (error) {
      console.error(chalk.red('无法监听报告文件:'), error);
    }
  }

  private async loadDashboardData(): Promise<void> {
    try {
      const dashboardFile = path.join(this.reportDir, 'dashboard.json');
      const content = await fs.readFile(dashboardFile, 'utf8');
      const newData = JSON.parse(content);
      
      // 合并数据，保持实时指标
      this.dashboardData = {
        ...newData,
        liveMetrics: this.dashboardData.liveMetrics
      };
      
      // 广播更新
      this.io.emit('dashboard-update', this.dashboardData);
    } catch (error) {
      // 忽略文件读取错误，可能是文件正在写入
    }
  }

  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server.listen(this.port, () => {
        console.log(chalk.green(`\n📈 SmellPin 测试仪表盘已启动`));
        console.log(chalk.blue(`🌐 访问地址: http://localhost:${this.port}`));
        console.log(chalk.gray(`📁 报告目录: ${this.reportDir}\n`));
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server.close(() => {
        console.log(chalk.yellow('📈 测试仪表盘已停止'));
        resolve();
      });
    });
  }

  updateStatus(status: DashboardData['status'], progress: number = 0): void {
    this.dashboardData.status = status;
    this.dashboardData.progress = progress;
    this.io.emit('dashboard-update', this.dashboardData);
  }
}

// 全局实例
export const testDashboard = new TestDashboard();

// CLI模式
if (require.main === module) {
  const port = parseInt(process.argv[2]) || 3333;
  const reportDir = process.argv[3] || './test-results';
  
  const dashboard = new TestDashboard(port, reportDir);
  
  dashboard.start().then(() => {
    console.log(chalk.green('🚀 仪表盘启动成功！'));
  }).catch((error) => {
    console.error(chalk.red('仪表盘启动失败:'), error);
    process.exit(1);
  });
  
  // 优雅关闭
  process.on('SIGINT', async () => {
    console.log(chalk.yellow('\n正在关闭仪表盘...'));
    await dashboard.stop();
    process.exit(0);
  });
}
