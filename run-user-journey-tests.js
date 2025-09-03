#!/usr/bin/env node

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🎯 SmellPin 用户路径测试执行器');
console.log('=====================================\n');

// 检查依赖
function checkDependencies() {
  console.log('📋 检查测试环境...');
  
  try {
    // 检查Node.js版本
    const nodeVersion = process.version;
    console.log(`✅ Node.js版本: ${nodeVersion}`);
    
    // 检查Playwright是否已安装
    const playwrightVersion = execSync('npx playwright --version', { encoding: 'utf8' }).trim();
    console.log(`✅ Playwright版本: ${playwrightVersion}`);
    
    // 检查TypeScript编译器
    try {
      const tsVersion = execSync('npx tsc --version', { encoding: 'utf8' }).trim();
      console.log(`✅ TypeScript版本: ${tsVersion}`);
    } catch (error) {
      console.log('⚠️  TypeScript未找到，将使用ts-node');
    }
    
  } catch (error) {
    console.error('❌ 依赖检查失败:', error.message);
    console.log('\n请运行以下命令安装依赖:');
    console.log('npm install');
    console.log('npx playwright install');
    process.exit(1);
  }
}

// 启动服务
async function startServices() {
  console.log('\n🚀 启动测试服务...');
  
  return new Promise((resolve, reject) => {
    // 启动后端服务
    const backend = spawn('npm', ['run', 'dev'], {
      stdio: 'pipe',
      env: { ...process.env, PORT: '3000' }
    });
    
    // 启动前端服务  
    const frontend = spawn('npm', ['run', 'dev'], {
      cwd: path.join(__dirname, 'frontend'),
      stdio: 'pipe',
      env: { ...process.env, PORT: '3001' }
    });
    
    let backendReady = false;
    let frontendReady = false;
    
    backend.stdout.on('data', (data) => {
      const output = data.toString();
      if (output.includes('Server running') || output.includes('ready')) {
        backendReady = true;
        console.log('✅ 后端服务已启动 (http://localhost:3000)');
        
        if (frontendReady) {
          resolve({ backend, frontend });
        }
      }
    });
    
    frontend.stdout.on('data', (data) => {
      const output = data.toString();
      if (output.includes('ready') || output.includes('Local:')) {
        frontendReady = true;
        console.log('✅ 前端服务已启动 (http://localhost:3001)');
        
        if (backendReady) {
          resolve({ backend, frontend });
        }
      }
    });
    
    // 错误处理
    backend.on('error', reject);
    frontend.on('error', reject);
    
    // 超时处理
    setTimeout(() => {
      if (!backendReady || !frontendReady) {
        reject(new Error('服务启动超时'));
      }
    }, 30000);
  });
}

// 等待服务就绪
async function waitForServices() {
  console.log('⏳ 等待服务完全就绪...');
  
  const maxRetries = 30;
  let retries = 0;
  
  while (retries < maxRetries) {
    try {
      // 检查后端API
      const http = require('http');
      await new Promise((resolve, reject) => {
        const req = http.get('http://localhost:3000/health', (res) => {
          if (res.statusCode === 200) {
            resolve();
          } else {
            reject(new Error(`Backend responded with status ${res.statusCode}`));
          }
        });
        req.on('error', reject);
        req.setTimeout(2000, () => req.destroy());
      });
      
      // 检查前端应用
      await new Promise((resolve, reject) => {
        const req = http.get('http://localhost:3001', (res) => {
          if (res.statusCode === 200) {
            resolve();
          } else {
            reject(new Error(`Frontend responded with status ${res.statusCode}`));
          }
        });
        req.on('error', reject);
        req.setTimeout(2000, () => req.destroy());
      });
      
      console.log('✅ 所有服务已就绪');
      return;
      
    } catch (error) {
      retries++;
      console.log(`⏳ 等待服务就绪... (${retries}/${maxRetries})`);
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }
  
  throw new Error('服务未能及时启动');
}

// 运行用户路径测试
async function runUserJourneyTests() {
  console.log('\n🎪 开始执行用户路径测试...');
  
  try {
    // 创建测试结果目录
    const testResultsDir = path.join(__dirname, 'test-results');
    if (!fs.existsSync(testResultsDir)) {
      fs.mkdirSync(testResultsDir, { recursive: true });
    }
    
    // 运行综合测试套件
    console.log('📊 执行综合测试运行器...');
    const runnerResult = execSync('npx ts-node tests/e2e/user-journey-runner.ts', {
      encoding: 'utf8',
      stdio: 'inherit',
      timeout: 300000 // 5分钟超时
    });
    
    console.log('\n📋 执行Playwright测试套件...');
    const playwrightResult = execSync('npx playwright test --config=playwright.config.ts', {
      encoding: 'utf8',
      stdio: 'inherit',
      timeout: 600000 // 10分钟超时
    });
    
    return true;
    
  } catch (error) {
    console.error('❌ 用户路径测试执行失败:', error.message);
    return false;
  }
}

// 生成测试报告
function generateFinalReport() {
  console.log('\n📊 生成最终测试报告...');
  
  const reportDir = path.join(__dirname, 'test-results');
  const reports = [];
  
  try {
    // 查找所有测试结果文件
    if (fs.existsSync(reportDir)) {
      const files = fs.readdirSync(reportDir, { recursive: true });
      
      files.forEach(file => {
        if (typeof file === 'string' && file.endsWith('.json')) {
          const filePath = path.join(reportDir, file);
          try {
            const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            reports.push({
              file: file,
              content: content
            });
          } catch (e) {
            console.log(`⚠️  无法解析报告文件: ${file}`);
          }
        }
      });
    }
    
    // 生成综合报告
    const finalReport = {
      timestamp: new Date().toISOString(),
      summary: {
        totalReports: reports.length,
        testExecutionTime: new Date().toLocaleString('zh-CN'),
        environment: {
          nodeVersion: process.version,
          platform: process.platform,
          arch: process.arch
        }
      },
      reports: reports
    };
    
    const finalReportPath = path.join(reportDir, 'final-user-journey-report.json');
    fs.writeFileSync(finalReportPath, JSON.stringify(finalReport, null, 2));
    
    console.log(`✅ 最终报告已生成: ${finalReportPath}`);
    
    // 显示报告摘要
    console.log('\n📈 测试结果摘要:');
    console.log(`   • 总报告数量: ${reports.length}`);
    console.log(`   • 执行时间: ${new Date().toLocaleString('zh-CN')}`);
    console.log(`   • 环境信息: ${process.platform} ${process.arch}`);
    
    return finalReportPath;
    
  } catch (error) {
    console.error('❌ 生成最终报告失败:', error.message);
    return null;
  }
}

// 清理资源
function cleanup(services) {
  console.log('\n🧹 清理测试环境...');
  
  if (services) {
    if (services.backend) {
      services.backend.kill('SIGTERM');
      console.log('✅ 后端服务已关闭');
    }
    
    if (services.frontend) {
      services.frontend.kill('SIGTERM');
      console.log('✅ 前端服务已关闭');
    }
  }
}

// 主执行函数
async function main() {
  let services = null;
  
  try {
    // 1. 检查环境
    checkDependencies();
    
    // 2. 启动服务
    services = await startServices();
    await waitForServices();
    
    // 3. 执行测试
    const testSuccess = await runUserJourneyTests();
    
    // 4. 生成报告
    const finalReportPath = generateFinalReport();
    
    // 5. 输出结果
    console.log('\n' + '='.repeat(50));
    console.log('🎉 SmellPin 用户路径测试执行完成!');
    console.log('='.repeat(50));
    
    if (testSuccess) {
      console.log('✅ 测试执行状态: 成功');
    } else {
      console.log('⚠️  测试执行状态: 部分失败');
    }
    
    if (finalReportPath) {
      console.log(`📊 最终报告位置: ${finalReportPath}`);
    }
    
    console.log('\n可用的报告查看命令:');
    console.log('• HTML报告: npx playwright show-report');
    console.log('• JSON报告: cat test-results/final-user-journey-report.json');
    console.log('• 截图目录: ls test-results/screenshots/');
    
    return testSuccess ? 0 : 1;
    
  } catch (error) {
    console.error('\n❌ 测试执行发生错误:', error.message);
    return 1;
    
  } finally {
    cleanup(services);
  }
}

// 处理程序退出
process.on('SIGINT', () => {
  console.log('\n⏹️  接收到中断信号，正在清理...');
  process.exit(1);
});

process.on('SIGTERM', () => {
  console.log('\n⏹️  接收到终止信号，正在清理...');
  process.exit(1);
});

// 如果直接运行此脚本
if (require.main === module) {
  main().then(exitCode => {
    process.exit(exitCode);
  }).catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}

module.exports = { main };