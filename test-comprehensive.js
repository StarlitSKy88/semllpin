const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// 导入各个测试模块
const { runTests: runEndToEndTests } = require('./test-end-to-end');
const { runDatabaseValidationTests } = require('./test-database-validation');
const { runE2EIntegrationTests } = require('./test-e2e-integration');
const { runThirdPartyIntegrationTests } = require('./test-third-party-integrations');

// 测试配置
const TEST_CONFIG = {
  timeout: 300000, // 5分钟总超时
  retries: 2, // 失败重试次数
  parallel: false, // 是否并行运行测试
  generateReport: true,
  saveResults: true
};

// 全局测试结果
const comprehensiveResults = {
  startTime: null,
  endTime: null,
  duration: null,
  testSuites: {},
  summary: {
    totalSuites: 0,
    passedSuites: 0,
    failedSuites: 0,
    totalTests: 0,
    passedTests: 0,
    failedTests: 0,
    overallSuccessRate: 0
  },
  environment: {
    nodeVersion: process.version,
    platform: process.platform,
    timestamp: new Date().toISOString()
  },
  recommendations: []
};

// 工具函数
function logSection(title) {
  console.log('\n' + '='.repeat(60));
  console.log(`  ${title}`);
  console.log('='.repeat(60) + '\n');
}

function logSubSection(title) {
  console.log('\n' + '-'.repeat(40));
  console.log(`  ${title}`);
  console.log('-'.repeat(40));
}

function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  
  if (minutes > 0) {
    return `${minutes}分${remainingSeconds}秒`;
  }
  return `${remainingSeconds}秒`;
}

// 运行单个测试套件
async function runTestSuite(suiteName, testFunction, description) {
  logSubSection(`运行 ${suiteName} 测试`);
  
  const suiteResult = {
    name: suiteName,
    description,
    startTime: Date.now(),
    endTime: null,
    duration: null,
    success: false,
    error: null,
    report: null,
    retries: 0
  };
  
  let lastError = null;
  
  // 重试机制
  for (let attempt = 0; attempt <= TEST_CONFIG.retries; attempt++) {
    try {
      if (attempt > 0) {
        console.log(`\n重试第 ${attempt} 次...`);
        suiteResult.retries = attempt;
      }
      
      const report = await Promise.race([
        testFunction(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error('测试超时')), TEST_CONFIG.timeout)
        )
      ]);
      
      suiteResult.endTime = Date.now();
      suiteResult.duration = suiteResult.endTime - suiteResult.startTime;
      suiteResult.success = true;
      suiteResult.report = report;
      
      console.log(`✓ ${suiteName} 测试完成 (${formatDuration(suiteResult.duration)})`);
      break;
      
    } catch (error) {
      lastError = error;
      console.log(`✗ ${suiteName} 测试失败: ${error.message}`);
      
      if (attempt === TEST_CONFIG.retries) {
        suiteResult.endTime = Date.now();
        suiteResult.duration = suiteResult.endTime - suiteResult.startTime;
        suiteResult.success = false;
        suiteResult.error = error.message;
        console.log(`✗ ${suiteName} 测试最终失败`);
      }
    }
  }
  
  comprehensiveResults.testSuites[suiteName] = suiteResult;
  return suiteResult;
}

// 检查服务器状态
async function checkServerStatus() {
  logSubSection('检查服务器状态');
  
  try {
    const axios = require('axios');
    const response = await axios.get('http://localhost:8787/health', {
      timeout: 5000
    });
    
    if (response.status === 200) {
      console.log('✓ 服务器运行正常');
      return true;
    } else {
      console.log('⚠ 服务器响应异常');
      return false;
    }
  } catch (error) {
    console.log('✗ 服务器连接失败:', error.message);
    return false;
  }
}

// 检查数据库连接
async function checkDatabaseConnection() {
  logSubSection('检查数据库连接');
  
  try {
    const axios = require('axios');
    const response = await axios.get('http://localhost:8787/api/health/database', {
      timeout: 10000
    });
    
    if (response.status === 200 && response.data?.connected) {
      console.log('✓ 数据库连接正常');
      return true;
    } else {
      console.log('⚠ 数据库连接异常');
      return false;
    }
  } catch (error) {
    console.log('✗ 数据库连接检查失败:', error.message);
    return false;
  }
}

// 运行预检查
async function runPreChecks() {
  logSection('系统预检查');
  
  const checks = {
    server: await checkServerStatus(),
    database: await checkDatabaseConnection()
  };
  
  const allPassed = Object.values(checks).every(check => check);
  
  if (!allPassed) {
    console.log('\n⚠ 预检查发现问题，某些测试可能会失败');
    console.log('建议先解决以下问题:');
    if (!checks.server) console.log('- 启动后端服务器');
    if (!checks.database) console.log('- 检查数据库连接配置');
  } else {
    console.log('\n✓ 所有预检查通过');
  }
  
  return checks;
}

// 计算测试统计
function calculateStatistics() {
  const suites = Object.values(comprehensiveResults.testSuites);
  
  comprehensiveResults.summary.totalSuites = suites.length;
  comprehensiveResults.summary.passedSuites = suites.filter(s => s.success).length;
  comprehensiveResults.summary.failedSuites = suites.filter(s => !s.success).length;
  
  // 计算总测试数
  suites.forEach(suite => {
    if (suite.report && suite.report.summary) {
      comprehensiveResults.summary.totalTests += suite.report.summary.totalTests || 0;
      comprehensiveResults.summary.passedTests += suite.report.summary.passedTests || 0;
      comprehensiveResults.summary.failedTests += suite.report.summary.failedTests || 0;
    }
  });
  
  // 计算成功率
  if (comprehensiveResults.summary.totalTests > 0) {
    comprehensiveResults.summary.overallSuccessRate = 
      ((comprehensiveResults.summary.passedTests / comprehensiveResults.summary.totalTests) * 100).toFixed(2);
  }
}

// 生成建议
function generateRecommendations() {
  const recommendations = [];
  const suites = Object.values(comprehensiveResults.testSuites);
  
  // 检查失败的测试套件
  const failedSuites = suites.filter(s => !s.success);
  if (failedSuites.length > 0) {
    recommendations.push({
      type: 'critical',
      title: '测试套件失败',
      message: `有 ${failedSuites.length} 个测试套件失败`,
      details: failedSuites.map(s => `${s.name}: ${s.error}`),
      action: '检查失败原因并修复相关问题'
    });
  }
  
  // 检查成功率
  const successRate = parseFloat(comprehensiveResults.summary.overallSuccessRate);
  if (successRate < 80) {
    recommendations.push({
      type: 'warning',
      title: '测试成功率偏低',
      message: `当前成功率为 ${successRate}%，建议提升至 90% 以上`,
      action: '分析失败测试，优化代码质量和测试稳定性'
    });
  }
  
  // 检查性能问题
  const slowSuites = suites.filter(s => s.duration > 60000); // 超过1分钟
  if (slowSuites.length > 0) {
    recommendations.push({
      type: 'performance',
      title: '测试执行时间过长',
      message: `有 ${slowSuites.length} 个测试套件执行时间超过1分钟`,
      details: slowSuites.map(s => `${s.name}: ${formatDuration(s.duration)}`),
      action: '优化测试性能，考虑并行执行或减少测试范围'
    });
  }
  
  // 检查重试情况
  const retriedSuites = suites.filter(s => s.retries > 0);
  if (retriedSuites.length > 0) {
    recommendations.push({
      type: 'stability',
      title: '测试稳定性问题',
      message: `有 ${retriedSuites.length} 个测试套件需要重试`,
      details: retriedSuites.map(s => `${s.name}: 重试 ${s.retries} 次`),
      action: '检查测试环境稳定性和网络连接'
    });
  }
  
  // 如果所有测试都通过，给出优化建议
  if (recommendations.length === 0 && successRate >= 95) {
    recommendations.push({
      type: 'optimization',
      title: '测试质量优秀',
      message: '所有测试都通过，系统质量良好',
      action: '可以考虑添加更多边界情况测试和性能测试'
    });
  }
  
  comprehensiveResults.recommendations = recommendations;
}

// 生成综合报告
function generateComprehensiveReport() {
  calculateStatistics();
  generateRecommendations();
  
  const report = {
    ...comprehensiveResults,
    generatedAt: new Date().toISOString()
  };
  
  // 保存报告
  if (TEST_CONFIG.saveResults) {
    const reportPath = path.join(__dirname, 'comprehensive-test-report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    
    // 生成简化的Markdown报告
    const markdownReport = generateMarkdownReport(report);
    const markdownPath = path.join(__dirname, 'COMPREHENSIVE_TEST_REPORT.md');
    fs.writeFileSync(markdownPath, markdownReport);
    
    console.log(`\n📊 详细报告已保存到: ${reportPath}`);
    console.log(`📄 Markdown报告已保存到: ${markdownPath}`);
  }
  
  return report;
}

// 生成Markdown报告
function generateMarkdownReport(report) {
  const { summary, testSuites, recommendations, duration } = report;
  
  let markdown = `# SmellPin 综合测试报告\n\n`;
  markdown += `**生成时间**: ${new Date(report.generatedAt).toLocaleString('zh-CN')}\n`;
  markdown += `**测试时长**: ${formatDuration(duration)}\n\n`;
  
  // 概览
  markdown += `## 📊 测试概览\n\n`;
  markdown += `| 指标 | 数值 |\n`;
  markdown += `|------|------|\n`;
  markdown += `| 测试套件总数 | ${summary.totalSuites} |\n`;
  markdown += `| 通过套件 | ${summary.passedSuites} |\n`;
  markdown += `| 失败套件 | ${summary.failedSuites} |\n`;
  markdown += `| 测试用例总数 | ${summary.totalTests} |\n`;
  markdown += `| 通过用例 | ${summary.passedTests} |\n`;
  markdown += `| 失败用例 | ${summary.failedTests} |\n`;
  markdown += `| 整体成功率 | ${summary.overallSuccessRate}% |\n\n`;
  
  // 测试套件详情
  markdown += `## 🧪 测试套件详情\n\n`;
  Object.values(testSuites).forEach(suite => {
    const status = suite.success ? '✅' : '❌';
    const retryInfo = suite.retries > 0 ? ` (重试${suite.retries}次)` : '';
    markdown += `### ${status} ${suite.name}${retryInfo}\n\n`;
    markdown += `- **描述**: ${suite.description}\n`;
    markdown += `- **执行时间**: ${formatDuration(suite.duration)}\n`;
    if (!suite.success) {
      markdown += `- **错误信息**: ${suite.error}\n`;
    }
    if (suite.report && suite.report.summary) {
      markdown += `- **测试结果**: ${suite.report.summary.passedTests}/${suite.report.summary.totalTests} 通过\n`;
    }
    markdown += `\n`;
  });
  
  // 建议
  if (recommendations.length > 0) {
    markdown += `## 💡 改进建议\n\n`;
    recommendations.forEach((rec, index) => {
      const icon = rec.type === 'critical' ? '🚨' : 
                  rec.type === 'warning' ? '⚠️' : 
                  rec.type === 'performance' ? '⚡' : 
                  rec.type === 'stability' ? '🔄' : '✨';
      
      markdown += `### ${icon} ${rec.title}\n\n`;
      markdown += `${rec.message}\n\n`;
      if (rec.details) {
        markdown += `**详细信息**:\n`;
        rec.details.forEach(detail => {
          markdown += `- ${detail}\n`;
        });
        markdown += `\n`;
      }
      markdown += `**建议操作**: ${rec.action}\n\n`;
    });
  }
  
  return markdown;
}

// 显示测试结果
function displayResults() {
  logSection('综合测试结果');
  
  const { summary } = comprehensiveResults;
  
  console.log(`📊 测试概览:`);
  console.log(`   测试套件: ${summary.passedSuites}/${summary.totalSuites} 通过`);
  console.log(`   测试用例: ${summary.passedTests}/${summary.totalTests} 通过`);
  console.log(`   整体成功率: ${summary.overallSuccessRate}%`);
  console.log(`   总耗时: ${formatDuration(comprehensiveResults.duration)}`);
  
  console.log(`\n🧪 各测试套件结果:`);
  Object.values(comprehensiveResults.testSuites).forEach(suite => {
    const status = suite.success ? '✅' : '❌';
    const retryInfo = suite.retries > 0 ? ` (重试${suite.retries}次)` : '';
    console.log(`   ${status} ${suite.name} - ${formatDuration(suite.duration)}${retryInfo}`);
    if (!suite.success) {
      console.log(`      错误: ${suite.error}`);
    }
  });
  
  if (comprehensiveResults.recommendations.length > 0) {
    console.log(`\n💡 改进建议:`);
    comprehensiveResults.recommendations.forEach(rec => {
      const icon = rec.type === 'critical' ? '🚨' : 
                  rec.type === 'warning' ? '⚠️' : '💡';
      console.log(`   ${icon} ${rec.title}: ${rec.message}`);
    });
  }
}

// 主测试函数
async function runComprehensiveTests() {
  comprehensiveResults.startTime = Date.now();
  
  logSection('SmellPin 综合测试开始');
  
  try {
    // 运行预检查
    const preChecks = await runPreChecks();
    
    // 定义测试套件
    const testSuites = [
      {
        name: 'database-validation',
        description: '数据库验证和数据真实性测试',
        function: runDatabaseValidationTests
      },
      {
        name: 'end-to-end',
        description: '端到端业务流程测试',
        function: runEndToEndTests
      },
      {
        name: 'e2e-integration',
        description: '端到端集成测试',
        function: runE2EIntegrationTests
      },
      {
        name: 'third-party-integration',
        description: '第三方服务集成测试',
        function: runThirdPartyIntegrationTests
      }
    ];
    
    // 运行测试套件
    if (TEST_CONFIG.parallel) {
      // 并行运行（可能会有资源竞争）
      const promises = testSuites.map(suite => 
        runTestSuite(suite.name, suite.function, suite.description)
      );
      await Promise.allSettled(promises);
    } else {
      // 串行运行（推荐）
      for (const suite of testSuites) {
        await runTestSuite(suite.name, suite.function, suite.description);
      }
    }
    
    comprehensiveResults.endTime = Date.now();
    comprehensiveResults.duration = comprehensiveResults.endTime - comprehensiveResults.startTime;
    
    // 生成报告
    const report = generateComprehensiveReport();
    
    // 显示结果
    displayResults();
    
    logSection('综合测试完成');
    
    return report;
    
  } catch (error) {
    console.error('综合测试过程中发生错误:', error);
    comprehensiveResults.endTime = Date.now();
    comprehensiveResults.duration = comprehensiveResults.endTime - comprehensiveResults.startTime;
    return null;
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  runComprehensiveTests()
    .then(report => {
      if (report) {
        const exitCode = report.summary.failedSuites > 0 ? 1 : 0;
        process.exit(exitCode);
      } else {
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('测试失败:', error);
      process.exit(1);
    });
}

module.exports = {
  runComprehensiveTests,
  TEST_CONFIG
};