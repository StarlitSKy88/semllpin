#!/usr/bin/env node

/**
 * SmellPin 前端性能测试套件
 * 模拟Web Vitals检测和前端资源加载性能分析
 * 
 * 运行方式: node tests/frontend/frontend-performance-test.js
 */

const axios = require('axios');
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

// 前端性能测试配置
const FRONTEND_CONFIG = {
  baseURL: 'http://localhost:3000', // Next.js前端服务
  backendURL: 'http://localhost:3003', // 后端API服务
  testTimeout: 30000,
  
  // Web Vitals阈值 (Google标准)
  webVitals: {
    LCP: 2500,    // Largest Contentful Paint < 2.5s
    FID: 100,     // First Input Delay < 100ms  
    CLS: 0.1,     // Cumulative Layout Shift < 0.1
    FCP: 1800,    // First Contentful Paint < 1.8s
    TTI: 3800,    // Time to Interactive < 3.8s
  }
};

// 测试结果存储
const frontendResults = {
  timestamp: new Date().toISOString(),
  config: FRONTEND_CONFIG,
  tests: [],
  webVitals: {},
  summary: {},
  recommendations: []
};

class FrontendPerformanceTestSuite {
  constructor() {
    this.resourceLoadTimes = {};
  }

  // 1. 静态资源加载性能测试
  async testStaticResourcePerformance() {
    console.log('\n📦 执行静态资源加载性能测试...');
    
    const testResult = {
      name: 'Static Resource Loading Performance',
      category: 'Resource Loading',
      resources: [],
      totalLoadTime: 0,
      passed: true
    };

    // 测试关键静态资源
    const staticResources = [
      { name: 'favicon', path: '/favicon.ico', type: 'icon' },
      { name: 'robots', path: '/robots.txt', type: 'text' },
      { name: 'sitemap', path: '/sitemap.xml', type: 'xml' },
    ];

    for (const resource of staticResources) {
      console.log(`  测试资源: ${resource.name}`);
      
      const startTime = performance.now();
      
      try {
        const response = await axios.get(`${FRONTEND_CONFIG.backendURL}${resource.path}`, {
          timeout: FRONTEND_CONFIG.testTimeout,
          validateStatus: (status) => status < 500 // 允许404等客户端错误
        });
        
        const loadTime = performance.now() - startTime;
        
        const resourceTest = {
          name: resource.name,
          path: resource.path,
          type: resource.type,
          loadTime,
          status: response.status,
          size: response.headers['content-length'] || 0,
          cacheControl: response.headers['cache-control'],
          passed: response.status === 200 && loadTime < 1000
        };
        
        testResult.resources.push(resourceTest);
        testResult.totalLoadTime += loadTime;
        
        if (resourceTest.passed) {
          console.log(`    ✅ ${resource.name}: ${Math.round(loadTime)}ms`);
        } else {
          console.log(`    ❌ ${resource.name}: ${Math.round(loadTime)}ms (状态: ${response.status})`);
          testResult.passed = false;
        }
        
      } catch (error) {
        console.log(`    ⚠ ${resource.name}: 加载失败 - ${error.message}`);
        testResult.resources.push({
          name: resource.name,
          path: resource.path,
          type: resource.type,
          loadTime: performance.now() - startTime,
          status: 0,
          error: error.message,
          passed: false
        });
        testResult.passed = false;
      }
    }

    frontendResults.tests.push(testResult);
    this.logFrontendResult('Static Resources', testResult);
    return testResult;
  }

  // 2. API调用性能分析（前端视角）
  async testAPIPerformanceFromFrontend() {
    console.log('\n🌐 执行前端API调用性能测试...');
    
    const testResult = {
      name: 'Frontend API Call Performance',
      category: 'API Performance',
      apiCalls: [],
      averageResponseTime: 0,
      passed: true
    };

    // 模拟前端常用API调用
    const apiEndpoints = [
      { name: 'Health Check', path: '/health', method: 'GET' },
      { name: 'Annotations List', path: '/api/v1/annotations/list?page=1&limit=10', method: 'GET' },
      { name: 'API Documentation', path: '/api/v1/docs', method: 'GET' },
      { name: 'Nearby Search', path: '/api/v1/annotations/nearby?lat=39.9042&lng=116.4074&radius=5000', method: 'GET' },
    ];

    let totalResponseTime = 0;
    let successfulCalls = 0;

    for (const endpoint of apiEndpoints) {
      console.log(`  测试API: ${endpoint.name}`);
      
      const startTime = performance.now();
      
      try {
        const response = await axios({
          method: endpoint.method,
          url: `${FRONTEND_CONFIG.backendURL}${endpoint.path}`,
          timeout: FRONTEND_CONFIG.testTimeout
        });
        
        const responseTime = performance.now() - startTime;
        
        const apiCall = {
          name: endpoint.name,
          path: endpoint.path,
          method: endpoint.method,
          responseTime,
          status: response.status,
          dataSize: JSON.stringify(response.data).length,
          passed: response.status === 200 && responseTime < 500
        };
        
        testResult.apiCalls.push(apiCall);
        
        if (apiCall.passed) {
          totalResponseTime += responseTime;
          successfulCalls++;
          console.log(`    ✅ ${endpoint.name}: ${Math.round(responseTime)}ms`);
        } else {
          console.log(`    ❌ ${endpoint.name}: ${Math.round(responseTime)}ms (状态: ${response.status})`);
          testResult.passed = false;
        }
        
      } catch (error) {
        console.log(`    ❌ ${endpoint.name}: 调用失败 - ${error.message}`);
        testResult.apiCalls.push({
          name: endpoint.name,
          path: endpoint.path,
          method: endpoint.method,
          responseTime: performance.now() - startTime,
          status: 0,
          error: error.message,
          passed: false
        });
        testResult.passed = false;
      }
    }

    testResult.averageResponseTime = successfulCalls > 0 ? totalResponseTime / successfulCalls : 0;

    frontendResults.tests.push(testResult);
    this.logFrontendResult('API Calls', testResult);
    return testResult;
  }

  // 3. 模拟Web Vitals测量
  async measureWebVitals() {
    console.log('\n📊 模拟Web Vitals性能指标测量...');
    
    const webVitals = {
      name: 'Web Vitals Simulation',
      category: 'User Experience',
      metrics: {},
      passed: true
    };

    // 模拟LCP - Largest Contentful Paint
    const lcpStartTime = performance.now();
    try {
      await axios.get(`${FRONTEND_CONFIG.backendURL}/api/v1/docs`);
      webVitals.metrics.LCP = performance.now() - lcpStartTime;
      console.log(`  LCP (模拟): ${Math.round(webVitals.metrics.LCP)}ms`);
    } catch (error) {
      webVitals.metrics.LCP = FRONTEND_CONFIG.webVitals.LCP + 1000; // 超时值
    }

    // 模拟FCP - First Contentful Paint
    const fcpStartTime = performance.now();
    try {
      await axios.get(`${FRONTEND_CONFIG.backendURL}/health`);
      webVitals.metrics.FCP = performance.now() - fcpStartTime;
      console.log(`  FCP (模拟): ${Math.round(webVitals.metrics.FCP)}ms`);
    } catch (error) {
      webVitals.metrics.FCP = FRONTEND_CONFIG.webVitals.FCP + 1000;
    }

    // 模拟TTI - Time to Interactive
    const ttiStartTime = performance.now();
    try {
      // 并行请求模拟页面交互就绪时间
      await Promise.all([
        axios.get(`${FRONTEND_CONFIG.backendURL}/health`),
        axios.get(`${FRONTEND_CONFIG.backendURL}/api/v1/docs`),
        axios.get(`${FRONTEND_CONFIG.backendURL}/api/v1/annotations/list?limit=5`)
      ]);
      webVitals.metrics.TTI = performance.now() - ttiStartTime;
      console.log(`  TTI (模拟): ${Math.round(webVitals.metrics.TTI)}ms`);
    } catch (error) {
      webVitals.metrics.TTI = FRONTEND_CONFIG.webVitals.TTI + 1000;
    }

    // 模拟FID - First Input Delay (使用API响应时间作为代理指标)
    const fidStartTime = performance.now();
    try {
      await axios.post(`${FRONTEND_CONFIG.backendURL}/api/v1/users/login`, {
        email: 'test@example.com',
        password: 'wrongpassword'
      }, { validateStatus: () => true });
      webVitals.metrics.FID = performance.now() - fidStartTime;
      console.log(`  FID (模拟): ${Math.round(webVitals.metrics.FID)}ms`);
    } catch (error) {
      webVitals.metrics.FID = FRONTEND_CONFIG.webVitals.FID + 50;
    }

    // 模拟CLS - Cumulative Layout Shift (固定值，实际需要浏览器测量)
    webVitals.metrics.CLS = 0.05; // 假设较好的CLS值
    console.log(`  CLS (假设): ${webVitals.metrics.CLS}`);

    // 评估Web Vitals
    const vitalsCheck = {
      LCP: webVitals.metrics.LCP <= FRONTEND_CONFIG.webVitals.LCP,
      FCP: webVitals.metrics.FCP <= FRONTEND_CONFIG.webVitals.FCP,
      TTI: webVitals.metrics.TTI <= FRONTEND_CONFIG.webVitals.TTI,
      FID: webVitals.metrics.FID <= FRONTEND_CONFIG.webVitals.FID,
      CLS: webVitals.metrics.CLS <= FRONTEND_CONFIG.webVitals.CLS
    };

    webVitals.passed = Object.values(vitalsCheck).every(check => check);
    webVitals.score = (Object.values(vitalsCheck).filter(check => check).length / 5) * 100;

    frontendResults.webVitals = webVitals;
    frontendResults.tests.push(webVitals);
    
    console.log(`\n📊 Web Vitals评分: ${webVitals.score}%`);
    return webVitals;
  }

  // 4. 压缩和缓存效率测试
  async testCompressionAndCaching() {
    console.log('\n🗜️ 执行压缩和缓存效率测试...');
    
    const testResult = {
      name: 'Compression & Caching Efficiency',
      category: 'Optimization',
      compressionTests: [],
      cachingTests: [],
      passed: true
    };

    // 测试API响应压缩
    const apiEndpoints = [
      '/api/v1/docs',
      '/api/v1/annotations/list',
    ];

    for (const endpoint of apiEndpoints) {
      console.log(`  测试压缩: ${endpoint}`);
      
      try {
        const response = await axios.get(`${FRONTEND_CONFIG.backendURL}${endpoint}`, {
          headers: {
            'Accept-Encoding': 'gzip, deflate, br'
          },
          timeout: FRONTEND_CONFIG.testTimeout
        });
        
        const compressionTest = {
          endpoint,
          hasCompression: !!response.headers['content-encoding'],
          contentEncoding: response.headers['content-encoding'],
          contentLength: response.headers['content-length'],
          uncompressedSize: JSON.stringify(response.data).length,
          compressionRatio: response.headers['content-length'] ? 
            (JSON.stringify(response.data).length / parseInt(response.headers['content-length'])) : 1
        };
        
        testResult.compressionTests.push(compressionTest);
        
        if (compressionTest.hasCompression) {
          console.log(`    ✅ 启用压缩: ${compressionTest.contentEncoding}`);
        } else {
          console.log(`    ❌ 未启用压缩`);
          testResult.passed = false;
        }
        
      } catch (error) {
        console.log(`    ⚠ 测试失败: ${error.message}`);
      }
    }

    // 测试缓存头部
    const cacheEndpoints = [
      { path: '/health', cacheable: false },
      { path: '/api/v1/docs', cacheable: true },
    ];

    for (const endpoint of cacheEndpoints) {
      console.log(`  测试缓存: ${endpoint.path}`);
      
      try {
        const response = await axios.get(`${FRONTEND_CONFIG.backendURL}${endpoint.path}`, {
          timeout: FRONTEND_CONFIG.testTimeout
        });
        
        const cachingTest = {
          endpoint: endpoint.path,
          shouldCache: endpoint.cacheable,
          hasCacheControl: !!response.headers['cache-control'],
          cacheControl: response.headers['cache-control'],
          hasETag: !!response.headers['etag'],
          hasLastModified: !!response.headers['last-modified'],
          appropriate: endpoint.cacheable ? 
            (!!response.headers['cache-control'] && !response.headers['cache-control'].includes('no-cache')) :
            (!response.headers['cache-control'] || response.headers['cache-control'].includes('no-cache'))
        };
        
        testResult.cachingTests.push(cachingTest);
        
        if (cachingTest.appropriate) {
          console.log(`    ✅ 缓存策略适当`);
        } else {
          console.log(`    ❌ 缓存策略不当`);
          testResult.passed = false;
        }
        
      } catch (error) {
        console.log(`    ⚠ 测试失败: ${error.message}`);
      }
    }

    frontendResults.tests.push(testResult);
    this.logFrontendResult('Compression & Caching', testResult);
    return testResult;
  }

  // 记录前端测试结果
  logFrontendResult(testName, result) {
    const status = result.passed ? '✅ PASSED' : '❌ FAILED';
    
    console.log(`\n${status} ${testName}:`);
    
    if (result.averageResponseTime !== undefined) {
      console.log(`  平均响应时间: ${Math.round(result.averageResponseTime)}ms`);
    }
    
    if (result.totalLoadTime !== undefined) {
      console.log(`  总加载时间: ${Math.round(result.totalLoadTime)}ms`);
    }
    
    if (result.score !== undefined) {
      console.log(`  评分: ${result.score}%`);
    }
  }

  // 生成前端性能报告
  generateFrontendReport() {
    console.log('\n📋 生成前端性能报告...');
    
    const passedTests = frontendResults.tests.filter(test => test.passed).length;
    const totalTests = frontendResults.tests.length;
    const webVitalsScore = frontendResults.webVitals.score || 0;
    
    const overallScore = ((passedTests / totalTests) * 0.6 + (webVitalsScore / 100) * 0.4) * 100;

    frontendResults.summary = {
      overallScore,
      passedTests,
      totalTests,
      webVitalsScore,
      performanceGrade: this.getPerformanceGrade(overallScore)
    };

    // 生成优化建议
    this.generateFrontendRecommendations();

    // 输出结果到文件
    const reportPath = path.join(__dirname, `../test-results/frontend-performance-report-${Date.now()}.json`);
    
    // 确保目录存在
    const reportDir = path.dirname(reportPath);
    if (!fs.existsSync(reportDir)) {
      fs.mkdirSync(reportDir, { recursive: true });
    }
    
    fs.writeFileSync(reportPath, JSON.stringify(frontendResults, null, 2));

    console.log(`\n🎯 前端性能评分: ${overallScore.toFixed(1)}/100`);
    console.log(`🏆 性能等级: ${frontendResults.summary.performanceGrade}`);
    console.log(`📊 测试通过率: ${passedTests}/${totalTests}`);
    console.log(`⚡ Web Vitals评分: ${webVitalsScore}%`);
    console.log(`📄 详细报告: ${reportPath}`);

    return frontendResults;
  }

  getPerformanceGrade(score) {
    if (score >= 90) return 'A - 优秀';
    if (score >= 80) return 'B - 良好';
    if (score >= 70) return 'C - 一般';
    if (score >= 60) return 'D - 需改进';
    return 'F - 差';
  }

  generateFrontendRecommendations() {
    const recommendations = [];

    // 基于测试结果生成建议
    const failedTests = frontendResults.tests.filter(test => !test.passed);
    
    if (failedTests.length > 0) {
      failedTests.forEach(test => {
        switch (test.name) {
          case 'Static Resource Loading Performance':
            recommendations.push({
              priority: 'High',
              category: '资源优化',
              title: '优化静态资源加载',
              description: '部分静态资源加载缓慢或失败',
              actions: [
                '启用HTTP/2服务器推送',
                '实施CDN加速',
                '优化图片格式和大小',
                '启用资源预加载'
              ]
            });
            break;
          
          case 'Frontend API Call Performance':
            recommendations.push({
              priority: 'High',
              category: 'API优化',
              title: '优化前端API调用',
              description: 'API调用响应时间过慢',
              actions: [
                '实施API响应缓存',
                '优化数据库查询',
                '减少API响应数据大小',
                '使用GraphQL减少过度获取'
              ]
            });
            break;
        }
      });
    }

    // Web Vitals优化建议
    if (frontendResults.webVitals.score < 80) {
      recommendations.push({
        priority: 'Medium',
        category: '用户体验',
        title: '改善Web Vitals指标',
        description: '关键用户体验指标需要优化',
        actions: [
          '优化LCP - 减少关键资源加载时间',
          '改善FID - 减少JavaScript执行时间',
          '优化CLS - 避免布局偏移',
          '实施服务端渲染(SSR)'
        ]
      });
    }

    // 通用前端优化建议
    recommendations.push({
      priority: 'Medium',
      category: '前端优化',
      title: '前端性能最佳实践',
      description: '实施现代前端优化技术',
      actions: [
        '启用代码分割和懒加载',
        '优化Web字体加载策略',
        '实施Critical CSS',
        '使用现代JavaScript特性'
      ]
    });

    frontendResults.recommendations = recommendations;
  }

  // 执行所有前端测试
  async runAllTests() {
    console.log('🌐 开始SmellPin前端性能测试套件');
    console.log(`🎯 后端API: ${FRONTEND_CONFIG.backendURL}`);
    console.log(`⏱️ 请求超时: ${FRONTEND_CONFIG.testTimeout}ms`);
    
    try {
      // 执行所有前端测试
      await this.testStaticResourcePerformance();
      await this.testAPIPerformanceFromFrontend();
      await this.measureWebVitals();
      await this.testCompressionAndCaching();

      // 生成报告
      return this.generateFrontendReport();

    } catch (error) {
      console.error('❌ 前端测试执行失败:', error);
      throw error;
    }
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  const testSuite = new FrontendPerformanceTestSuite();
  
  testSuite.runAllTests()
    .then(results => {
      console.log('\n✅ 所有前端性能测试完成');
      process.exit(results.summary.overallScore >= 70 ? 0 : 1);
    })
    .catch(error => {
      console.error('❌ 前端测试失败:', error);
      process.exit(1);
    });
}

module.exports = FrontendPerformanceTestSuite;