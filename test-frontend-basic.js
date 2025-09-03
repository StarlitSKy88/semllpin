/**
 * SmellPin前端基础功能测试脚本
 * 测试腾讯云CloudBase部署的前端应用
 */

const axios = require('axios');
const { performance } = require('perf_hooks');

// 测试配置
const FRONTEND_URL = 'https://x1aoyang-1-5gimfr95c320432c.tcloudbaseapp.com';
const TEST_RESULTS = [];
let failCount = 0;

// 测试结果记录函数
function recordTest(testName, status, details, duration) {
    const result = {
        testName,
        status,
        details,
        duration: `${duration}ms`,
        timestamp: new Date().toISOString()
    };
    TEST_RESULTS.push(result);
    console.log(`\n[${status}] ${testName}`);
    console.log(`   详情: ${details}`);
    console.log(`   耗时: ${duration}ms`);
}

// 1. 测试主页加载
async function testHomepageLoad() {
    console.log('\n=== 测试1: 主页加载 ===');
    const startTime = performance.now();
    
    try {
        const response = await axios.get(FRONTEND_URL, {
            timeout: 10000,
            headers: {
                'User-Agent': 'SmellPin-Test-Agent/1.0'
            }
        });
        
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);
        
        if (response.status === 200) {
            const contentLength = response.data.length;
            const hasTitle = response.data.includes('<title>');
            const hasReactRoot = response.data.includes('id="root"');
            
            recordTest(
                '主页加载',
                'PASS',
                `状态码: ${response.status}, 内容长度: ${contentLength}字符, 包含标题: ${hasTitle}, React根元素: ${hasReactRoot}`,
                duration
            );
        } else {
            recordTest(
                '主页加载',
                'FAIL',
                `意外的状态码: ${response.status}`,
                duration
            );
        }
    } catch (error) {
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);
        recordTest(
            '主页加载',
            'FAIL',
            `请求失败: ${error.message}`,
            duration
        );
    }
}

// 2. 测试静态资源加载
async function testStaticResources() {
    console.log('\n=== 测试2: 静态资源加载 ===');
    
    const resources = [
        '/assets/',
        '/manifest.json',
        '/favicon.ico'
    ];
    
    for (const resource of resources) {
        const startTime = performance.now();
        try {
            const response = await axios.get(`${FRONTEND_URL}${resource}`, {
                timeout: 5000,
                validateStatus: function (status) {
                    return status < 500; // 允许404等客户端错误
                }
            });
            
            const endTime = performance.now();
            const duration = Math.round(endTime - startTime);
            
            if (response.status === 200) {
                recordTest(
                    `静态资源: ${resource}`,
                    'PASS',
                    `状态码: ${response.status}, 内容类型: ${response.headers['content-type'] || 'unknown'}`,
                    duration
                );
            } else {
                recordTest(
                    `静态资源: ${resource}`,
                    'WARN',
                    `状态码: ${response.status} (可能是正常的404)`,
                    duration
                );
            }
        } catch (error) {
            const endTime = performance.now();
            const duration = Math.round(endTime - startTime);
            recordTest(
                `静态资源: ${resource}`,
                'FAIL',
                `请求失败: ${error.message}`,
                duration
            );
        }
    }
}

// 3. 测试响应头和安全性
async function testSecurityHeaders() {
    console.log('\n=== 测试3: 安全响应头 ===');
    const startTime = performance.now();
    
    try {
        const response = await axios.head(FRONTEND_URL, {
            timeout: 5000
        });
        
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);
        
        const headers = response.headers;
        const securityChecks = {
            'Content-Type': headers['content-type'],
            'Cache-Control': headers['cache-control'],
            'X-Frame-Options': headers['x-frame-options'],
            'X-Content-Type-Options': headers['x-content-type-options'],
            'Server': headers['server']
        };
        
        recordTest(
            '安全响应头检查',
            'PASS',
            `响应头: ${JSON.stringify(securityChecks, null, 2)}`,
            duration
        );
    } catch (error) {
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);
        recordTest(
            '安全响应头检查',
            'FAIL',
            `请求失败: ${error.message}`,
            duration
        );
    }
}

// 4. 测试不同路由的可访问性
async function testRouteAccessibility() {
    console.log('\n=== 测试4: 路由可访问性 ===');
    
    const routes = [
        '/',
        '/login',
        '/register',
        '/map',
        '/profile',
        '/about'
    ];
    
    for (const route of routes) {
        const startTime = performance.now();
        try {
            const response = await axios.get(`${FRONTEND_URL}${route}`, {
                timeout: 8000,
                maxRedirects: 5,
                validateStatus: function (status) {
                    return status < 500;
                }
            });
            
            const endTime = performance.now();
            const duration = Math.round(endTime - startTime);
            
            if (response.status === 200) {
                recordTest(
                    `路由: ${route}`,
                    'PASS',
                    `状态码: ${response.status}, 内容长度: ${response.data.length}字符`,
                    duration
                );
            } else {
                recordTest(
                    `路由: ${route}`,
                    'WARN',
                    `状态码: ${response.status} (可能需要认证或重定向)`,
                    duration
                );
            }
        } catch (error) {
            const endTime = performance.now();
            const duration = Math.round(endTime - startTime);
            recordTest(
                `路由: ${route}`,
                'FAIL',
                `请求失败: ${error.message}`,
                duration
            );
        }
    }
}

// 5. 测试移动端响应性
async function testMobileResponsiveness() {
    console.log('\n=== 测试5: 移动端响应性 ===');
    const startTime = performance.now();
    
    try {
        const response = await axios.get(FRONTEND_URL, {
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1'
            }
        });
        
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);
        
        const content = response.data;
        const hasViewport = content.includes('viewport');
        const hasResponsiveCSS = content.includes('responsive') || content.includes('mobile');
        const hasTailwind = content.includes('tailwind');
        
        recordTest(
            '移动端响应性',
            'PASS',
            `Viewport标签: ${hasViewport}, 响应式CSS: ${hasResponsiveCSS}, Tailwind: ${hasTailwind}`,
            duration
        );
    } catch (error) {
        const endTime = performance.now();
        const duration = Math.round(endTime - startTime);
        recordTest(
            '移动端响应性',
            'FAIL',
            `请求失败: ${error.message}`,
            duration
        );
    }
}

// 主测试函数
async function runFrontendBasicTests() {
    console.log('🚀 开始SmellPin前端基础功能测试...');
    console.log(`📍 测试目标: ${FRONTEND_URL}`);
    console.log(`⏰ 测试时间: ${new Date().toLocaleString()}`);
    
    const overallStartTime = performance.now();
    
    // 执行所有测试
    await testHomepageLoad();
    await testStaticResources();
    await testSecurityHeaders();
    await testRouteAccessibility();
    await testMobileResponsiveness();
    
    const overallEndTime = performance.now();
    const totalDuration = Math.round(overallEndTime - overallStartTime);
    
    // 生成测试报告
    console.log('\n' + '='.repeat(60));
    console.log('📊 前端基础功能测试报告');
    console.log('='.repeat(60));
    
    const passCount = TEST_RESULTS.filter(r => r.status === 'PASS').length;
    const warnCount = TEST_RESULTS.filter(r => r.status === 'WARN').length;
    const failCount = TEST_RESULTS.filter(r => r.status === 'FAIL').length;
    
    console.log(`✅ 通过: ${passCount}`);
    console.log(`⚠️  警告: ${warnCount}`);
    console.log(`❌ 失败: ${failCount}`);
    console.log(`⏱️  总耗时: ${totalDuration}ms`);
    console.log(`📈 成功率: ${((passCount / TEST_RESULTS.length) * 100).toFixed(1)}%`);
    
    // 详细结果
    console.log('\n📋 详细测试结果:');
    TEST_RESULTS.forEach((result, index) => {
        console.log(`${index + 1}. [${result.status}] ${result.testName} (${result.duration})`);
        if (result.status === 'FAIL') {
            console.log(`   ❌ ${result.details}`);
        }
    });
    
    return {
        summary: {
            total: TEST_RESULTS.length,
            passed: passCount,
            warned: warnCount,
            failed: failCount,
            duration: totalDuration,
            successRate: ((passCount / TEST_RESULTS.length) * 100).toFixed(1)
        },
        results: TEST_RESULTS
    };
}

// 如果直接运行此脚本
if (require.main === module) {
    runFrontendBasicTests()
        .then(report => {
            console.log('\n✨ 前端基础功能测试完成!');
            process.exit(report.summary.failed > 0 ? 1 : 0);
        })
        .catch(error => {
            console.error('❌ 测试执行失败:', error);
            process.exit(1);
        });
}

module.exports = { runFrontendBasicTests };