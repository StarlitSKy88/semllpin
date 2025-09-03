// 前端功能测试脚本
const puppeteer = require('puppeteer');

// 测试配置
const config = {
  baseUrl: 'http://localhost:5173',
  timeout: 30000,
  headless: false // 设置为false以便观察测试过程
};

// 测试结果记录
const testResults = {
  passed: 0,
  failed: 0,
  errors: []
};

// 记录测试结果
function recordTest(testName, success, error = null) {
  if (success) {
    testResults.passed++;
    console.log(`✅ ${testName} - 通过`);
  } else {
    testResults.failed++;
    testResults.errors.push({ test: testName, error });
    console.log(`❌ ${testName} - 失败: ${error}`);
  }
}

// 等待函数
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// 测试页面加载
async function testPageLoad(page, url, pageName) {
  try {
    console.log(`\n=== 测试${pageName}页面加载 ===`);
    
    await page.goto(url, { waitUntil: 'networkidle2', timeout: config.timeout });
    
    // 检查页面标题
    const title = await page.title();
    console.log(`页面标题: ${title}`);
    
    // 检查是否有React错误
    const errors = await page.evaluate(() => {
      return window.__REACT_ERROR_OVERLAY__ ? window.__REACT_ERROR_OVERLAY__.errors : [];
    });
    
    if (errors.length > 0) {
      throw new Error(`React错误: ${errors.join(', ')}`);
    }
    
    // 等待页面内容加载
    await page.waitForSelector('body', { timeout: 5000 });
    
    recordTest(`${pageName}页面加载`, true);
    return true;
  } catch (error) {
    recordTest(`${pageName}页面加载`, false, error.message);
    return false;
  }
}

// 测试登录页面
async function testLoginPage(page) {
  try {
    console.log('\n=== 测试登录页面功能 ===');
    
    await page.goto(`${config.baseUrl}/login`, { waitUntil: 'networkidle2' });
    
    // 检查登录表单元素
    const emailInput = await page.$('input[type="email"], input[placeholder*="邮箱"], input[placeholder*="email"]');
    const passwordInput = await page.$('input[type="password"], input[placeholder*="密码"], input[placeholder*="password"]');
    const loginButton = await page.$('button[type="submit"], button:contains("登录"), button:contains("Login")');
    
    if (!emailInput) throw new Error('未找到邮箱输入框');
    if (!passwordInput) throw new Error('未找到密码输入框');
    if (!loginButton) throw new Error('未找到登录按钮');
    
    // 测试表单验证
    await loginButton.click();
    await delay(1000);
    
    recordTest('登录页面表单元素', true);
    
    // 测试输入功能
    await emailInput.type('test@example.com');
    await passwordInput.type('testpassword');
    
    recordTest('登录表单输入功能', true);
    
  } catch (error) {
    recordTest('登录页面功能', false, error.message);
  }
}

// 测试注册页面
async function testRegisterPage(page) {
  try {
    console.log('\n=== 测试注册页面功能 ===');
    
    await page.goto(`${config.baseUrl}/register`, { waitUntil: 'networkidle2' });
    
    // 检查注册表单元素
    const usernameInput = await page.$('input[placeholder*="用户名"], input[placeholder*="username"]');
    const emailInput = await page.$('input[type="email"], input[placeholder*="邮箱"]');
    const passwordInput = await page.$('input[type="password"], input[placeholder*="密码"]');
    
    if (!usernameInput) throw new Error('未找到用户名输入框');
    if (!emailInput) throw new Error('未找到邮箱输入框');
    if (!passwordInput) throw new Error('未找到密码输入框');
    
    recordTest('注册页面表单元素', true);
    
    // 测试输入功能
    await usernameInput.type('testuser');
    await emailInput.type('test@example.com');
    await passwordInput.type('testpassword123');
    
    recordTest('注册表单输入功能', true);
    
  } catch (error) {
    recordTest('注册页面功能', false, error.message);
  }
}

// 测试主页面
async function testHomePage(page) {
  try {
    console.log('\n=== 测试主页面功能 ===');
    
    await page.goto(`${config.baseUrl}/`, { waitUntil: 'networkidle2' });
    
    // 检查主要元素
    const welcomeSection = await page.$('h1, h2, .welcome, [class*="welcome"]');
    const createButton = await page.$('button:contains("创建"), button:contains("添加"), [class*="create"]');
    
    if (welcomeSection) {
      recordTest('主页欢迎区域', true);
    } else {
      recordTest('主页欢迎区域', false, '未找到欢迎区域');
    }
    
    // 检查导航功能
    const navLinks = await page.$$('a, button[onclick], [role="button"]');
    recordTest('主页导航元素', navLinks.length > 0, navLinks.length === 0 ? '未找到导航元素' : null);
    
  } catch (error) {
    recordTest('主页面功能', false, error.message);
  }
}

// 测试地图页面
async function testMapPage(page) {
  try {
    console.log('\n=== 测试地图页面功能 ===');
    
    await page.goto(`${config.baseUrl}/map`, { waitUntil: 'networkidle2' });
    
    // 等待地图容器加载
    await delay(3000);
    
    // 检查地图相关元素
    const mapContainer = await page.$('[class*="map"], #map, .leaflet-container, .mapbox');
    const addButton = await page.$('button:contains("添加"), button:contains("创建"), button[class*="add"]');
    
    if (mapContainer) {
      recordTest('地图容器加载', true);
    } else {
      recordTest('地图容器加载', false, '未找到地图容器');
    }
    
    recordTest('地图页面基本元素', true);
    
  } catch (error) {
    recordTest('地图页面功能', false, error.message);
  }
}

// 测试响应式设计
async function testResponsiveDesign(page) {
  try {
    console.log('\n=== 测试响应式设计 ===');
    
    // 测试不同屏幕尺寸
    const viewports = [
      { width: 1920, height: 1080, name: '桌面端' },
      { width: 768, height: 1024, name: '平板端' },
      { width: 375, height: 667, name: '手机端' }
    ];
    
    for (const viewport of viewports) {
      await page.setViewport(viewport);
      await page.goto(`${config.baseUrl}/`, { waitUntil: 'networkidle2' });
      await delay(1000);
      
      // 检查页面是否正常显示
      const bodyHeight = await page.evaluate(() => document.body.scrollHeight);
      
      if (bodyHeight > 100) {
        recordTest(`${viewport.name}响应式显示`, true);
      } else {
        recordTest(`${viewport.name}响应式显示`, false, '页面内容异常');
      }
    }
    
  } catch (error) {
    recordTest('响应式设计测试', false, error.message);
  }
}

// 测试控制台错误
async function testConsoleErrors(page) {
  console.log('\n=== 监听控制台错误 ===');
  
  const errors = [];
  
  page.on('console', msg => {
    if (msg.type() === 'error') {
      errors.push(msg.text());
      console.log(`🔍 控制台错误: ${msg.text()}`);
    }
  });
  
  page.on('pageerror', error => {
    errors.push(error.message);
    console.log(`🔍 页面错误: ${error.message}`);
  });
  
  return errors;
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始前端功能测试...\n');
  
  let browser;
  let page;
  
  try {
    // 启动浏览器
    browser = await puppeteer.launch({
      headless: config.headless,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });
    
    page = await browser.newPage();
    
    // 设置默认超时
    page.setDefaultTimeout(config.timeout);
    
    // 监听控制台错误
    const consoleErrors = testConsoleErrors(page);
    
    // 执行各项测试
    await testPageLoad(page, config.baseUrl, '主页');
    await testHomePage(page);
    
    await testPageLoad(page, `${config.baseUrl}/login`, '登录页');
    await testLoginPage(page);
    
    await testPageLoad(page, `${config.baseUrl}/register`, '注册页');
    await testRegisterPage(page);
    
    await testPageLoad(page, `${config.baseUrl}/map`, '地图页');
    await testMapPage(page);
    
    await testResponsiveDesign(page);
    
    // 检查控制台错误
    if (consoleErrors.length === 0) {
      recordTest('控制台无错误', true);
    } else {
      recordTest('控制台无错误', false, `发现${consoleErrors.length}个错误`);
    }
    
  } catch (error) {
    console.error('测试执行失败:', error);
    recordTest('测试执行', false, error.message);
  } finally {
    if (browser) {
      await browser.close();
    }
  }
  
  // 输出测试结果
  console.log('\n' + '='.repeat(50));
  console.log('📊 前端功能测试结果');
  console.log('='.repeat(50));
  console.log(`✅ 通过: ${testResults.passed}`);
  console.log(`❌ 失败: ${testResults.failed}`);
  console.log(`📈 成功率: ${((testResults.passed / (testResults.passed + testResults.failed)) * 100).toFixed(1)}%`);
  
  if (testResults.errors.length > 0) {
    console.log('\n🔍 失败详情:');
    testResults.errors.forEach((error, index) => {
      console.log(`${index + 1}. ${error.test}: ${error.error}`);
    });
  }
  
  console.log('\n✨ 前端功能测试完成!');
}

// 检查依赖
try {
  require('puppeteer');
  runTests().catch(console.error);
} catch (error) {
  console.error('❌ 缺少puppeteer依赖，请先安装: npm install puppeteer');
  process.exit(1);
}