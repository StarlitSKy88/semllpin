import { chromium, FullConfig } from '@playwright/test';

async function globalSetup(config: FullConfig) {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();

  console.log('🚀 Starting global setup for SmellPin E2E tests...');

  // 清理测试数据
  try {
    // 清理测试用户和数据
    await page.goto('http://localhost:3003/api/test/cleanup', {
      waitUntil: 'networkidle'
    });
    console.log('✅ Test data cleanup completed');
  } catch (error) {
    console.log('⚠️  Test cleanup endpoint not available, continuing...');
  }

  // 准备测试数据
  try {
    await page.goto('http://localhost:3003/api/test/seed', {
      waitUntil: 'networkidle'
    });
    console.log('✅ Test data seeding completed');
  } catch (error) {
    console.log('⚠️  Test seeding endpoint not available, continuing...');
  }

  // 验证服务可用性
  const services = [
    { name: 'Backend API', url: 'http://localhost:3003/health' }
  ];

  for (const service of services) {
    try {
      await page.goto(service.url, { 
        waitUntil: 'networkidle',
        timeout: 30000
      });
      console.log(`✅ ${service.name} is available`);
    } catch (error) {
      console.error(`❌ ${service.name} is not available at ${service.url}`);
      throw error;
    }
  }

  await context.close();
  await browser.close();

  console.log('🎉 Global setup completed successfully!');
}

export default globalSetup;