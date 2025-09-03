import { chromium, FullConfig } from '@playwright/test';

async function globalTeardown(config: FullConfig) {
  const browser = await chromium.launch();
  const context = await browser.newContext();
  const page = await context.newPage();

  console.log('🧹 Starting global teardown for SmellPin E2E tests...');

  // 清理测试数据
  try {
    await page.goto('http://localhost:3000/api/test/cleanup', {
      waitUntil: 'networkidle'
    });
    console.log('✅ Test data cleanup completed');
  } catch (error) {
    console.log('⚠️  Test cleanup endpoint not available during teardown');
  }

  // 清理上传的测试文件
  try {
    await page.goto('http://localhost:3000/api/test/cleanup-files', {
      waitUntil: 'networkidle'
    });
    console.log('✅ Test files cleanup completed');
  } catch (error) {
    console.log('⚠️  Test files cleanup endpoint not available');
  }

  await context.close();
  await browser.close();

  console.log('🎉 Global teardown completed successfully!');
}

export default globalTeardown;