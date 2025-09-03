import { Page, Locator, expect } from '@playwright/test';

export class BasePage {
  readonly page: Page;

  constructor(page: Page) {
    this.page = page;
  }

  // 通用等待方法
  async waitForPageLoad(timeout = 10000) {
    await this.page.waitForLoadState('networkidle', { timeout });
  }

  // 通用导航方法
  async navigateTo(url: string) {
    await this.page.goto(url, { waitUntil: 'networkidle' });
  }

  // 等待元素可见
  async waitForElement(selector: string, timeout = 10000): Promise<Locator> {
    const element = this.page.locator(selector);
    await element.waitFor({ state: 'visible', timeout });
    return element;
  }

  // 等待并点击元素
  async clickElement(selector: string, timeout = 10000) {
    const element = await this.waitForElement(selector, timeout);
    await element.click();
  }

  // 等待并输入文本
  async fillElement(selector: string, text: string, timeout = 10000) {
    const element = await this.waitForElement(selector, timeout);
    await element.fill(text);
  }

  // 等待并选择选项
  async selectOption(selector: string, value: string, timeout = 10000) {
    const element = await this.waitForElement(selector, timeout);
    await element.selectOption(value);
  }

  // 上传文件
  async uploadFile(selector: string, filePath: string) {
    const fileInput = this.page.locator(selector);
    await fileInput.setInputFiles(filePath);
  }

  // 截图方法
  async takeScreenshot(name: string) {
    await this.page.screenshot({ 
      path: `test-results/screenshots/${name}.png`,
      fullPage: true 
    });
  }

  // 验证页面标题
  async verifyPageTitle(expectedTitle: string) {
    await expect(this.page).toHaveTitle(expectedTitle);
  }

  // 验证URL包含特定路径
  async verifyURL(expectedPath: string) {
    await expect(this.page).toHaveURL(new RegExp(expectedPath));
  }

  // 等待API响应
  async waitForAPI(apiPath: string, timeout = 15000) {
    await this.page.waitForResponse(
      response => response.url().includes(apiPath) && response.status() === 200,
      { timeout }
    );
  }

  // 验证Toast消息
  async verifyToastMessage(expectedMessage: string) {
    const toast = this.page.locator('[role="status"], .toast, .notification').first();
    await expect(toast).toBeVisible();
    await expect(toast).toContainText(expectedMessage);
  }

  // 验证错误消息
  async verifyErrorMessage(expectedError: string) {
    const errorElement = this.page.locator('.error, [role="alert"], .alert-error').first();
    await expect(errorElement).toBeVisible();
    await expect(errorElement).toContainText(expectedError);
  }

  // 等待加载完成
  async waitForLoading() {
    // 等待loading spinner消失
    await this.page.locator('.loading, .spinner, [aria-label="Loading"]').waitFor({ 
      state: 'hidden',
      timeout: 15000 
    }).catch(() => {
      // 如果没有loading元素，继续执行
    });
  }

  // 验证地理位置权限
  async grantGeolocation(latitude = 40.7128, longitude = -74.0060) {
    await this.page.context().grantPermissions(['geolocation']);
    await this.page.context().setGeolocation({ latitude, longitude });
  }

  // 模拟网络条件
  async simulateSlowNetwork() {
    await this.page.context().route('**/*', route => {
      setTimeout(() => route.continue(), 1000); // 延迟1秒
    });
  }

  // 清除本地存储
  async clearLocalStorage() {
    await this.page.evaluate(() => {
      localStorage.clear();
      sessionStorage.clear();
    });
  }
}