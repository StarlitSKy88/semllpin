import { Page, expect } from '@playwright/test';
import { BasePage } from './base-page';

export class AuthPage extends BasePage {
  // 选择器定义
  private readonly selectors = {
    // 登录页面
    emailInput: 'input[type="email"], input[name="email"]',
    passwordInput: 'input[type="password"], input[name="password"]',
    loginButton: 'button[type="submit"], button:has-text("登录"), button:has-text("Login")',
    registerLink: 'a:has-text("注册"), a:has-text("Register"), a[href*="register"]',
    
    // 注册页面
    registerForm: 'form[action*="register"], form:has(input[name="email"])',
    usernameInput: 'input[name="username"], input[name="name"]',
    confirmPasswordInput: 'input[name="confirmPassword"], input[name="password_confirmation"]',
    registerButton: 'button[type="submit"], button:has-text("注册"), button:has-text("Register")',
    
    // 验证相关
    verificationCode: 'input[name="code"], input[name="verificationCode"]',
    verifyButton: 'button:has-text("验证"), button:has-text("Verify")',
    
    // 错误和成功消息
    errorMessage: '.error, .alert-error, [role="alert"]',
    successMessage: '.success, .alert-success',
    
    // 用户菜单
    userMenu: '[data-testid="user-menu"], .user-menu',
    logoutButton: 'button:has-text("退出"), button:has-text("Logout")',
    profileLink: 'a:has-text("个人资料"), a:has-text("Profile")',
  };

  constructor(page: Page) {
    super(page);
  }

  // 导航到登录页面
  async navigateToLogin() {
    await this.navigateTo('/login');
    await this.waitForPageLoad();
  }

  // 导航到注册页面
  async navigateToRegister() {
    await this.navigateTo('/register');
    await this.waitForPageLoad();
  }

  // 用户登录
  async login(email: string, password: string) {
    await this.navigateToLogin();
    
    await this.fillElement(this.selectors.emailInput, email);
    await this.fillElement(this.selectors.passwordInput, password);
    
    // 监听登录API请求
    const loginResponsePromise = this.page.waitForResponse(
      response => response.url().includes('/api/auth/login') && response.status() === 200
    );
    
    await this.clickElement(this.selectors.loginButton);
    
    // 等待登录响应
    await loginResponsePromise;
    await this.waitForPageLoad();
  }

  // 用户注册
  async register(userData: {
    username: string;
    email: string;
    password: string;
    confirmPassword?: string;
  }) {
    await this.navigateToRegister();
    
    await this.fillElement(this.selectors.usernameInput, userData.username);
    await this.fillElement(this.selectors.emailInput, userData.email);
    await this.fillElement(this.selectors.passwordInput, userData.password);
    
    if (userData.confirmPassword) {
      await this.fillElement(this.selectors.confirmPasswordInput, userData.confirmPassword);
    }
    
    // 监听注册API请求
    const registerResponsePromise = this.page.waitForResponse(
      response => response.url().includes('/api/auth/register')
    );
    
    await this.clickElement(this.selectors.registerButton);
    
    // 等待注册响应
    await registerResponsePromise;
    await this.waitForPageLoad();
  }

  // 验证邮箱
  async verifyEmail(code: string) {
    await this.fillElement(this.selectors.verificationCode, code);
    
    const verifyResponsePromise = this.page.waitForResponse(
      response => response.url().includes('/api/auth/verify')
    );
    
    await this.clickElement(this.selectors.verifyButton);
    await verifyResponsePromise;
    await this.waitForPageLoad();
  }

  // 用户退出登录
  async logout() {
    // 点击用户菜单
    await this.clickElement(this.selectors.userMenu);
    
    // 等待菜单展开
    await this.page.waitForTimeout(500);
    
    // 点击退出按钮
    await this.clickElement(this.selectors.logoutButton);
    
    // 等待重定向到首页或登录页
    await this.waitForPageLoad();
  }

  // 验证登录状态
  async verifyLoggedIn() {
    // 检查是否存在用户菜单
    await expect(this.page.locator(this.selectors.userMenu)).toBeVisible();
    
    // 验证URL不是登录页面
    await expect(this.page).not.toHaveURL(/\/login/);
  }

  // 验证未登录状态
  async verifyLoggedOut() {
    // 检查用户菜单不存在或登录按钮存在
    const isLoginPage = await this.page.locator(this.selectors.loginButton).isVisible();
    const hasUserMenu = await this.page.locator(this.selectors.userMenu).isVisible();
    
    expect(isLoginPage || !hasUserMenu).toBeTruthy();
  }

  // 验证注册成功
  async verifyRegistrationSuccess() {
    // 检查是否重定向到验证页面或显示成功消息
    const isVerificationPage = this.page.url().includes('/verify');
    const hasSuccessMessage = await this.page.locator(this.selectors.successMessage).isVisible();
    
    expect(isVerificationPage || hasSuccessMessage).toBeTruthy();
  }

  // 验证登录错误
  async verifyLoginError(expectedError?: string) {
    const errorElement = this.page.locator(this.selectors.errorMessage);
    await expect(errorElement).toBeVisible();
    
    if (expectedError) {
      await expect(errorElement).toContainText(expectedError);
    }
  }

  // 快速创建测试用户并登录
  async createAndLoginTestUser(userData?: Partial<{
    username: string;
    email: string;
    password: string;
  }>) {
    const defaultData = {
      username: `testuser_${Date.now()}`,
      email: `test_${Date.now()}@example.com`,
      password: 'TestPassword123!',
      ...userData
    };

    await this.register({
      ...defaultData,
      confirmPassword: defaultData.password
    });

    // 如果需要邮箱验证，使用测试验证码
    const needsVerification = this.page.url().includes('/verify');
    if (needsVerification) {
      await this.verifyEmail('123456'); // 测试环境通用验证码
    }

    return defaultData;
  }
}