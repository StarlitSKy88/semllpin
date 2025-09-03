"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthPage = void 0;
const test_1 = require("@playwright/test");
const base_page_1 = require("./base-page");
class AuthPage extends base_page_1.BasePage {
    constructor(page) {
        super(page);
        this.selectors = {
            emailInput: 'input[type="email"], input[name="email"]',
            passwordInput: 'input[type="password"], input[name="password"]',
            loginButton: 'button[type="submit"], button:has-text("登录"), button:has-text("Login")',
            registerLink: 'a:has-text("注册"), a:has-text("Register"), a[href*="register"]',
            registerForm: 'form[action*="register"], form:has(input[name="email"])',
            usernameInput: 'input[name="username"], input[name="name"]',
            confirmPasswordInput: 'input[name="confirmPassword"], input[name="password_confirmation"]',
            registerButton: 'button[type="submit"], button:has-text("注册"), button:has-text("Register")',
            verificationCode: 'input[name="code"], input[name="verificationCode"]',
            verifyButton: 'button:has-text("验证"), button:has-text("Verify")',
            errorMessage: '.error, .alert-error, [role="alert"]',
            successMessage: '.success, .alert-success',
            userMenu: '[data-testid="user-menu"], .user-menu',
            logoutButton: 'button:has-text("退出"), button:has-text("Logout")',
            profileLink: 'a:has-text("个人资料"), a:has-text("Profile")',
        };
    }
    async navigateToLogin() {
        await this.navigateTo('/login');
        await this.waitForPageLoad();
    }
    async navigateToRegister() {
        await this.navigateTo('/register');
        await this.waitForPageLoad();
    }
    async login(email, password) {
        await this.navigateToLogin();
        await this.fillElement(this.selectors.emailInput, email);
        await this.fillElement(this.selectors.passwordInput, password);
        const loginResponsePromise = this.page.waitForResponse(response => response.url().includes('/api/auth/login') && response.status() === 200);
        await this.clickElement(this.selectors.loginButton);
        await loginResponsePromise;
        await this.waitForPageLoad();
    }
    async register(userData) {
        await this.navigateToRegister();
        await this.fillElement(this.selectors.usernameInput, userData.username);
        await this.fillElement(this.selectors.emailInput, userData.email);
        await this.fillElement(this.selectors.passwordInput, userData.password);
        if (userData.confirmPassword) {
            await this.fillElement(this.selectors.confirmPasswordInput, userData.confirmPassword);
        }
        const registerResponsePromise = this.page.waitForResponse(response => response.url().includes('/api/auth/register'));
        await this.clickElement(this.selectors.registerButton);
        await registerResponsePromise;
        await this.waitForPageLoad();
    }
    async verifyEmail(code) {
        await this.fillElement(this.selectors.verificationCode, code);
        const verifyResponsePromise = this.page.waitForResponse(response => response.url().includes('/api/auth/verify'));
        await this.clickElement(this.selectors.verifyButton);
        await verifyResponsePromise;
        await this.waitForPageLoad();
    }
    async logout() {
        await this.clickElement(this.selectors.userMenu);
        await this.page.waitForTimeout(500);
        await this.clickElement(this.selectors.logoutButton);
        await this.waitForPageLoad();
    }
    async verifyLoggedIn() {
        await (0, test_1.expect)(this.page.locator(this.selectors.userMenu)).toBeVisible();
        await (0, test_1.expect)(this.page).not.toHaveURL(/\/login/);
    }
    async verifyLoggedOut() {
        const isLoginPage = await this.page.locator(this.selectors.loginButton).isVisible();
        const hasUserMenu = await this.page.locator(this.selectors.userMenu).isVisible();
        (0, test_1.expect)(isLoginPage || !hasUserMenu).toBeTruthy();
    }
    async verifyRegistrationSuccess() {
        const isVerificationPage = this.page.url().includes('/verify');
        const hasSuccessMessage = await this.page.locator(this.selectors.successMessage).isVisible();
        (0, test_1.expect)(isVerificationPage || hasSuccessMessage).toBeTruthy();
    }
    async verifyLoginError(expectedError) {
        const errorElement = this.page.locator(this.selectors.errorMessage);
        await (0, test_1.expect)(errorElement).toBeVisible();
        if (expectedError) {
            await (0, test_1.expect)(errorElement).toContainText(expectedError);
        }
    }
    async createAndLoginTestUser(userData) {
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
        const needsVerification = this.page.url().includes('/verify');
        if (needsVerification) {
            await this.verifyEmail('123456');
        }
        return defaultData;
    }
}
exports.AuthPage = AuthPage;
//# sourceMappingURL=auth-page.js.map