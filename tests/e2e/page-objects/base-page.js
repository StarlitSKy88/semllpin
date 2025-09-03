"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BasePage = void 0;
const test_1 = require("@playwright/test");
class BasePage {
    constructor(page) {
        this.page = page;
    }
    async waitForPageLoad(timeout = 10000) {
        await this.page.waitForLoadState('networkidle', { timeout });
    }
    async navigateTo(url) {
        await this.page.goto(url, { waitUntil: 'networkidle' });
    }
    async waitForElement(selector, timeout = 10000) {
        const element = this.page.locator(selector);
        await element.waitFor({ state: 'visible', timeout });
        return element;
    }
    async clickElement(selector, timeout = 10000) {
        const element = await this.waitForElement(selector, timeout);
        await element.click();
    }
    async fillElement(selector, text, timeout = 10000) {
        const element = await this.waitForElement(selector, timeout);
        await element.fill(text);
    }
    async selectOption(selector, value, timeout = 10000) {
        const element = await this.waitForElement(selector, timeout);
        await element.selectOption(value);
    }
    async uploadFile(selector, filePath) {
        const fileInput = this.page.locator(selector);
        await fileInput.setInputFiles(filePath);
    }
    async takeScreenshot(name) {
        await this.page.screenshot({
            path: `test-results/screenshots/${name}.png`,
            fullPage: true
        });
    }
    async verifyPageTitle(expectedTitle) {
        await (0, test_1.expect)(this.page).toHaveTitle(expectedTitle);
    }
    async verifyURL(expectedPath) {
        await (0, test_1.expect)(this.page).toHaveURL(new RegExp(expectedPath));
    }
    async waitForAPI(apiPath, timeout = 15000) {
        await this.page.waitForResponse(response => response.url().includes(apiPath) && response.status() === 200, { timeout });
    }
    async verifyToastMessage(expectedMessage) {
        const toast = this.page.locator('[role="status"], .toast, .notification').first();
        await (0, test_1.expect)(toast).toBeVisible();
        await (0, test_1.expect)(toast).toContainText(expectedMessage);
    }
    async verifyErrorMessage(expectedError) {
        const errorElement = this.page.locator('.error, [role="alert"], .alert-error').first();
        await (0, test_1.expect)(errorElement).toBeVisible();
        await (0, test_1.expect)(errorElement).toContainText(expectedError);
    }
    async waitForLoading() {
        await this.page.locator('.loading, .spinner, [aria-label="Loading"]').waitFor({
            state: 'hidden',
            timeout: 15000
        }).catch(() => {
        });
    }
    async grantGeolocation(latitude = 40.7128, longitude = -74.0060) {
        await this.page.context().grantPermissions(['geolocation']);
        await this.page.context().setGeolocation({ latitude, longitude });
    }
    async simulateSlowNetwork() {
        await this.page.context().route('**/*', route => {
            setTimeout(() => route.continue(), 1000);
        });
    }
    async clearLocalStorage() {
        await this.page.evaluate(() => {
            localStorage.clear();
            sessionStorage.clear();
        });
    }
}
exports.BasePage = BasePage;
//# sourceMappingURL=base-page.js.map