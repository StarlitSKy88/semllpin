import { Page, Locator } from '@playwright/test';
export declare class BasePage {
    readonly page: Page;
    constructor(page: Page);
    waitForPageLoad(timeout?: number): Promise<void>;
    navigateTo(url: string): Promise<void>;
    waitForElement(selector: string, timeout?: number): Promise<Locator>;
    clickElement(selector: string, timeout?: number): Promise<void>;
    fillElement(selector: string, text: string, timeout?: number): Promise<void>;
    selectOption(selector: string, value: string, timeout?: number): Promise<void>;
    uploadFile(selector: string, filePath: string): Promise<void>;
    takeScreenshot(name: string): Promise<void>;
    verifyPageTitle(expectedTitle: string): Promise<void>;
    verifyURL(expectedPath: string): Promise<void>;
    waitForAPI(apiPath: string, timeout?: number): Promise<void>;
    verifyToastMessage(expectedMessage: string): Promise<void>;
    verifyErrorMessage(expectedError: string): Promise<void>;
    waitForLoading(): Promise<void>;
    grantGeolocation(latitude?: number, longitude?: number): Promise<void>;
    simulateSlowNetwork(): Promise<void>;
    clearLocalStorage(): Promise<void>;
}
//# sourceMappingURL=base-page.d.ts.map