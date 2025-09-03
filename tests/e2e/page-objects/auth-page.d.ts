import { Page } from '@playwright/test';
import { BasePage } from './base-page';
export declare class AuthPage extends BasePage {
    private readonly selectors;
    constructor(page: Page);
    navigateToLogin(): Promise<void>;
    navigateToRegister(): Promise<void>;
    login(email: string, password: string): Promise<void>;
    register(userData: {
        username: string;
        email: string;
        password: string;
        confirmPassword?: string;
    }): Promise<void>;
    verifyEmail(code: string): Promise<void>;
    logout(): Promise<void>;
    verifyLoggedIn(): Promise<void>;
    verifyLoggedOut(): Promise<void>;
    verifyRegistrationSuccess(): Promise<void>;
    verifyLoginError(expectedError?: string): Promise<void>;
    createAndLoginTestUser(userData?: Partial<{
        username: string;
        email: string;
        password: string;
    }>): Promise<{
        username: string;
        email: string;
        password: string;
    }>;
}
//# sourceMappingURL=auth-page.d.ts.map