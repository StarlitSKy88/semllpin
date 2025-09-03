import { TestDataFactory } from './index';
export interface TestUserData {
    id?: string;
    username: string;
    email: string;
    password?: string;
    hashedPassword?: string;
    firstName?: string;
    lastName?: string;
    avatar?: string;
    status?: 'active' | 'inactive' | 'banned';
    emailVerified?: boolean;
    phoneNumber?: string;
    dateOfBirth?: Date;
    gender?: string;
    bio?: string;
    location?: string;
    preferredLanguage?: string;
    timezone?: string;
    createdAt?: Date;
    updatedAt?: Date;
    lastLoginAt?: Date;
    loginCount?: number;
    twoFactorEnabled?: boolean;
}
declare class UserFactoryClass implements TestDataFactory<TestUserData> {
    private counter;
    create(overrides?: Partial<TestUserData>): TestUserData;
    createMultiple(count: number, overrides?: Partial<TestUserData>): TestUserData[];
    build(overrides?: Partial<TestUserData>): TestUserData;
    buildList(count: number, overrides?: Partial<TestUserData>): TestUserData[];
    createAdmin(overrides?: Partial<TestUserData>): TestUserData;
    createPremiumUser(overrides?: Partial<TestUserData>): TestUserData;
    createInactiveUser(overrides?: Partial<TestUserData>): TestUserData;
    createBannedUser(overrides?: Partial<TestUserData>): TestUserData;
    reset(): void;
}
export declare const UserFactory: UserFactoryClass;
export declare function createTestUser(overrides?: Partial<TestUserData>): Promise<TestUserData>;
export declare function createMultipleTestUsers(count: number, overrides?: Partial<TestUserData>): Promise<TestUserData[]>;
export declare function persistTestUser(userData: TestUserData, db?: any): Promise<any>;
export declare function persistMultipleTestUsers(usersData: TestUserData[], db?: any): Promise<any[]>;
export {};
//# sourceMappingURL=userFactory.d.ts.map