export interface User {
    id: string;
    email: string;
    username: string;
    password_hash: string;
    display_name?: string;
    bio?: string;
    avatar_url?: string;
    university?: string;
    graduation_year?: number;
    role: 'user' | 'moderator' | 'admin';
    status: 'active' | 'suspended' | 'deleted';
    email_verified: boolean;
    email_verification_token?: string;
    password_reset_token?: string;
    password_reset_expires?: Date;
    last_login_at?: Date;
    created_at: Date;
    updated_at: Date;
}
export interface CreateUserData {
    email: string;
    username: string;
    password: string;
    display_name?: string;
    university?: string;
    graduation_year?: number;
    role?: 'user' | 'moderator' | 'admin';
}
export interface UpdateUserData {
    display_name?: string;
    bio?: string;
    avatar_url?: string;
    status?: 'active' | 'suspended' | 'deleted';
    role?: 'user' | 'moderator' | 'admin';
    email_verified?: boolean;
    last_login_at?: Date;
}
export interface UserStats {
    total_annotations: number;
    total_comments: number;
    total_payments: number;
    reputation_score: number;
    followers_count: number;
    following_count: number;
    likes_received: number;
    likes_given: number;
    favorites_count: number;
    shares_count: number;
    activity_score: number;
    weekly_posts: number;
    monthly_posts: number;
}
export declare class UserModel {
    static create(userData: CreateUserData): Promise<User>;
    static findById(id: string): Promise<User | null>;
    static findByEmail(email: string): Promise<User | null>;
    static findByUsername(username: string): Promise<User | null>;
    static update(id: string, updateData: UpdateUserData): Promise<User | null>;
    static verifyPassword(user: User, password: string): Promise<boolean>;
    static updatePassword(id: string, newPassword: string): Promise<boolean>;
    static setPasswordResetToken(email: string, token: string, expiresAt: Date): Promise<boolean>;
    static findByPasswordResetToken(token: string): Promise<User | null>;
    static setEmailVerificationToken(id: string, token: string): Promise<boolean>;
    static verifyEmail(token: string): Promise<User | null>;
    static updateLastLogin(id: string): Promise<void>;
    static getStats(id: string): Promise<UserStats>;
    private static getBasicStats;
    private static getSocialStats;
    private static getActivityStats;
    static getList(options?: {
        page?: number;
        limit?: number;
        sortBy?: string;
        sortOrder?: 'asc' | 'desc';
        search?: string;
        role?: string;
        status?: string;
    }): Promise<{
        users: User[];
        total: number;
    }>;
    static delete(id: string): Promise<boolean>;
    static emailExists(email: string, excludeId?: string): Promise<boolean>;
    static usernameExists(username: string, excludeId?: string): Promise<boolean>;
}
export default UserModel;
//# sourceMappingURL=User.d.ts.map