import { Request, Response } from 'express';
interface AuthRequest extends Request {
    user?: {
        id: string;
        email: string;
        username: string;
        role: string;
    };
}
export declare const AdminRole: {
    readonly SUPER_ADMIN: "super_admin";
    readonly ADMIN: "admin";
    readonly MODERATOR: "moderator";
};
export type AdminRoleType = typeof AdminRole[keyof typeof AdminRole];
export declare const UserStatus: {
    readonly ACTIVE: "active";
    readonly SUSPENDED: "suspended";
    readonly BANNED: "banned";
    readonly PENDING: "pending";
};
export type UserStatusType = typeof UserStatus[keyof typeof UserStatus];
export interface UserManagement {
    id: string;
    username: string;
    email: string;
    status: UserStatusType;
    role: string;
    created_at: Date;
    last_login?: Date;
    total_annotations: number;
    total_spent: number;
    total_earned: number;
    reports_count: number;
}
export interface ContentReview {
    id: string;
    type: 'annotation' | 'comment' | 'media';
    content_id: string;
    status: 'pending' | 'approved' | 'rejected';
    reported_by?: string;
    reason?: string;
    created_at: Date;
    reviewed_at?: Date;
    reviewed_by?: string;
    content_preview: string;
}
export declare const getAdminStats: (req: AuthRequest, res: Response) => Promise<void>;
export declare const getUserManagement: (req: AuthRequest, res: Response) => Promise<void>;
export declare const updateUserStatus: (req: AuthRequest, res: Response) => Promise<void>;
export declare const getContentReviews: (req: AuthRequest, res: Response) => Promise<void>;
export declare const handleContentReview: (req: AuthRequest, res: Response) => Promise<void>;
export declare const batchUserOperation: (req: AuthRequest, res: Response) => Promise<void>;
export declare const getAdminLogs: (req: AuthRequest, res: Response) => Promise<void>;
export {};
//# sourceMappingURL=adminController.d.ts.map