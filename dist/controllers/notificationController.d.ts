import { Request, Response } from 'express';
interface AuthRequest extends Request {
    user?: {
        id: string;
        email: string;
        username: string;
        role: string;
    };
}
export declare const getUserNotificationSettings: (req: AuthRequest, res: Response) => Promise<Response>;
export declare const updateUserNotificationSettings: (req: AuthRequest, res: Response) => Promise<Response>;
export declare const testNotification: (req: AuthRequest, res: Response) => Promise<Response>;
export declare const getNotificationStats: (req: AuthRequest, res: Response) => Promise<Response>;
export declare const deleteNotifications: (req: AuthRequest, res: Response) => Promise<Response>;
export {};
//# sourceMappingURL=notificationController.d.ts.map