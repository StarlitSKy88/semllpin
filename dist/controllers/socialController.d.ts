import { Request, Response } from 'express';
interface AuthRequest extends Request {
    user?: {
        id: string;
        email: string;
        username: string;
        role: string;
    };
}
export declare const followUser: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const unfollowUser: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getFollowing: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getFollowers: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const likeAnnotation: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const unlikeAnnotation: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const favoriteAnnotation: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const unfavoriteAnnotation: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getUserFavorites: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getUserNotifications: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const markNotificationAsRead: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const markAllNotificationsAsRead: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export {};
//# sourceMappingURL=socialController.d.ts.map