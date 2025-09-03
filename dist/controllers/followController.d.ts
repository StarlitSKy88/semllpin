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
export declare const getUserFollowing: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getUserFollowers: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const checkFollowStatus: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getMutualFollows: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export {};
//# sourceMappingURL=followController.d.ts.map