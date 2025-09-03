import { Request, Response } from 'express';
interface AuthRequest extends Request {
    user?: {
        id: string;
        email: string;
        username: string;
        role: string;
    };
}
export declare const createShareRecord: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getAnnotationShareStats: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getUserShareHistory: (req: AuthRequest, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const getPopularShares: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export declare const generateShareLink: (req: Request, res: Response) => Promise<Response<any, Record<string, any>>>;
export {};
//# sourceMappingURL=shareController.d.ts.map