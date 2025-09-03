import { Request, Response, NextFunction } from 'express';
interface JWTPayload {
    sub: string;
    email: string;
    username: string;
    role: string;
    iat: number;
    exp: number;
}
export declare const authMiddleware: (req: Request, _res: Response, next: NextFunction) => Promise<void>;
export declare const optionalAuthMiddleware: (req: Request, _res: Response, next: NextFunction) => Promise<void>;
export declare const requireRole: (roles: string | string[]) => (req: Request, _res: Response, next: NextFunction) => void;
export declare const requireAdmin: (req: Request, _res: Response, next: NextFunction) => void;
export declare const requireModerator: (req: Request, _res: Response, next: NextFunction) => void;
export declare const requireOwnership: (getResourceUserId: (req: Request) => string | Promise<string>) => (req: Request, _res: Response, next: NextFunction) => Promise<void>;
export declare const generateToken: (payload: Omit<JWTPayload, "iat" | "exp">) => string;
export declare const generateRefreshToken: (userId: string) => string;
export declare const verifyRefreshToken: (token: string) => Promise<{
    sub: string;
}>;
export declare const blacklistToken: (token: string) => Promise<void>;
export declare const rateLimitByUser: (maxRequests: number, windowMs: number) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
export default authMiddleware;
//# sourceMappingURL=auth.d.ts.map