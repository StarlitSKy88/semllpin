import { Request, Response, NextFunction } from 'express';
export declare const securityHeaders: (req: import("http").IncomingMessage, res: import("http").ServerResponse, next: (err?: unknown) => void) => void;
export declare const apiRateLimit: import("express-rate-limit").RateLimitRequestHandler;
export declare const strictRateLimit: import("express-rate-limit").RateLimitRequestHandler;
export declare const fileUploadRateLimit: import("express-rate-limit").RateLimitRequestHandler;
export declare const validateInput: (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>> | undefined;
export declare const corsConfig: {
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => void;
    credentials: boolean;
    optionsSuccessStatus: number;
    methods: string[];
    allowedHeaders: string[];
    exposedHeaders: string[];
};
export declare const securityLogger: (req: Request, res: Response, next: NextFunction) => void;
declare const _default: {
    securityHeaders: (req: import("http").IncomingMessage, res: import("http").ServerResponse, next: (err?: unknown) => void) => void;
    apiRateLimit: import("express-rate-limit").RateLimitRequestHandler;
    strictRateLimit: import("express-rate-limit").RateLimitRequestHandler;
    fileUploadRateLimit: import("express-rate-limit").RateLimitRequestHandler;
    validateInput: (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>> | undefined;
    corsConfig: {
        origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => void;
        credentials: boolean;
        optionsSuccessStatus: number;
        methods: string[];
        allowedHeaders: string[];
        exposedHeaders: string[];
    };
    securityLogger: (req: Request, res: Response, next: NextFunction) => void;
};
export default _default;
//# sourceMappingURL=security.d.ts.map