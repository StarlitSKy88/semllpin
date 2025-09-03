import { Request, Response, NextFunction } from 'express';
export declare class AppError extends Error {
    statusCode: number;
    isOperational: boolean;
    code?: string;
    constructor(message: string, statusCode?: number, code?: string, isOperational?: boolean);
}
export declare const errorHandler: (error: any, req: Request, res: Response, _next: NextFunction) => void;
export declare const asyncHandler: (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) => (req: Request, res: Response, next: NextFunction) => void;
export declare const notFoundHandler: (req: Request, _res: Response, next: NextFunction) => void;
export declare const createValidationError: (field: string, message: string) => AppError;
export declare const createAuthError: (message?: string) => AppError;
export declare const createForbiddenError: (message?: string) => AppError;
export declare const createNotFoundError: (resource?: string) => AppError;
export declare const createConflictError: (message: string) => AppError;
export declare const createRateLimitError: () => AppError;
export default errorHandler;
//# sourceMappingURL=errorHandler.d.ts.map