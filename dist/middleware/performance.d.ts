import { Request, Response, NextFunction } from 'express';
export interface PerformanceMetrics {
    requestId: string;
    method: string;
    url: string;
    statusCode: number;
    responseTime: number;
    memoryUsage: NodeJS.MemoryUsage;
    timestamp: Date;
    userAgent?: string;
    ip?: string;
}
export declare const performanceMonitor: (req: Request, res: Response, next: NextFunction) => void;
export declare const getPerformanceStats: () => {
    last5Minutes: {
        count: number;
        avgResponseTime: number;
        minResponseTime: number;
        maxResponseTime: number;
        errorRate: number;
        avgMemoryUsage: number;
    };
    last1Hour: {
        count: number;
        avgResponseTime: number;
        minResponseTime: number;
        maxResponseTime: number;
        errorRate: number;
        avgMemoryUsage: number;
    };
    total: {
        count: number;
        avgResponseTime: number;
        minResponseTime: number;
        maxResponseTime: number;
        errorRate: number;
        avgMemoryUsage: number;
    };
    slowestEndpoints: {
        url: string;
        method: string;
        responseTime: number;
        timestamp: Date;
    }[];
};
export declare const cacheMiddleware: (ttlSeconds?: number) => (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
export declare const clearCache: (pattern?: string) => void;
export declare const optimizeQuery: (req: Request, _res: Response, next: NextFunction) => void;
export declare const rateLimiter: (maxRequests?: number, windowMs?: number) => (req: Request, res: Response, next: NextFunction) => void | Response<any, Record<string, any>>;
export declare const compressionConfig: {
    filter: (req: Request, _res: Response) => boolean;
    threshold: number;
    level: number;
};
//# sourceMappingURL=performance.d.ts.map