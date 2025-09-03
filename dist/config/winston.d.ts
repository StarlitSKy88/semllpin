import winston from 'winston';
declare const logger: winston.Logger;
export declare const businessLogger: {
    userAction: (userId: string, action: string, details: any) => void;
    payment: (userId: string, amount: number, status: string, details: any) => void;
    annotation: (userId: string, annotationId: string, action: string, details: any) => void;
    lbsReward: (userId: string, annotationId: string, reward: number, details: any) => void;
    security: (event: string, userId?: string, details?: any) => void;
    performance: (operation: string, duration: number, details: any) => void;
};
export declare const errorLogger: {
    apiError: (error: Error, req: any, details?: any) => void;
    dbError: (error: Error, operation: string, details?: any) => void;
    externalError: (service: string, error: Error, details?: any) => void;
    systemError: (error: Error, context: string, details?: any) => void;
};
export declare const httpLogger: {
    request: (req: any, res: any, responseTime: number) => void;
};
export { logger };
export default logger;
//# sourceMappingURL=winston.d.ts.map