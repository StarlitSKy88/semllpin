import express from 'express';
declare class Server {
    private app;
    private port;
    private server;
    constructor();
    private initializeMiddlewares;
    private initializeRoutes;
    private initializeErrorHandling;
    start(): Promise<void>;
    getApp(): express.Application;
}
export default Server;
declare global {
    namespace Express {
        interface Request {
            id: string;
            user?: {
                id: string;
                email: string;
                username: string;
                role: string;
            };
        }
    }
}
//# sourceMappingURL=server.d.ts.map