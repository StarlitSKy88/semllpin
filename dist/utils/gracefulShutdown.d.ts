export declare class GracefulShutdown {
    private isShuttingDown;
    private server;
    private shutdownTimeout;
    private cleanupCallbacks;
    constructor(server: any);
    addCleanupCallback(callback: () => Promise<void>): void;
    private setupSignalHandlers;
    private shutdown;
    private waitForActiveConnections;
    setShutdownTimeout(timeout: number): void;
}
export declare function gracefulShutdown(server: any, cleanupCallback?: () => Promise<void>): GracefulShutdown;
export default gracefulShutdown;
//# sourceMappingURL=gracefulShutdown.d.ts.map