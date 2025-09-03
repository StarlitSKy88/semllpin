#!/usr/bin/env ts-node
interface DashboardData {
    status: 'idle' | 'running' | 'passed' | 'failed';
    currentSuite: any;
    progress: number;
    results: any[];
    metrics: {
        totalTests: number;
        passedTests: number;
        failedTests: number;
        totalDuration: number;
    };
    liveMetrics: {
        timestamp: number;
        cpu: number;
        memory: number;
        activeConnections: number;
        responseTime: number;
    }[];
}
declare class TestDashboard {
    private app;
    private server;
    private io;
    private port;
    private reportDir;
    private dashboardData;
    private clients;
    constructor(port?: number, reportDir?: string);
    private setupRoutes;
    private setupSocketHandlers;
    private generateDashboardHtml;
    private startMetricsCollection;
    private watchReportFiles;
    private loadDashboardData;
    start(): Promise<void>;
    stop(): Promise<void>;
    updateStatus(status: DashboardData['status'], progress?: number): void;
}
export declare const testDashboard: TestDashboard;
export {};
//# sourceMappingURL=dashboard-server.d.ts.map