export declare enum HealthStatus {
    HEALTHY = "healthy",
    DEGRADED = "degraded",
    UNHEALTHY = "unhealthy"
}
export interface ServiceHealthInfo {
    status: HealthStatus;
    responseTime?: number;
    error?: string;
    details?: any;
    lastCheck?: string;
}
export interface SystemHealthInfo {
    status: HealthStatus;
    timestamp: string;
    version: string;
    environment: string;
    uptime: number;
    services: {
        [serviceName: string]: ServiceHealthInfo;
    };
    metrics?: {
        [metricName: string]: number;
    };
}
declare class HealthService {
    private healthChecks;
    private lastHealthCheck;
    private healthCheckInterval;
    constructor();
    registerHealthCheck(serviceName: string, checkFunction: () => Promise<ServiceHealthInfo>): void;
    unregisterHealthCheck(serviceName: string): void;
    performHealthCheck(): Promise<SystemHealthInfo>;
    getLastHealthCheck(): SystemHealthInfo | null;
    private calculateOverallStatus;
    private createTimeoutPromise;
    private startPeriodicHealthCheck;
    stopPeriodicHealthCheck(): void;
    checkServiceHealth(serviceName: string): Promise<ServiceHealthInfo | null>;
    getSystemHealth(): Promise<SystemHealthInfo>;
    getSimpleHealth(): Promise<{
        status: string;
        timestamp: string;
    }>;
    getReadinessStatus(): Promise<SystemHealthInfo>;
    getLivenessStatus(): Promise<{
        status: string;
        timestamp: string;
        uptime: number;
    }>;
    getSystemInfo(): any;
    initialize(): Promise<void>;
    cleanup(): Promise<void>;
}
export declare const healthService: HealthService;
export default healthService;
//# sourceMappingURL=healthService.d.ts.map