export interface ApiMetric {
    timestamp: number;
    endpoint: string;
    method: string;
    responseTime: number;
    status: number;
    payloadSize?: number;
    errorMessage?: string;
}
export interface PerformanceMetric {
    timestamp: number;
    label: string;
    cpuUsage: NodeJS.CpuUsage;
    memoryUsage: NodeJS.MemoryUsage;
    heapStatistics?: any;
}
export interface SecurityTestResult {
    testName: string;
    passed: boolean;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
    payload?: string;
    response?: any;
}
export declare class TestMetrics {
    private apiMetrics;
    private performanceMetrics;
    private securityTestResults;
    private testStartTime;
    constructor();
    recordApiCall(endpoint: string, responseTime: number, status: number, method?: string, payloadSize?: number, errorMessage?: string): void;
    recordPerformanceMetric(label: string): void;
    recordSecurityTest(result: SecurityTestResult): void;
    getApiStatistics(): {
        totalRequests: number;
        successfulRequests: number;
        clientErrors: number;
        serverErrors: number;
        successRate: number;
        averageResponseTime: number;
        minResponseTime: number;
        maxResponseTime: number;
        medianResponseTime: number;
        p95ResponseTime: number;
        p99ResponseTime: number;
        throughput: number;
        endpointSummary: any;
    } | null;
    getPerformanceStatistics(): {
        testDuration: number;
        memoryGrowth: number;
        maxMemoryUsage: number;
        avgMemoryUsage: number;
        cpuTime: {
            user: number;
            system: number;
        };
        peakMemoryUsage: number;
        memoryGrowthRate: number;
        snapshots: number;
    } | null;
    getSecurityStatistics(): {
        totalTests: number;
        passedTests: number;
        failedTests: number;
        passRate: number;
        severityBreakdown: Record<string, number>;
        vulnerabilities: {
            testName: string;
            severity: "low" | "medium" | "high" | "critical";
            description: string;
        }[];
        criticalVulnerabilities: number;
        highVulnerabilities: number;
    } | null;
    generateReport(): {
        timestamp: string;
        testDuration: number;
        summary: {
            totalApiCalls: number;
            overallSuccessRate: number;
            averageResponseTime: number;
            securityTestsPassed: number;
            vulnerabilitiesFound: number;
            memoryGrowth: number;
        };
        apiStatistics: {
            totalRequests: number;
            successfulRequests: number;
            clientErrors: number;
            serverErrors: number;
            successRate: number;
            averageResponseTime: number;
            minResponseTime: number;
            maxResponseTime: number;
            medianResponseTime: number;
            p95ResponseTime: number;
            p99ResponseTime: number;
            throughput: number;
            endpointSummary: any;
        } | null;
        performanceStatistics: {
            testDuration: number;
            memoryGrowth: number;
            maxMemoryUsage: number;
            avgMemoryUsage: number;
            cpuTime: {
                user: number;
                system: number;
            };
            peakMemoryUsage: number;
            memoryGrowthRate: number;
            snapshots: number;
        } | null;
        securityStatistics: {
            totalTests: number;
            passedTests: number;
            failedTests: number;
            passRate: number;
            severityBreakdown: Record<string, number>;
            vulnerabilities: {
                testName: string;
                severity: "low" | "medium" | "high" | "critical";
                description: string;
            }[];
            criticalVulnerabilities: number;
            highVulnerabilities: number;
        } | null;
    };
    saveReport(filename?: string): Promise<string>;
    generateHtmlReport(filename?: string): Promise<string>;
    private average;
    private percentile;
    private groupBy;
    private calculateThroughput;
    private generateHtmlContent;
    private generateApiStatsHtml;
    private generatePerformanceStatsHtml;
    private generateSecurityStatsHtml;
}
//# sourceMappingURL=test-metrics.d.ts.map