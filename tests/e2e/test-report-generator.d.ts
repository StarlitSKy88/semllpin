interface TestResult {
    title: string;
    status: 'passed' | 'failed' | 'skipped';
    duration: number;
    error?: string;
    screenshots: string[];
    performanceMetrics?: any;
}
interface TestSuite {
    name: string;
    results: TestResult[];
    totalDuration: number;
    passRate: number;
}
interface PerformanceMetrics {
    pageLoad: {
        coldStart: number;
        hotStart: number;
        fcp: number;
        lcp: number;
        cls: number;
    };
    interactions: {
        averageResponseTime: number;
        maxResponseTime: number;
    };
    memory: {
        initialUsage: number;
        finalUsage: number;
        growthPercentage: number;
    };
    network: {
        apiRequestCount: number;
        totalDataTransferred: number;
        cacheHitRate: number;
    };
}
export declare class TestReportGenerator {
    private testSuites;
    private overallMetrics;
    private startTime;
    private endTime;
    private reportDir;
    constructor(reportDir?: string);
    private initializeReportDirectory;
    addTestSuite(suite: TestSuite): void;
    setOverallMetrics(metrics: PerformanceMetrics): void;
    finalize(): void;
    generateReport(): string;
    private buildReportHtml;
    private buildPerformanceSection;
    private buildTestSuitesSection;
    private buildTestResultHtml;
    private buildRecommendationsSection;
    private buildAppendixSection;
    private generateRecommendations;
    private generateJsonReport;
    private generatePerformanceSummary;
    private getPerformanceGrade;
    private getPlaywrightVersion;
    private getReportStyles;
    private getReportScripts;
}
export {};
//# sourceMappingURL=test-report-generator.d.ts.map