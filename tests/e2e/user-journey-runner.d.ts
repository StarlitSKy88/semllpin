interface TestResult {
    testName: string;
    status: 'passed' | 'failed' | 'skipped';
    duration: number;
    error?: string;
    screenshots: string[];
    uxMetrics?: any;
    userFeedback?: UserFeedback;
}
interface UserFeedback {
    taskCompletionRate: number;
    userSatisfactionScore: number;
    usabilityIssues: string[];
    suggestions: string[];
}
interface ComprehensiveTestReport {
    summary: {
        totalTests: number;
        passed: number;
        failed: number;
        skipped: number;
        totalDuration: number;
        overallSuccessRate: number;
    };
    deviceResults: Record<string, TestResult[]>;
    networkResults: Record<string, TestResult[]>;
    userJourneyResults: Record<string, TestResult[]>;
    performanceMetrics: {
        averagePageLoadTime: number;
        averageTaskCompletionTime: number;
        errorRate: number;
        conversionRates: Record<string, number>;
    };
    usabilityFindings: {
        criticalIssues: string[];
        moderateIssues: string[];
        minorIssues: string[];
        positiveFindings: string[];
    };
    recommendations: string[];
    timestamp: string;
}
export declare class UserJourneyRunner {
    private browser;
    private results;
    private startTime;
    initialize(): Promise<void>;
    cleanup(): Promise<void>;
    runNewUserRegistrationTests(): Promise<TestResult[]>;
    runAnnotationCreatorTests(): Promise<TestResult[]>;
    runRewardDiscovererTests(): Promise<TestResult[]>;
    runSocialInteractionTests(): Promise<TestResult[]>;
    runCrossDeviceNetworkTests(): Promise<TestResult[]>;
    private runSingleTest;
    private simulateUserFeedback;
    generateComprehensiveReport(): Promise<ComprehensiveTestReport>;
    private groupResultsByCategory;
    private calculateConversionRates;
    exportReport(report: ComprehensiveTestReport, filename?: string): Promise<void>;
    private generateHTMLReport;
    runCompleteTestSuite(): Promise<void>;
}
export {};
//# sourceMappingURL=user-journey-runner.d.ts.map