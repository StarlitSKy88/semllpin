declare class ComprehensiveTestRunner {
    private testMetrics;
    private suites;
    private results;
    constructor();
    runAllTests(): Promise<void>;
    private runTestSuite;
    private executeJestTest;
    private generateComprehensiveReport;
    private generateRecommendations;
    private generateHtmlReport;
    private printConsoleSummary;
}
export default ComprehensiveTestRunner;
//# sourceMappingURL=test-runner.d.ts.map