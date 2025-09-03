#!/usr/bin/env ts-node
import { EventEmitter } from 'events';
interface TestSuite {
    name: string;
    description: string;
    scenarios: string[];
    parallel: boolean;
    timeout: number;
}
declare class ComprehensiveTestRunner extends EventEmitter {
    private testSuites;
    private runningTests;
    private results;
    private startTime?;
    private reportDir;
    private dashboardData;
    constructor(reportDir?: string);
    private setupTestSuites;
    runTestSuite(suiteName: string): Promise<boolean>;
    private runScenariosInParallel;
    private runScenariosSequentially;
    private runSystemTests;
    private testDatabaseIntegrity;
    private testApiEndpoints;
    private testPerformanceMetrics;
    private testSecurityBasics;
    private generateComprehensiveReport;
    private generateHtmlReport;
    private updateDashboard;
    getAvailableTestSuites(): string[];
    getTestSuiteInfo(suiteName: string): TestSuite | undefined;
    addCustomTestSuite(name: string, suite: TestSuite): void;
}
export declare const comprehensiveTestRunner: ComprehensiveTestRunner;
export {};
//# sourceMappingURL=comprehensive-test-runner.d.ts.map