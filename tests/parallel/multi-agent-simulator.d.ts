import { EventEmitter } from 'events';
export interface AgentConfig {
    id: string;
    name: string;
    behavior: 'explorer' | 'annotator' | 'social' | 'merchant' | 'validator';
    intensity: 'low' | 'medium' | 'high';
    duration: number;
    baseUrl: string;
}
export interface TestScenario {
    name: string;
    description: string;
    agents: AgentConfig[];
    concurrency: number;
    expectedOutcomes: string[];
}
export interface AgentMetrics {
    agentId: string;
    startTime: number;
    endTime?: number;
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTime: number;
    errors: string[];
    actions: AgentAction[];
}
export interface AgentAction {
    timestamp: number;
    action: string;
    endpoint: string;
    duration: number;
    success: boolean;
    error?: string;
    responseData?: any;
}
export declare class MultiAgentSimulator extends EventEmitter {
    private agents;
    private scenarios;
    private isRunning;
    private startTime?;
    private endTime?;
    private reportDir;
    constructor(reportDir?: string);
    private setupDefaultScenarios;
    runScenario(scenarioName: string): Promise<void>;
    private setupAgentEventListeners;
    private generateReport;
    private calculateSummary;
    private groupMetricsByBehavior;
    private evaluateOutcomes;
    private generateHtmlReport;
    private getBehaviorName;
    private printSummary;
    private sleep;
    addCustomScenario(name: string, scenario: TestScenario): void;
    getAvailableScenarios(): string[];
    stopAll(): void;
}
export declare const simulator: MultiAgentSimulator;
//# sourceMappingURL=multi-agent-simulator.d.ts.map