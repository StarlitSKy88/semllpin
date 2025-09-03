export declare enum AlertLevel {
    INFO = "info",
    WARNING = "warning",
    ERROR = "error",
    CRITICAL = "critical"
}
export declare enum AlertChannel {
    EMAIL = "email",
    SLACK = "slack",
    WEBHOOK = "webhook",
    SMS = "sms",
    DINGTALK = "dingtalk"
}
interface AlertMessage {
    title: string;
    message: string;
    level: AlertLevel;
    timestamp: string;
    metadata?: Record<string, any>;
}
declare class AlertManager {
    sendAlert(ruleKey: string, message: AlertMessage): Promise<void>;
    private sendToChannel;
    private sendEmail;
    private sendSlack;
    private sendWebhook;
    private sendSMS;
    private sendDingTalk;
    private formatEmailContent;
    private getSlackColor;
    private getEmailColor;
}
export declare const alertManager: AlertManager;
export declare const sendAlert: {
    highCpuUsage: (cpuUsage: number) => void;
    highMemoryUsage: (memoryUsage: number) => void;
    serviceDown: (serviceName: string) => void;
    highErrorRate: (errorRate: number, timeWindow: string) => void;
    dbConnectionFailed: (error: string) => void;
    paymentFailureSpike: (failureRate: number, timeWindow: string) => void;
    suspiciousLoginAttempts: (attempts: number, ip: string) => void;
};
export default alertManager;
//# sourceMappingURL=alerts.d.ts.map