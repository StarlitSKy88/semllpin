"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendAlert = exports.alertManager = exports.AlertChannel = exports.AlertLevel = void 0;
const axios_1 = __importDefault(require("axios"));
const nodemailer_1 = __importDefault(require("nodemailer"));
const winston_1 = require("./winston");
var AlertLevel;
(function (AlertLevel) {
    AlertLevel["INFO"] = "info";
    AlertLevel["WARNING"] = "warning";
    AlertLevel["ERROR"] = "error";
    AlertLevel["CRITICAL"] = "critical";
})(AlertLevel || (exports.AlertLevel = AlertLevel = {}));
var AlertChannel;
(function (AlertChannel) {
    AlertChannel["EMAIL"] = "email";
    AlertChannel["SLACK"] = "slack";
    AlertChannel["WEBHOOK"] = "webhook";
    AlertChannel["SMS"] = "sms";
    AlertChannel["DINGTALK"] = "dingtalk";
})(AlertChannel || (exports.AlertChannel = AlertChannel = {}));
const alertRules = {
    high_cpu_usage: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
        level: AlertLevel.WARNING,
        cooldown: 300,
        recipients: ['admin@smellpin.com', 'ops@smellpin.com'],
    },
    high_memory_usage: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
        level: AlertLevel.WARNING,
        cooldown: 300,
        recipients: ['admin@smellpin.com', 'ops@smellpin.com'],
    },
    disk_space_low: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
        level: AlertLevel.ERROR,
        cooldown: 600,
        recipients: ['admin@smellpin.com', 'ops@smellpin.com'],
    },
    service_down: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK, AlertChannel.SMS],
        level: AlertLevel.CRITICAL,
        cooldown: 60,
        recipients: ['admin@smellpin.com', 'ops@smellpin.com', '+1234567890'],
    },
    high_error_rate: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
        level: AlertLevel.ERROR,
        cooldown: 180,
        recipients: ['dev@smellpin.com', 'ops@smellpin.com'],
    },
    slow_response_time: {
        enabled: true,
        channels: [AlertChannel.SLACK],
        level: AlertLevel.WARNING,
        cooldown: 600,
        recipients: ['dev@smellpin.com'],
    },
    db_connection_failed: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
        level: AlertLevel.CRITICAL,
        cooldown: 120,
        recipients: ['admin@smellpin.com', 'dba@smellpin.com'],
    },
    db_slow_query: {
        enabled: true,
        channels: [AlertChannel.SLACK],
        level: AlertLevel.WARNING,
        cooldown: 300,
        recipients: ['dba@smellpin.com'],
    },
    payment_failure_spike: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
        level: AlertLevel.ERROR,
        cooldown: 300,
        recipients: ['business@smellpin.com', 'dev@smellpin.com'],
    },
    user_registration_drop: {
        enabled: true,
        channels: [AlertChannel.EMAIL],
        level: AlertLevel.WARNING,
        cooldown: 1800,
        recipients: ['business@smellpin.com'],
    },
    suspicious_login_attempts: {
        enabled: true,
        channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
        level: AlertLevel.ERROR,
        cooldown: 300,
        recipients: ['security@smellpin.com', 'admin@smellpin.com'],
    },
    rate_limit_exceeded: {
        enabled: true,
        channels: [AlertChannel.SLACK],
        level: AlertLevel.WARNING,
        cooldown: 600,
        recipients: ['security@smellpin.com'],
    },
};
const alertCooldowns = new Map();
const emailTransporter = nodemailer_1.default.createTransport({
    host: process.env['SMTP_HOST'] || 'smtp.gmail.com',
    port: parseInt(process.env['SMTP_PORT'] || '587'),
    secure: false,
    auth: {
        user: process.env['SMTP_USER'],
        pass: process.env['SMTP_PASS'],
    },
});
class AlertManager {
    async sendAlert(ruleKey, message) {
        const rule = alertRules[ruleKey];
        if (!rule || !rule.enabled) {
            return;
        }
        const now = Date.now();
        const lastAlert = alertCooldowns.get(ruleKey) || 0;
        if (now - lastAlert < rule.cooldown * 1000) {
            winston_1.logger.debug(`Alert ${ruleKey} is in cooldown period`);
            return;
        }
        alertCooldowns.set(ruleKey, now);
        const promises = rule.channels.map(channel => this.sendToChannel(channel, message, rule.recipients));
        try {
            await Promise.allSettled(promises);
            winston_1.logger.info(`Alert sent: ${ruleKey}`, { message, channels: rule.channels });
        }
        catch (error) {
            winston_1.logger.error('Failed to send alert', { error, ruleKey, message });
        }
    }
    async sendToChannel(channel, message, recipients) {
        switch (channel) {
            case AlertChannel.EMAIL:
                await this.sendEmail(message, recipients);
                break;
            case AlertChannel.SLACK:
                await this.sendSlack(message);
                break;
            case AlertChannel.WEBHOOK:
                await this.sendWebhook(message);
                break;
            case AlertChannel.SMS:
                await this.sendSMS(message, recipients);
                break;
            case AlertChannel.DINGTALK:
                await this.sendDingTalk(message);
                break;
            default:
                winston_1.logger.warn(`Unknown alert channel: ${channel}`);
        }
    }
    async sendEmail(message, recipients) {
        if (!process.env['SMTP_USER'] || !process.env['SMTP_PASS']) {
            winston_1.logger.warn('Email credentials not configured');
            return;
        }
        const emailRecipients = recipients.filter(r => r.includes('@'));
        if (emailRecipients.length === 0) {
            return;
        }
        const mailOptions = {
            from: process.env['SMTP_FROM'] || 'alerts@smellpin.com',
            to: emailRecipients.join(','),
            subject: `[${message.level.toUpperCase()}] ${message.title}`,
            html: this.formatEmailContent(message),
        };
        await emailTransporter.sendMail(mailOptions);
    }
    async sendSlack(message) {
        const webhookUrl = process.env['SLACK_WEBHOOK_URL'];
        if (!webhookUrl) {
            winston_1.logger.warn('Slack webhook URL not configured');
            return;
        }
        const color = this.getSlackColor(message.level);
        const payload = {
            attachments: [
                {
                    color,
                    title: message.title,
                    text: message.message,
                    fields: [
                        {
                            title: 'Level',
                            value: message.level.toUpperCase(),
                            short: true,
                        },
                        {
                            title: 'Time',
                            value: message.timestamp,
                            short: true,
                        },
                    ],
                    footer: 'SmellPin Monitoring',
                    ts: Math.floor(new Date(message.timestamp).getTime() / 1000),
                },
            ],
        };
        await axios_1.default.post(webhookUrl, payload);
    }
    async sendWebhook(message) {
        const webhookUrl = process.env['ALERT_WEBHOOK_URL'];
        if (!webhookUrl) {
            winston_1.logger.warn('Alert webhook URL not configured');
            return;
        }
        await axios_1.default.post(webhookUrl, {
            alert: message,
            source: 'smellpin-backend',
        });
    }
    async sendSMS(message, recipients) {
        winston_1.logger.info('SMS alert would be sent', { message, recipients });
    }
    async sendDingTalk(message) {
        const webhookUrl = process.env['DINGTALK_WEBHOOK_URL'];
        if (!webhookUrl) {
            winston_1.logger.warn('DingTalk webhook URL not configured');
            return;
        }
        const payload = {
            msgtype: 'markdown',
            markdown: {
                title: message.title,
                text: `### ${message.title}\n\n` +
                    `**级别**: ${message.level.toUpperCase()}\n\n` +
                    `**时间**: ${message.timestamp}\n\n` +
                    `**详情**: ${message.message}`,
            },
        };
        await axios_1.default.post(webhookUrl, payload);
    }
    formatEmailContent(message) {
        return `
      <html>
        <body>
          <h2 style="color: ${this.getEmailColor(message.level)}">${message.title}</h2>
          <p><strong>级别:</strong> ${message.level.toUpperCase()}</p>
          <p><strong>时间:</strong> ${message.timestamp}</p>
          <p><strong>详情:</strong></p>
          <p>${message.message}</p>
          ${message.metadata ? `
            <p><strong>元数据:</strong></p>
            <pre>${JSON.stringify(message.metadata, null, 2)}</pre>
          ` : ''}
          <hr>
          <p><small>此邮件由SmellPin监控系统自动发送</small></p>
        </body>
      </html>
    `;
    }
    getSlackColor(level) {
        switch (level) {
            case AlertLevel.INFO:
                return 'good';
            case AlertLevel.WARNING:
                return 'warning';
            case AlertLevel.ERROR:
                return 'danger';
            case AlertLevel.CRITICAL:
                return '#ff0000';
            default:
                return '#cccccc';
        }
    }
    getEmailColor(level) {
        switch (level) {
            case AlertLevel.INFO:
                return '#28a745';
            case AlertLevel.WARNING:
                return '#ffc107';
            case AlertLevel.ERROR:
                return '#dc3545';
            case AlertLevel.CRITICAL:
                return '#ff0000';
            default:
                return '#6c757d';
        }
    }
}
exports.alertManager = new AlertManager();
exports.sendAlert = {
    highCpuUsage: (cpuUsage) => {
        exports.alertManager.sendAlert('high_cpu_usage', {
            title: 'High CPU Usage Detected',
            message: `CPU usage is ${cpuUsage.toFixed(2)}%, which exceeds the threshold.`,
            level: AlertLevel.WARNING,
            timestamp: new Date().toISOString(),
            metadata: { cpuUsage },
        });
    },
    highMemoryUsage: (memoryUsage) => {
        exports.alertManager.sendAlert('high_memory_usage', {
            title: 'High Memory Usage Detected',
            message: `Memory usage is ${memoryUsage.toFixed(2)}%, which exceeds the threshold.`,
            level: AlertLevel.WARNING,
            timestamp: new Date().toISOString(),
            metadata: { memoryUsage },
        });
    },
    serviceDown: (serviceName) => {
        exports.alertManager.sendAlert('service_down', {
            title: 'Service Down',
            message: `Service ${serviceName} is not responding to health checks.`,
            level: AlertLevel.CRITICAL,
            timestamp: new Date().toISOString(),
            metadata: { serviceName },
        });
    },
    highErrorRate: (errorRate, timeWindow) => {
        exports.alertManager.sendAlert('high_error_rate', {
            title: 'High Error Rate Detected',
            message: `Error rate is ${errorRate.toFixed(2)}% in the last ${timeWindow}.`,
            level: AlertLevel.ERROR,
            timestamp: new Date().toISOString(),
            metadata: { errorRate, timeWindow },
        });
    },
    dbConnectionFailed: (error) => {
        exports.alertManager.sendAlert('db_connection_failed', {
            title: 'Database Connection Failed',
            message: `Failed to connect to database: ${error}`,
            level: AlertLevel.CRITICAL,
            timestamp: new Date().toISOString(),
            metadata: { error },
        });
    },
    paymentFailureSpike: (failureRate, timeWindow) => {
        exports.alertManager.sendAlert('payment_failure_spike', {
            title: 'Payment Failure Spike',
            message: `Payment failure rate is ${failureRate.toFixed(2)}% in the last ${timeWindow}.`,
            level: AlertLevel.ERROR,
            timestamp: new Date().toISOString(),
            metadata: { failureRate, timeWindow },
        });
    },
    suspiciousLoginAttempts: (attempts, ip) => {
        exports.alertManager.sendAlert('suspicious_login_attempts', {
            title: 'Suspicious Login Attempts',
            message: `${attempts} failed login attempts detected from IP ${ip}.`,
            level: AlertLevel.ERROR,
            timestamp: new Date().toISOString(),
            metadata: { attempts, ip },
        });
    },
};
exports.default = exports.alertManager;
//# sourceMappingURL=alerts.js.map