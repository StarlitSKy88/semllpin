import axios from 'axios';
import nodemailer from 'nodemailer';
import { logger } from './winston';

// 告警级别
export enum AlertLevel {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

// 告警渠道
export enum AlertChannel {
  EMAIL = 'email',
  SLACK = 'slack',
  WEBHOOK = 'webhook',
  SMS = 'sms',
  DINGTALK = 'dingtalk',
}

// 告警配置接口
interface AlertConfig {
  enabled: boolean;
  channels: AlertChannel[];
  level: AlertLevel;
  cooldown: number; // 冷却时间（秒）
  recipients: string[];
}

// 告警消息接口
interface AlertMessage {
  title: string;
  message: string;
  level: AlertLevel;
  timestamp: string;
  metadata?: Record<string, any>;
}

// 告警规则配置
const alertRules: Record<string, AlertConfig> = {
  // 系统告警
  high_cpu_usage: {
    enabled: true,
    channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
    level: AlertLevel.WARNING,
    cooldown: 300, // 5分钟
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
    cooldown: 600, // 10分钟
    recipients: ['admin@smellpin.com', 'ops@smellpin.com'],
  },

  // 应用告警
  service_down: {
    enabled: true,
    channels: [AlertChannel.EMAIL, AlertChannel.SLACK, AlertChannel.SMS],
    level: AlertLevel.CRITICAL,
    cooldown: 60, // 1分钟
    recipients: ['admin@smellpin.com', 'ops@smellpin.com', '+1234567890'],
  },

  high_error_rate: {
    enabled: true,
    channels: [AlertChannel.EMAIL, AlertChannel.SLACK],
    level: AlertLevel.ERROR,
    cooldown: 180, // 3分钟
    recipients: ['dev@smellpin.com', 'ops@smellpin.com'],
  },

  slow_response_time: {
    enabled: true,
    channels: [AlertChannel.SLACK],
    level: AlertLevel.WARNING,
    cooldown: 600,
    recipients: ['dev@smellpin.com'],
  },

  // 数据库告警
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

  // 业务告警
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
    cooldown: 1800, // 30分钟
    recipients: ['business@smellpin.com'],
  },

  // 安全告警
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

// 告警冷却时间管理
const alertCooldowns = new Map<string, number>();

// 邮件传输器
const emailTransporter = nodemailer.createTransport({
  host: process.env['SMTP_HOST'] || 'smtp.gmail.com',
  port: parseInt(process.env['SMTP_PORT'] || '587'),
  secure: false,
  auth: {
    user: process.env['SMTP_USER'],
    pass: process.env['SMTP_PASS'],
  },
});

// 告警发送器类
class AlertManager {
  // 发送告警
  async sendAlert(ruleKey: string, message: AlertMessage): Promise<void> {
    const rule = alertRules[ruleKey];

    if (!rule || !rule.enabled) {
      return;
    }

    // 检查冷却时间
    const now = Date.now();
    const lastAlert = alertCooldowns.get(ruleKey) || 0;

    if (now - lastAlert < rule.cooldown * 1000) {
      logger.debug(`Alert ${ruleKey} is in cooldown period`);
      return;
    }

    // 更新冷却时间
    alertCooldowns.set(ruleKey, now);

    // 发送到各个渠道
    const promises = rule.channels.map(channel =>
      this.sendToChannel(channel, message, rule.recipients),
    );

    try {
      await Promise.allSettled(promises);
      logger.info(`Alert sent: ${ruleKey}`, { message, channels: rule.channels });
    } catch (error) {
      logger.error('Failed to send alert', { error, ruleKey, message });
    }
  }

  // 发送到指定渠道
  private async sendToChannel(
    channel: AlertChannel,
    message: AlertMessage,
    recipients: string[],
  ): Promise<void> {
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
        logger.warn(`Unknown alert channel: ${channel}`);
    }
  }

  // 发送邮件告警
  private async sendEmail(message: AlertMessage, recipients: string[]): Promise<void> {
    if (!process.env['SMTP_USER'] || !process.env['SMTP_PASS']) {
      logger.warn('Email credentials not configured');
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

  // 发送Slack告警
  private async sendSlack(message: AlertMessage): Promise<void> {
    const webhookUrl = process.env['SLACK_WEBHOOK_URL'];

    if (!webhookUrl) {
      logger.warn('Slack webhook URL not configured');
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

    await axios.post(webhookUrl, payload);
  }

  // 发送Webhook告警
  private async sendWebhook(message: AlertMessage): Promise<void> {
    const webhookUrl = process.env['ALERT_WEBHOOK_URL'];

    if (!webhookUrl) {
      logger.warn('Alert webhook URL not configured');
      return;
    }

    await axios.post(webhookUrl, {
      alert: message,
      source: 'smellpin-backend',
    });
  }

  // 发送短信告警
  private async sendSMS(message: AlertMessage, recipients: string[]): Promise<void> {
    // 这里可以集成短信服务提供商的API
    // 例如：阿里云短信、腾讯云短信等
    logger.info('SMS alert would be sent', { message, recipients });
  }

  // 发送钉钉告警
  private async sendDingTalk(message: AlertMessage): Promise<void> {
    const webhookUrl = process.env['DINGTALK_WEBHOOK_URL'];

    if (!webhookUrl) {
      logger.warn('DingTalk webhook URL not configured');
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

    await axios.post(webhookUrl, payload);
  }

  // 格式化邮件内容
  private formatEmailContent(message: AlertMessage): string {
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

  // 获取Slack颜色
  private getSlackColor(level: AlertLevel): string {
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

  // 获取邮件颜色
  private getEmailColor(level: AlertLevel): string {
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

// 创建告警管理器实例
export const alertManager = new AlertManager();

// 便捷的告警发送函数
export const sendAlert = {
  // 系统告警
  highCpuUsage: (cpuUsage: number) => {
    alertManager.sendAlert('high_cpu_usage', {
      title: 'High CPU Usage Detected',
      message: `CPU usage is ${cpuUsage.toFixed(2)}%, which exceeds the threshold.`,
      level: AlertLevel.WARNING,
      timestamp: new Date().toISOString(),
      metadata: { cpuUsage },
    });
  },

  highMemoryUsage: (memoryUsage: number) => {
    alertManager.sendAlert('high_memory_usage', {
      title: 'High Memory Usage Detected',
      message: `Memory usage is ${memoryUsage.toFixed(2)}%, which exceeds the threshold.`,
      level: AlertLevel.WARNING,
      timestamp: new Date().toISOString(),
      metadata: { memoryUsage },
    });
  },

  serviceDown: (serviceName: string) => {
    alertManager.sendAlert('service_down', {
      title: 'Service Down',
      message: `Service ${serviceName} is not responding to health checks.`,
      level: AlertLevel.CRITICAL,
      timestamp: new Date().toISOString(),
      metadata: { serviceName },
    });
  },

  highErrorRate: (errorRate: number, timeWindow: string) => {
    alertManager.sendAlert('high_error_rate', {
      title: 'High Error Rate Detected',
      message: `Error rate is ${errorRate.toFixed(2)}% in the last ${timeWindow}.`,
      level: AlertLevel.ERROR,
      timestamp: new Date().toISOString(),
      metadata: { errorRate, timeWindow },
    });
  },

  // 数据库告警
  dbConnectionFailed: (error: string) => {
    alertManager.sendAlert('db_connection_failed', {
      title: 'Database Connection Failed',
      message: `Failed to connect to database: ${error}`,
      level: AlertLevel.CRITICAL,
      timestamp: new Date().toISOString(),
      metadata: { error },
    });
  },

  // 业务告警
  paymentFailureSpike: (failureRate: number, timeWindow: string) => {
    alertManager.sendAlert('payment_failure_spike', {
      title: 'Payment Failure Spike',
      message: `Payment failure rate is ${failureRate.toFixed(2)}% in the last ${timeWindow}.`,
      level: AlertLevel.ERROR,
      timestamp: new Date().toISOString(),
      metadata: { failureRate, timeWindow },
    });
  },

  // 安全告警
  suspiciousLoginAttempts: (attempts: number, ip: string) => {
    alertManager.sendAlert('suspicious_login_attempts', {
      title: 'Suspicious Login Attempts',
      message: `${attempts} failed login attempts detected from IP ${ip}.`,
      level: AlertLevel.ERROR,
      timestamp: new Date().toISOString(),
      metadata: { attempts, ip },
    });
  },
};

export default alertManager;
