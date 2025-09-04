import nodemailer from 'nodemailer';
import { logger } from '../utils/logger';

interface EmailConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
}

interface EmailTemplate {
  subject: string;
  html: string;
  text: string;
}

interface NotificationEmailData {
  type: string;
  title: string;
  content: string;
  fromUsername?: string;
  actionUrl?: string | undefined;
}

class EmailService {
  private transporter: nodemailer.Transporter | null = null;
  private isConfigured = false;

  constructor() {
    this.initializeTransporter();
  }

  private initializeTransporter() {
    try {
      const emailConfig: EmailConfig = {
        host: process.env['SMTP_HOST'] || 'smtp.gmail.com',
        port: parseInt(process.env['SMTP_PORT'] || '587'),
        secure: process.env['SMTP_SECURE'] === 'true',
        auth: {
          user: process.env['SMTP_USER'] || '',
          pass: process.env['SMTP_PASS'] || '',
        },
      };

      if (!emailConfig.auth.user || !emailConfig.auth.pass) {
        logger.warn('邮件服务未配置，将跳过邮件发送');
        return;
      }

      this.transporter = nodemailer.createTransport(emailConfig);
      this.isConfigured = true;

      // 验证配置
      this.transporter?.verify((error: any) => {
        if (error) {
          logger.error('邮件服务配置验证失败:', error);
          this.isConfigured = false;
        } else {
          logger.info('邮件服务配置验证成功');
        }
      });
    } catch (error) {
      logger.error('初始化邮件服务失败:', error);
    }
  }

  // 生成通知邮件模板
  private generateNotificationTemplate(data: NotificationEmailData): EmailTemplate {
    const { type, title, content, fromUsername, actionUrl } = data;

    const baseUrl = process.env['FRONTEND_URL'] || 'http://localhost:5176';
    const logoUrl = `${baseUrl}/logo.png`;

    const typeLabels: { [key: string]: string } = {
      follow: '关注',
      comment: '评论',
      like: '点赞',
      share: '分享',
      system: '系统',
    };

    const typeLabel = typeLabels[type] || '通知';

    const html = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
          }
          .container {
            background-color: #ffffff;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
          }
          .logo {
            width: 60px;
            height: 60px;
            margin-bottom: 15px;
          }
          .title {
            color: #1890ff;
            font-size: 24px;
            font-weight: bold;
            margin: 0;
          }
          .notification-type {
            display: inline-block;
            background-color: #1890ff;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 15px;
          }
          .notification-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
          }
          .notification-content {
            font-size: 14px;
            color: #666;
            margin-bottom: 20px;
            line-height: 1.5;
          }
          .from-user {
            font-size: 13px;
            color: #999;
            margin-bottom: 20px;
          }
          .action-button {
            display: inline-block;
            background-color: #1890ff;
            color: white;
            text-decoration: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: bold;
            margin: 20px 0;
          }
          .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            font-size: 12px;
            color: #999;
          }
          .unsubscribe {
            color: #999;
            text-decoration: none;
            font-size: 11px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <img src="${logoUrl}" alt="SmellPin" class="logo" />
            <h1 class="title">SmellPin</h1>
          </div>
          
          <div class="notification-type">${typeLabel}通知</div>
          
          <div class="notification-title">${title}</div>
          
          <div class="notification-content">${content}</div>
          
          ${fromUsername ? `<div class="from-user">来自: ${fromUsername}</div>` : ''}
          
          ${actionUrl ? `
            <div style="text-align: center;">
              <a href="${actionUrl}" class="action-button">查看详情</a>
            </div>
          ` : ''}
          
          <div class="footer">
            <p>这是一封来自 SmellPin 的通知邮件</p>
            <p>
              <a href="${baseUrl}/notifications" class="unsubscribe">管理通知设置</a> |
              <a href="${baseUrl}/unsubscribe" class="unsubscribe">取消订阅</a>
            </p>
          </div>
        </div>
      </body>
      </html>
    `;

    const text = `
${typeLabel}通知 - SmellPin

${title}

${content}

${fromUsername ? `来自: ${fromUsername}\n` : ''}
${actionUrl ? `查看详情: ${actionUrl}\n` : ''}

---
这是一封来自 SmellPin 的通知邮件
管理通知设置: ${baseUrl}/notifications
取消订阅: ${baseUrl}/unsubscribe
    `.trim();

    return {
      subject: `[SmellPin] ${title}`,
      html,
      text,
    };
  }

  // 发送通知邮件
  async sendNotificationEmail(
    to: string,
    notificationData: NotificationEmailData,
  ): Promise<boolean> {
    if (!this.isConfigured || !this.transporter) {
      logger.warn('邮件服务未配置，跳过邮件发送');
      return false;
    }

    try {
      const template = this.generateNotificationTemplate(notificationData);

      const mailOptions = {
        from: {
          name: 'SmellPin',
          address: process.env['SMTP_FROM'] || process.env['SMTP_USER'] || '',
        },
        to,
        subject: template.subject,
        text: template.text,
        html: template.html,
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`通知邮件发送成功: ${result.messageId}`);
      return true;
    } catch (error) {
      logger.error('发送通知邮件失败:', error);
      return false;
    }
  }

  // 发送欢迎邮件
  async sendWelcomeEmail(to: string, username: string): Promise<boolean> {
    if (!this.isConfigured || !this.transporter) {
      return false;
    }

    try {
      const baseUrl = process.env['FRONTEND_URL'] || 'http://localhost:5176';

      const mailOptions = {
        from: {
          name: 'SmellPin',
          address: process.env['SMTP_FROM'] || process.env['SMTP_USER'] || '',
        },
        to,
        subject: '[SmellPin] 欢迎加入 SmellPin！',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h1 style="color: #1890ff;">欢迎加入 SmellPin！</h1>
            <p>亲爱的 ${username}，</p>
            <p>欢迎加入 SmellPin 社区！现在你可以：</p>
            <ul>
              <li>在地图上标记和分享有趣的气味</li>
              <li>与其他用户互动和评论</li>
              <li>发现你周围的有趣内容</li>
            </ul>
            <p><a href="${baseUrl}/map" style="background-color: #1890ff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">开始探索</a></p>
            <p>祝你使用愉快！</p>
            <p>SmellPin 团队</p>
          </div>
        `,
        text: `欢迎加入 SmellPin！\n\n亲爱的 ${username}，\n\n欢迎加入 SmellPin 社区！现在你可以在地图上标记和分享有趣的气味，与其他用户互动和评论，发现你周围的有趣内容。\n\n开始探索: ${baseUrl}/map\n\n祝你使用愉快！\nSmellPin 团队`,
      };

      const result = await this.transporter.sendMail(mailOptions);
      logger.info(`欢迎邮件发送成功: ${result.messageId}`);
      return true;
    } catch (error) {
      logger.error('发送欢迎邮件失败:', error);
      return false;
    }
  }

  // 测试邮件服务
  async testEmailService(): Promise<boolean> {
    if (!this.isConfigured || !this.transporter) {
      return false;
    }

    try {
      await this.transporter.verify();
      return true;
    } catch (error) {
      logger.error('邮件服务测试失败:', error);
      return false;
    }
  }
}

// 导出单例实例
export const emailService = new EmailService();
export default emailService;
