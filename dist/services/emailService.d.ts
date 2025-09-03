interface NotificationEmailData {
    type: string;
    title: string;
    content: string;
    fromUsername?: string;
    actionUrl?: string | undefined;
}
declare class EmailService {
    private transporter;
    private isConfigured;
    constructor();
    private initializeTransporter;
    private generateNotificationTemplate;
    sendNotificationEmail(to: string, notificationData: NotificationEmailData): Promise<boolean>;
    sendWelcomeEmail(to: string, username: string): Promise<boolean>;
    testEmailService(): Promise<boolean>;
}
export declare const emailService: EmailService;
export default emailService;
//# sourceMappingURL=emailService.d.ts.map