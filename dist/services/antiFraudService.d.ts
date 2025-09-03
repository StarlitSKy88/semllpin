import { LocationReport, AntiFraudResult, AntiFraudLog } from '../types/lbs';
export declare class AntiFraudService {
    constructor();
    detectFraud(userId: string, locationData: LocationReport, annotationId: string): Promise<AntiFraudResult>;
    private validateGPSAccuracy;
    private detectAbnormalMovement;
    private checkLocationHistory;
    private detectSuspiciousPatterns;
    private validateDeviceConsistency;
    private calculateFraudScore;
    private logAntiFraudResult;
    private calculateDistance;
    private toRadians;
    getUserFraudHistory(userId: string, days?: number): Promise<AntiFraudLog[]>;
    shouldBlockUser(userId: string, riskScore: number): Promise<{
        shouldBlock: boolean;
        reason?: string;
    }>;
}
//# sourceMappingURL=antiFraudService.d.ts.map