import { LocationReport, AntiFraudResult, AntiFraudLog } from '../types/lbs';
export declare class AntiFraudService {
    db?: {
        query: (sql: string, params?: any[]) => Promise<{
            rows: any[];
        }>;
    };
    constructor();
    detectFraud(userId: string, locationData: LocationReport, annotationId: string): Promise<AntiFraudResult>;
    private validateGPSAccuracyInternal;
    private detectAbnormalMovement;
    private checkLocationHistory;
    private detectSuspiciousPatterns;
    private validateDeviceConsistency;
    private calculateFraudScore;
    private logAntiFraudResult;
    private calculateDistance;
    private toRadians;
    validateGPSAccuracy(gps: {
        latitude: number;
        longitude: number;
        accuracy: number;
        timestamp: number | Date;
    }): {
        isValid: boolean;
        confidence?: number;
        reason?: string;
    };
    analyzeMovementPattern(userId: string, currentLocation: {
        latitude: number;
        longitude: number;
    }): Promise<{
        isNormal: boolean;
        suspiciousActivity: boolean;
        reason?: string;
    }>;
    detectDeviceFingerprinting(deviceInfo: Record<string, any>): string;
    checkDeviceMultipleAccounts(deviceFingerprint: string): Promise<{
        multipleAccounts: boolean;
        accountCount: number;
    }>;
    analyzeRewardClaimingPattern(userId: string): Promise<{
        isNormal: boolean;
        riskScore: number;
        suspiciousPatterns: string[];
    }>;
    checkGeofenceManipulation(userId: string, geofenceId: string, userLocation: {
        latitude: number;
        longitude: number;
    }): Promise<{
        isValid: boolean;
        manipulationDetected: boolean;
        reason?: string;
    }>;
    calculateRiskScore(userId: string, context: {
        deviceInfo?: Record<string, any>;
        location?: {
            latitude: number;
            longitude: number;
        };
        recentActivity?: string;
    }): Promise<number>;
    recordSuspiciousActivity(activityData: {
        userId: string;
        activityType: string;
        description?: string;
        riskScore?: number;
        metadata?: any;
    }): Promise<any>;
    getUserFraudHistory(userId: string, days?: number): Promise<AntiFraudLog[]>;
    shouldBlockUser(userId: string, riskScore: number): Promise<{
        shouldBlock: boolean;
        reason?: string;
    }>;
}
//# sourceMappingURL=antiFraudService.d.ts.map