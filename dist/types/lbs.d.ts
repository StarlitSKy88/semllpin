export interface LocationReport {
    id: string;
    userId: string;
    latitude: number;
    longitude: number;
    accuracy: number;
    speed?: number;
    heading?: number;
    altitude?: number;
    timestamp: Date;
    deviceInfo?: Record<string, any>;
    batteryLevel?: number;
    networkType?: string;
    reportType: string;
    createdAt?: Date;
}
export interface GeofenceConfig {
    id: string;
    annotationId: string;
    radiusMeters: number;
    detectionFrequency: number;
    minAccuracyMeters: number;
    minStayDuration: number;
    maxSpeedKmh: number;
    isActive: boolean;
    rewardBasePercentage: number;
    timeDecayEnabled: boolean;
    firstFinderBonus: number;
    comboBonusEnabled: boolean;
    createdAt: Date;
    updatedAt: Date;
}
export interface LBSReward {
    id: string;
    userId: string;
    annotationId: string;
    amount: number;
    rewardType: 'discovery' | 'first_finder' | 'combo' | 'time_bonus';
    status: 'pending' | 'verified' | 'claimed' | 'rejected' | 'expired';
    locationReportId: string;
    createdAt: Date;
    claimedAt?: Date;
    updatedAt: Date;
    locationVerified?: boolean;
    verificationData?: Record<string, any>;
    gpsAccuracy?: number;
    movementSpeed?: number;
    stayDuration?: number;
    distanceToAnnotation?: number;
    timeDecayFactor?: number;
    expiresAt?: Date;
    antiFraudScore?: number;
    deviceFingerprint?: string;
    ipAddress?: string;
    metadata?: Record<string, any>;
}
export interface AntiFraudLog {
    id: string;
    userId: string;
    detectionType: string;
    riskScore: number;
    details: Record<string, any>;
    actionTaken?: string;
    locationReportId?: string;
    lbsRewardId?: string;
    createdAt: Date;
}
export interface LBSRewardStats {
    id: string;
    userId: string;
    totalRewardsEarned: number;
    totalDiscoveries: number;
    firstFinderCount: number;
    comboCount: number;
    maxComboStreak: number;
    currentComboStreak: number;
    lastDiscoveryAt?: Date;
    fraudDetectionCount: number;
    verificationSuccessRate: number;
    createdAt: Date;
    updatedAt: Date;
}
export interface LocationReportRequest {
    latitude: number;
    longitude: number;
    accuracy: number;
    speed?: number;
    heading?: number;
    altitude?: number;
    timestamp: string;
    deviceInfo?: Record<string, any>;
    batteryLevel?: number;
    networkType?: string;
}
export interface RewardQueryResponse {
    rewards: LBSReward[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
    };
    summary: {
        totalAmount: number;
        claimedAmount: number;
        pendingAmount: number;
    };
}
export interface ClaimRewardRequest {
    rewardIds: string[];
    verificationCode?: string;
}
export interface ClaimRewardResponse {
    success: boolean;
    amount: number;
    claimedRewards: LBSReward[];
    newWalletBalance: number;
}
export interface GeofenceTriggerResult {
    annotationId: string;
    distanceMeters: number;
    rewardEligible: boolean;
    estimatedReward?: number;
    config?: GeofenceConfig;
}
export interface AntiFraudResult {
    isFraudulent: boolean;
    fraudScore: number;
    reasons: string[];
    checkResults: Array<{
        passed: boolean;
        reason: string;
        score: number;
    }>;
    actionRequired?: 'none' | 'warning' | 'block' | 'manual_review';
    details?: Record<string, any>;
}
export interface RewardCalculationParams {
    annotationId: string;
    userId: string;
    rewardType: LBSReward['rewardType'];
    baseAmount: number;
    timeDecayFactor?: number;
    isFirstFinder?: boolean;
    comboMultiplier?: number;
    locationData: {
        latitude: number;
        longitude: number;
        accuracy: number;
        stayDuration: number;
    };
}
export interface RewardCalculationResult {
    finalAmount: number;
    breakdown: {
        baseAmount: number;
        timeDecayFactor: number;
        firstFinderBonus: number;
        comboBonus: number;
        finalAmount: number;
    };
    eligibility: {
        eligible: boolean;
        reasons: string[];
    };
}
//# sourceMappingURL=lbs.d.ts.map