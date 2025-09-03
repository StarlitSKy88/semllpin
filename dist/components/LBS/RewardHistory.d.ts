import React from 'react';
interface RewardRecord {
    id: string;
    userId: string;
    geofenceId: string;
    geofenceName: string;
    rewardType: 'discovery' | 'checkin' | 'stay' | 'social';
    baseReward: number;
    timeDecay: number;
    firstDiscoveryBonus: number;
    finalPoints: number;
    longitude: number;
    latitude: number;
    timestamp: string;
    metadata?: any;
}
interface RewardHistoryProps {
    className?: string;
    onRewardSelect?: (reward: RewardRecord) => void;
}
declare const RewardHistory: React.FC<RewardHistoryProps>;
export default RewardHistory;
//# sourceMappingURL=RewardHistory.d.ts.map