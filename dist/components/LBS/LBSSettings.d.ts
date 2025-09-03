import React from 'react';
interface LBSSettingsData {
    locationTracking: {
        enabled: boolean;
        accuracy: 'high' | 'medium' | 'low';
        updateInterval: number;
        backgroundTracking: boolean;
        batteryOptimization: boolean;
    };
    geofencing: {
        enabled: boolean;
        detectionRadius: number;
        minStayDuration: number;
        maxDailyRewards: number;
        autoCheckin: boolean;
    };
    notifications: {
        enabled: boolean;
        rewardNotifications: boolean;
        geofenceEntry: boolean;
        geofenceExit: boolean;
        dailySummary: boolean;
        sound: boolean;
        vibration: boolean;
    };
    privacy: {
        shareLocation: boolean;
        anonymousMode: boolean;
        dataRetention: number;
        allowAnalytics: boolean;
    };
    performance: {
        cacheSize: number;
        offlineMode: boolean;
        dataCompression: boolean;
        lowDataMode: boolean;
    };
}
interface LBSSettingsProps {
    className?: string;
    onSettingsChange?: (settings: LBSSettingsData) => void;
}
declare const LBSSettings: React.FC<LBSSettingsProps>;
export default LBSSettings;
//# sourceMappingURL=LBSSettings.d.ts.map