import React from 'react';
interface PowerProfile {
    id: string;
    name: string;
    description: string;
    settings: {
        locationUpdateInterval: number;
        accuracyLevel: 'high' | 'medium' | 'low';
        backgroundSync: boolean;
        radarScanInterval: number;
        maxConcurrentRequests: number;
        cacheEnabled: boolean;
    };
    batteryThreshold: number;
    estimatedBatteryLife: number;
}
interface BatteryOptimizerProps {
    onProfileChange?: (profile: PowerProfile) => void;
    onOptimizationApply?: (settings: PowerProfile['settings']) => void;
    className?: string;
}
declare const BatteryOptimizer: React.FC<BatteryOptimizerProps>;
export default BatteryOptimizer;
//# sourceMappingURL=BatteryOptimizer.d.ts.map