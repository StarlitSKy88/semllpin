import React from 'react';
interface RadarTarget {
    id: string;
    name: string;
    distance: number;
    bearing: number;
    type: 'geofence' | 'user' | 'poi';
    strength: number;
    reward?: number;
}
interface RadarScannerProps {
    isScanning: boolean;
    targets: RadarTarget[];
    maxRange: number;
    className?: string;
    onTargetDetected?: (target: RadarTarget) => void;
    showGrid?: boolean;
    scanSpeed?: number;
}
declare const RadarScanner: React.FC<RadarScannerProps>;
export default RadarScanner;
//# sourceMappingURL=RadarScanner.d.ts.map