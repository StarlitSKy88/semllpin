import React from 'react';
interface Location {
    longitude: number;
    latitude: number;
}
interface GeofenceTarget {
    id: string;
    name: string;
    description?: string;
    location: Location;
    type: 'geofence' | 'poi' | 'destination';
    reward?: number;
    radius?: number;
    isActive?: boolean;
}
interface RadarTarget {
    id: string;
    name: string;
    distance: number;
    bearing: number;
    type: 'user' | 'geofence' | 'poi';
    strength: number;
    data?: any;
}
interface AdvancedLBSComponentsProps {
    userLocation: Location;
    geofenceTargets: GeofenceTarget[];
    onTargetDetected?: (target: RadarTarget) => void;
    onSettingsChange?: (settings: any) => void;
    className?: string;
}
declare const AdvancedLBSComponents: React.FC<AdvancedLBSComponentsProps>;
export default AdvancedLBSComponents;
//# sourceMappingURL=AdvancedLBSComponents.d.ts.map