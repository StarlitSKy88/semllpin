import React from 'react';
interface Location {
    longitude: number;
    latitude: number;
}
interface DistanceTarget {
    id: string;
    name: string;
    description?: string;
    location: Location;
    type: 'geofence' | 'poi' | 'destination';
    reward?: number;
    estimatedTime?: number;
    isActive?: boolean;
}
interface DistanceIndicatorProps {
    userLocation: Location;
    targets: DistanceTarget[];
    selectedTargetId?: string;
    className?: string;
    onTargetSelect?: (target: DistanceTarget) => void;
    showNavigation?: boolean;
    maxDisplayTargets?: number;
    sortBy?: 'distance' | 'reward' | 'name';
}
declare const DistanceIndicator: React.FC<DistanceIndicatorProps>;
export default DistanceIndicator;
//# sourceMappingURL=DistanceIndicator.d.ts.map