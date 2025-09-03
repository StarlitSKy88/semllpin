import React from 'react';
interface Location {
    longitude: number;
    latitude: number;
    accuracy?: number | null;
    timestamp?: number;
}
interface Geofence {
    id: string;
    name: string;
    description?: string;
    longitude: number;
    latitude: number;
    radius: number;
    rewardType: string;
    baseReward: number;
    distance?: number;
    isActive: boolean;
    metadata?: any;
}
interface GeofenceMapProps {
    center: [number, number];
    geofences: Geofence[];
    userLocation?: Location;
    className?: string;
    onGeofenceClick?: (geofence: Geofence) => void;
    showUserAccuracy?: boolean;
    interactive?: boolean;
}
declare const GeofenceMap: React.FC<GeofenceMapProps>;
export default GeofenceMap;
//# sourceMappingURL=GeofenceMap.d.ts.map