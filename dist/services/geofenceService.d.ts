import { GeofenceConfig } from '../types/lbs';
export declare class GeofenceService {
    constructor();
    checkGeofenceTriggers(latitude: number, longitude: number, _userId: string): Promise<Array<{
        annotationId: string;
        distance: number;
        triggered: boolean;
    }>>;
    createGeofenceConfig(config: Omit<GeofenceConfig, 'id' | 'createdAt' | 'updatedAt'>): Promise<GeofenceConfig>;
    getGeofenceConfig(annotationId: string): Promise<GeofenceConfig | null>;
    updateGeofenceConfig(id: string, updates: Partial<Omit<GeofenceConfig, 'id' | 'createdAt' | 'updatedAt'>>): Promise<GeofenceConfig>;
    calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number;
    validateGPSAccuracy(accuracy: number, requiredAccuracy?: number): boolean;
    validateMovementSpeed(previousLocation: {
        latitude: number;
        longitude: number;
        timestamp: Date;
    }, currentLocation: {
        latitude: number;
        longitude: number;
        timestamp: Date;
    }, maxSpeedKmh?: number): boolean;
    private toRadians;
    private mapGeofenceConfig;
}
//# sourceMappingURL=geofenceService.d.ts.map