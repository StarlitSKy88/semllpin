export interface Coordinates {
    lat: number;
    lng: number;
}
export interface GeofenceResult {
    type: 'circle' | 'square';
    center: Coordinates;
    radius: number;
    coordinates: Coordinates[];
}
export interface LocationAccuracy {
    level: 'high' | 'medium' | 'low';
    radius: number;
    confidence: number;
}
export interface GeocodingResult {
    lat: number;
    lng: number;
    formattedAddress: string;
    country?: string;
    city?: string;
}
export declare function calculateDistance(point1: Coordinates, point2: Coordinates): number;
export declare function isPointInPolygon(point: Coordinates, polygon: Coordinates[]): boolean;
export declare function generateGeofence(center: Coordinates, radius: number, type: 'circle' | 'square', points?: number): GeofenceResult;
export declare function validateCoordinates(lat: number, lng: number): boolean;
export declare function formatCoordinates(lat: number, lng: number, precision?: number): string;
export declare function getLocationAccuracy(source: string, radius: number): LocationAccuracy;
export declare function calculateBearing(start: Coordinates, end: Coordinates): number;
export declare function getLocationFromAddress(address: string): Promise<GeocodingResult>;
export declare function isValidGPSAccuracy(accuracy: number, threshold?: number): boolean;
//# sourceMappingURL=geoUtils.d.ts.map