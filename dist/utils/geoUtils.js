"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.calculateDistance = calculateDistance;
exports.isPointInPolygon = isPointInPolygon;
exports.generateGeofence = generateGeofence;
exports.validateCoordinates = validateCoordinates;
exports.formatCoordinates = formatCoordinates;
exports.getLocationAccuracy = getLocationAccuracy;
exports.calculateBearing = calculateBearing;
exports.getLocationFromAddress = getLocationFromAddress;
exports.isValidGPSAccuracy = isValidGPSAccuracy;
const NodeGeocoder = require('node-geocoder');
const EARTH_RADIUS = 6371000;
const GPS_ACCURACY_THRESHOLD = 20;
function calculateDistance(point1, point2) {
    if (!validateCoordinates(point1.lat, point1.lng) || !validateCoordinates(point2.lat, point2.lng)) {
        throw new Error('Invalid coordinates');
    }
    if (point1.lat === point2.lat && point1.lng === point2.lng) {
        return 0;
    }
    const lat1Rad = toRadians(point1.lat);
    const lat2Rad = toRadians(point2.lat);
    const deltaLatRad = toRadians(point2.lat - point1.lat);
    const deltaLngRad = toRadians(point2.lng - point1.lng);
    const a = Math.sin(deltaLatRad / 2) * Math.sin(deltaLatRad / 2) +
        Math.cos(lat1Rad) * Math.cos(lat2Rad) *
            Math.sin(deltaLngRad / 2) * Math.sin(deltaLngRad / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return EARTH_RADIUS * c;
}
function isPointInPolygon(point, polygon) {
    if (polygon.length < 3) {
        throw new Error('Polygon must have at least 3 points');
    }
    let inside = false;
    const x = point.lng;
    const y = point.lat;
    for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
        const pointI = polygon[i];
        const pointJ = polygon[j];
        if (!pointI || !pointJ) {
            continue;
        }
        const xi = pointI.lng;
        const yi = pointI.lat;
        const xj = pointJ.lng;
        const yj = pointJ.lat;
        if (((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi)) {
            inside = !inside;
        }
    }
    return inside;
}
function generateGeofence(center, radius, type, points = 16) {
    if (radius <= 0) {
        throw new Error('Radius must be positive');
    }
    if (!validateCoordinates(center.lat, center.lng)) {
        throw new Error('Invalid center coordinates');
    }
    const coordinates = [];
    if (type === 'circle') {
        for (let i = 0; i < points; i++) {
            const angle = (2 * Math.PI * i) / points;
            const point = getPointAtDistance(center, radius, toDegrees(angle));
            coordinates.push(point);
        }
    }
    else if (type === 'square') {
        const diagonal = radius * Math.sqrt(2);
        const halfDiagonal = diagonal / 2;
        coordinates.push(getPointAtDistance(center, halfDiagonal, 45), getPointAtDistance(center, halfDiagonal, 135), getPointAtDistance(center, halfDiagonal, 225), getPointAtDistance(center, halfDiagonal, 315));
    }
    return {
        type,
        center,
        radius,
        coordinates,
    };
}
function validateCoordinates(lat, lng) {
    return (typeof lat === 'number' &&
        typeof lng === 'number' &&
        !isNaN(lat) &&
        !isNaN(lng) &&
        isFinite(lat) &&
        isFinite(lng) &&
        lat >= -90 &&
        lat <= 90 &&
        lng >= -180 &&
        lng <= 180);
}
function formatCoordinates(lat, lng, precision = 4) {
    return `${lat.toFixed(precision)}, ${lng.toFixed(precision)}`;
}
function getLocationAccuracy(source, radius) {
    let level;
    let confidence;
    if (source === 'gps') {
        if (radius <= 10) {
            level = 'high';
            confidence = 0.95 - (radius / 100);
        }
        else if (radius <= 50) {
            level = 'medium';
            confidence = 0.85 - (radius / 200);
        }
        else {
            level = 'low';
            confidence = 0.7 - (radius / 500);
        }
    }
    else if (source === 'network') {
        level = 'medium';
        confidence = Math.max(0.3, 0.8 - (radius / 100));
    }
    else {
        level = 'low';
        confidence = Math.max(0.1, 0.6 - (radius / 200));
    }
    return {
        level,
        radius,
        confidence: Math.max(0.1, Math.min(0.99, confidence)),
    };
}
function calculateBearing(start, end) {
    if (start.lat === end.lat && start.lng === end.lng) {
        return 0;
    }
    const lat1Rad = toRadians(start.lat);
    const lat2Rad = toRadians(end.lat);
    const deltaLngRad = toRadians(end.lng - start.lng);
    const y = Math.sin(deltaLngRad) * Math.cos(lat2Rad);
    const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) -
        Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(deltaLngRad);
    let bearing = toDegrees(Math.atan2(y, x));
    bearing = (bearing + 360) % 360;
    return bearing;
}
async function getLocationFromAddress(address) {
    if (!address || address.trim().length === 0) {
        throw new Error('Address cannot be empty');
    }
    const geocoder = NodeGeocoder({
        provider: 'openstreetmap',
    });
    try {
        const results = await geocoder.geocode(address);
        if (!results || results.length === 0) {
            throw new Error('Address not found');
        }
        const result = results[0];
        if (!result || result.latitude === undefined || result.longitude === undefined) {
            throw new Error('Invalid geocoding result');
        }
        return {
            lat: result.latitude,
            lng: result.longitude,
            formattedAddress: result.formattedAddress || address,
            country: result.country,
            city: result.city,
        };
    }
    catch (error) {
        if (error instanceof Error) {
            throw error;
        }
        throw new Error('Geocoding failed');
    }
}
function isValidGPSAccuracy(accuracy, threshold = GPS_ACCURACY_THRESHOLD) {
    return (typeof accuracy === 'number' &&
        !isNaN(accuracy) &&
        isFinite(accuracy) &&
        accuracy >= 0 &&
        accuracy <= threshold);
}
function toRadians(degrees) {
    return degrees * (Math.PI / 180);
}
function toDegrees(radians) {
    return radians * (180 / Math.PI);
}
function getPointAtDistance(center, distance, bearing) {
    const bearingRad = toRadians(bearing);
    const lat1Rad = toRadians(center.lat);
    const lng1Rad = toRadians(center.lng);
    const lat2Rad = Math.asin(Math.sin(lat1Rad) * Math.cos(distance / EARTH_RADIUS) +
        Math.cos(lat1Rad) * Math.sin(distance / EARTH_RADIUS) * Math.cos(bearingRad));
    const lng2Rad = lng1Rad + Math.atan2(Math.sin(bearingRad) * Math.sin(distance / EARTH_RADIUS) * Math.cos(lat1Rad), Math.cos(distance / EARTH_RADIUS) - Math.sin(lat1Rad) * Math.sin(lat2Rad));
    return {
        lat: toDegrees(lat2Rad),
        lng: toDegrees(lng2Rad),
    };
}
//# sourceMappingURL=geoUtils.js.map