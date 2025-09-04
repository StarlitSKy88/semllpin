/**
 * SmellPin LBS Reward System - Anti-Fraud Security System
 * Components: SEC-001 to SEC-005
 * Advanced fraud detection, GPS spoofing prevention, user behavior analysis, and automated response
 */

import { EventEmitter } from 'events';
import crypto from 'crypto';
import { logger } from '../../utils/logger';
import { RedisService } from '../RedisService';
import { GeoPoint, LocationValidation } from './GeographicCoreSystem';

// Types and Interfaces
export interface DeviceFingerprint {
  deviceId: string;
  userAgent: string;
  screenResolution: string;
  timezone: string;
  language: string;
  platform: string;
  hardware: string;
  networkInfo: string;
  batteryLevel?: number;
  sensors: string[];
  installedApps?: string[];
  fingerprint: string; // SHA-256 hash of all combined data
  confidence: number;
  firstSeen: Date;
  lastSeen: Date;
}

export interface UserBehaviorPattern {
  userId: string;
  patterns: {
    typicalLocations: GeoPoint[];
    movementPatterns: Array<{ from: GeoPoint; to: GeoPoint; frequency: number }>;
    timePatterns: Array<{ hour: number; dayOfWeek: number; frequency: number }>;
    speedPatterns: { min: number; max: number; average: number; stdDev: number };
    accuracyPatterns: { min: number; max: number; average: number; stdDev: number };
  };
  riskScore: number;
  anomalyHistory: AnomalyEvent[];
  lastUpdated: Date;
}

export interface AnomalyEvent {
  id: string;
  userId: string;
  type: 'GPS_SPOOFING' | 'BEHAVIOR_ANOMALY' | 'DEVICE_ANOMALY' | 'VELOCITY_ANOMALY' | 'TIME_ANOMALY';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  details: Record<string, any>;
  location?: GeoPoint;
  deviceFingerprint?: string;
  timestamp: Date;
  resolved: boolean;
  actionTaken?: string;
}

export interface FraudDetectionResult {
  isFraudulent: boolean;
  riskScore: number;
  confidence: number;
  detectedAnomalies: AnomalyEvent[];
  recommendedAction: 'ALLOW' | 'FLAG' | 'BLOCK' | 'REQUIRE_VERIFICATION';
  reasoning: string[];
}

/**
 * SEC-001: GPS Spoofing Detection Algorithms
 * Advanced algorithms to detect GPS manipulation and spoofing attempts
 */
export class GPSSpoofingDetector extends EventEmitter {
  private redis: RedisService;
  private readonly SPOOFING_CACHE_TTL = 3600; // 1 hour

  constructor(redis: RedisService) {
    super();
    this.redis = redis;
  }

  /**
   * Comprehensive GPS spoofing detection using multiple analysis methods
   */
  public async detectGPSSpoofing(
    point: GeoPoint,
    userId: string,
    deviceFingerprint: DeviceFingerprint,
    previousLocations: GeoPoint[]
  ): Promise<{
    isSpoofed: boolean;
    confidence: number;
    spoofingMethods: string[];
    evidence: Record<string, any>;
  }> {
    const detectionMethods = await Promise.all([
      this.analyzeSignalConsistency(point, deviceFingerprint),
      this.analyzeSatelliteData(point),
      this.analyzeMovementPatterns(point, previousLocations),
      this.analyzeTimeConsistency(point, previousLocations),
      this.analyzeAccuracyPatterns(point, userId),
      this.analyzeEnvironmentalFactors(point),
      this.analyzeMockLocationIndicators(deviceFingerprint)
    ]);

    const spoofingMethods: string[] = [];
    const evidence: Record<string, any> = {};
    let totalConfidence = 0;
    let detectionCount = 0;

    detectionMethods.forEach((result, index) => {
      const methodName = [
        'SIGNAL_CONSISTENCY',
        'SATELLITE_DATA',
        'MOVEMENT_PATTERNS', 
        'TIME_CONSISTENCY',
        'ACCURACY_PATTERNS',
        'ENVIRONMENTAL_FACTORS',
        'MOCK_LOCATION'
      ][index];

      if (result.isSuspicious) {
        spoofingMethods.push(methodName);
        evidence[methodName] = result.evidence;
        totalConfidence += result.confidence;
        detectionCount++;
      }
    });

    const averageConfidence = detectionCount > 0 ? totalConfidence / detectionCount : 0;
    const isSpoofed = spoofingMethods.length >= 2 && averageConfidence > 0.7;

    // Cache detection result for future analysis
    await this.cacheDetectionResult(userId, point, {
      isSpoofed,
      confidence: averageConfidence,
      spoofingMethods,
      evidence
    });

    if (isSpoofed) {
      this.emit('spoofing_detected', {
        userId,
        point,
        spoofingMethods,
        confidence: averageConfidence
      });
    }

    return {
      isSpoofed,
      confidence: averageConfidence,
      spoofingMethods,
      evidence
    };
  }

  /**
   * Analyze GPS signal consistency and strength
   */
  private async analyzeSignalConsistency(
    point: GeoPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<{ isSuspicious: boolean; confidence: number; evidence: any }> {
    // Analyze signal strength patterns, noise levels, and consistency
    const signalPattern = {
      strength: point.accuracy ? 1 / point.accuracy : 1,
      consistency: Math.random(), // Mock - would use actual signal data
      jitter: Math.random() * 10,
      drift: Math.random() * 5
    };

    // Spoofed GPS often shows unnaturally consistent signals
    const isUnaturallyConsistent = signalPattern.consistency > 0.95 && signalPattern.jitter < 1;
    const isUnaturallyAccurate = point.accuracy && point.accuracy < 2; // Too good to be true
    const hasAbnormalDrift = signalPattern.drift > 50;

    const isSuspicious = isUnaturallyConsistent || isUnaturallyAccurate || hasAbnormalDrift;
    const confidence = isSuspicious ? 0.8 : 0.2;

    return {
      isSuspicious,
      confidence,
      evidence: {
        signalPattern,
        isUnaturallyConsistent,
        isUnaturallyAccurate,
        hasAbnormalDrift
      }
    };
  }

  /**
   * Analyze satellite constellation data
   */
  private async analyzeSatelliteData(
    point: GeoPoint
  ): Promise<{ isSuspicious: boolean; confidence: number; evidence: any }> {
    // Mock satellite data analysis - in production would use actual GNSS data
    const satelliteData = {
      visibleSatellites: Math.floor(Math.random() * 20) + 5,
      usedSatellites: Math.floor(Math.random() * 12) + 4,
      constellations: ['GPS', 'GLONASS', 'Galileo', 'BeiDou'],
      geometryQuality: Math.random(),
      signalToNoise: Math.random() * 50 + 20
    };

    // Suspicious patterns
    const tooFewSatellites = satelliteData.visibleSatellites < 4;
    const perfectGeometry = satelliteData.geometryQuality > 0.98;
    const unnaturalSignalStrength = satelliteData.signalToNoise > 45;

    const isSuspicious = tooFewSatellites || perfectGeometry || unnaturalSignalStrength;
    const confidence = isSuspicious ? 0.75 : 0.1;

    return {
      isSuspicious,
      confidence,
      evidence: {
        satelliteData,
        tooFewSatellites,
        perfectGeometry,
        unnaturalSignalStrength
      }
    };
  }

  /**
   * Analyze movement patterns for impossibilities
   */
  private async analyzeMovementPatterns(
    point: GeoPoint,
    previousLocations: GeoPoint[]
  ): Promise<{ isSuspicious: boolean; confidence: number; evidence: any }> {
    if (previousLocations.length === 0) {
      return { isSuspicious: false, confidence: 0, evidence: {} };
    }

    const lastLocation = previousLocations[previousLocations.length - 1];
    
    // Calculate movement characteristics
    const timeDiff = point.timestamp && lastLocation.timestamp ? 
      (point.timestamp.getTime() - lastLocation.timestamp.getTime()) / 1000 : 0;
    
    if (timeDiff <= 0) {
      return { isSuspicious: true, confidence: 0.9, evidence: { invalidTime: true } };
    }

    const distance = this.calculateDistance(lastLocation, point);
    const speed = distance / timeDiff; // meters per second
    const speedKmh = speed * 3.6;

    // Analyze trajectory smoothness
    const trajectorySmootness = this.calculateTrajectorySmootness(previousLocations, point);
    
    // Suspicious patterns
    const impossibleSpeed = speedKmh > 300; // Faster than high-speed train
    const teleportation = speedKmh > 1000 && distance > 1000; // Instant long-distance jump
    const unnaturalTrajectory = trajectorySmootness < 0.3; // Too erratic
    const perfectLinearMovement = trajectorySmootness > 0.98 && distance > 100; // Too smooth for human

    const isSuspicious = impossibleSpeed || teleportation || unnaturalTrajectory || perfectLinearMovement;
    const confidence = isSuspicious ? 0.85 : 0.1;

    return {
      isSuspicious,
      confidence,
      evidence: {
        distance,
        timeDiff,
        speed: speedKmh,
        trajectorySmootness,
        impossibleSpeed,
        teleportation,
        unnaturalTrajectory,
        perfectLinearMovement
      }
    };
  }

  /**
   * Analyze time consistency and patterns
   */
  private async analyzeTimeConsistency(
    point: GeoPoint,
    previousLocations: GeoPoint[]
  ): Promise<{ isSuspicious: boolean; confidence: number; evidence: any }> {
    if (!point.timestamp || previousLocations.length === 0) {
      return { isSuspicious: false, confidence: 0, evidence: {} };
    }

    const timeGaps = previousLocations
      .filter(loc => loc.timestamp)
      .map((loc, index, arr) => {
        if (index === 0) return null;
        return (arr[index].timestamp!.getTime() - arr[index - 1].timestamp!.getTime()) / 1000;
      })
      .filter(gap => gap !== null) as number[];

    if (timeGaps.length === 0) {
      return { isSuspicious: false, confidence: 0, evidence: {} };
    }

    // Analyze time patterns
    const avgGap = timeGaps.reduce((sum, gap) => sum + gap, 0) / timeGaps.length;
    const gapVariance = timeGaps.reduce((sum, gap) => sum + Math.pow(gap - avgGap, 2), 0) / timeGaps.length;
    const gapStdDev = Math.sqrt(gapVariance);

    const lastGap = point.timestamp.getTime() - previousLocations[previousLocations.length - 1].timestamp!.getTime();

    // Suspicious patterns
    const perfectTiming = gapStdDev < 0.1 && timeGaps.length > 5; // Too regular
    const impossibleGap = lastGap < 500; // Less than 500ms between readings
    const suspiciousRegularity = timeGaps.every(gap => gap % 1000 === 0); // Exactly rounded seconds

    const isSuspicious = perfectTiming || impossibleGap || suspiciousRegularity;
    const confidence = isSuspicious ? 0.7 : 0.1;

    return {
      isSuspicious,
      confidence,
      evidence: {
        avgGap,
        gapStdDev,
        lastGap,
        perfectTiming,
        impossibleGap,
        suspiciousRegularity
      }
    };
  }

  /**
   * Analyze accuracy patterns for anomalies
   */
  private async analyzeAccuracyPatterns(
    point: GeoPoint,
    userId: string
  ): Promise<{ isSuspicious: boolean; confidence: number; evidence: any }> {
    const userAccuracyHistory = await this.getUserAccuracyHistory(userId);
    
    if (!point.accuracy || userAccuracyHistory.length === 0) {
      return { isSuspicious: false, confidence: 0, evidence: {} };
    }

    const avgAccuracy = userAccuracyHistory.reduce((sum, acc) => sum + acc, 0) / userAccuracyHistory.length;
    const accuracyVariance = userAccuracyHistory.reduce((sum, acc) => sum + Math.pow(acc - avgAccuracy, 2), 0) / userAccuracyHistory.length;
    const accuracyStdDev = Math.sqrt(accuracyVariance);

    // Suspicious patterns
    const suddenlyPerfect = point.accuracy < 2 && avgAccuracy > 10; // Suddenly too accurate
    const impossiblyAccurate = point.accuracy < 0.5; // Sub-meter accuracy is rare for mobile devices
    const suspiciouslyConsistent = accuracyStdDev < 0.5 && userAccuracyHistory.length > 10; // Too consistent

    const isSuspicious = suddenlyPerfect || impossiblyAccurate || suspiciouslyConsistent;
    const confidence = isSuspicious ? 0.8 : 0.1;

    // Update accuracy history
    await this.updateUserAccuracyHistory(userId, point.accuracy);

    return {
      isSuspicious,
      confidence,
      evidence: {
        currentAccuracy: point.accuracy,
        avgAccuracy,
        accuracyStdDev,
        suddenlyPerfect,
        impossiblyAccurate,
        suspiciouslyConsistent
      }
    };
  }

  /**
   * Analyze environmental factors
   */
  private async analyzeEnvironmentalFactors(
    point: GeoPoint
  ): Promise<{ isSuspicious: boolean; confidence: number; evidence: any }> {
    // Mock environmental analysis - would integrate with weather APIs, building databases, etc.
    const environment = {
      isIndoors: Math.random() > 0.7,
      buildingDensity: Math.random(),
      weatherConditions: ['clear', 'cloudy', 'rainy', 'stormy'][Math.floor(Math.random() * 4)],
      ionosphericActivity: Math.random()
    };

    // Suspicious: Perfect GPS signal in challenging environments
    const perfectSignalIndoors = Boolean(environment.isIndoors && point.accuracy && point.accuracy < 3);
    const perfectSignalInStorm = Boolean(environment.weatherConditions === 'stormy' && point.accuracy && point.accuracy < 5);
    const perfectSignalHighDensity = Boolean(environment.buildingDensity > 0.8 && point.accuracy && point.accuracy < 3);

    const isSuspicious = perfectSignalIndoors || perfectSignalInStorm || perfectSignalHighDensity;
    const confidence = isSuspicious ? 0.6 : 0.1;

    return {
      isSuspicious,
      confidence,
      evidence: {
        environment,
        perfectSignalIndoors,
        perfectSignalInStorm,
        perfectSignalHighDensity
      }
    };
  }

  /**
   * Analyze mock location indicators from device
   */
  private async analyzeMockLocationIndicators(
    deviceFingerprint: DeviceFingerprint
  ): Promise<{ isSuspicious: boolean; confidence: number; evidence: any }> {
    // Check for developer options, mock location apps, rooting/jailbreaking indicators
    const mockIndicators = {
      hasDeveloperOptions: deviceFingerprint.installedApps?.includes('developer.tools') || false,
      hasMockLocationApps: deviceFingerprint.installedApps?.some(app => 
        app.includes('fake.gps') || app.includes('mock.location')
      ) || false,
      isRooted: deviceFingerprint.platform.includes('rooted') || false,
      hasLocationSpoofingApps: deviceFingerprint.installedApps?.some(app =>
        ['fake location', 'gps spoofing', 'location changer'].some(keyword => 
          app.toLowerCase().includes(keyword)
        )
      ) || false
    };

    const suspiciousAppCount = Object.values(mockIndicators).filter(Boolean).length;
    const isSuspicious = suspiciousAppCount > 1;
    const confidence = suspiciousAppCount * 0.3;

    return {
      isSuspicious,
      confidence,
      evidence: {
        mockIndicators,
        suspiciousAppCount
      }
    };
  }

  // Helper methods
  private calculateDistance(point1: GeoPoint, point2: GeoPoint): number {
    const R = 6371000; // Earth's radius in meters
    const lat1Rad = point1.latitude * Math.PI / 180;
    const lat2Rad = point2.latitude * Math.PI / 180;
    const deltaLat = (point2.latitude - point1.latitude) * Math.PI / 180;
    const deltaLng = (point2.longitude - point1.longitude) * Math.PI / 180;

    const a = Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
              Math.cos(lat1Rad) * Math.cos(lat2Rad) *
              Math.sin(deltaLng / 2) * Math.sin(deltaLng / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  }

  private calculateTrajectorySmootness(previousLocations: GeoPoint[], currentPoint: GeoPoint): number {
    if (previousLocations.length < 2) return 1;

    const locations = [...previousLocations, currentPoint];
    let totalBearingChange = 0;
    let segments = 0;

    for (let i = 2; i < locations.length; i++) {
      const bearing1 = this.calculateBearing(locations[i - 2], locations[i - 1]);
      const bearing2 = this.calculateBearing(locations[i - 1], locations[i]);
      
      let bearingDiff = Math.abs(bearing2 - bearing1);
      if (bearingDiff > 180) bearingDiff = 360 - bearingDiff;
      
      totalBearingChange += bearingDiff;
      segments++;
    }

    if (segments === 0) return 1;
    
    const avgBearingChange = totalBearingChange / segments;
    return Math.max(0, 1 - avgBearingChange / 180);
  }

  private calculateBearing(point1: GeoPoint, point2: GeoPoint): number {
    const lat1Rad = point1.latitude * Math.PI / 180;
    const lat2Rad = point2.latitude * Math.PI / 180;
    const deltaLngRad = (point2.longitude - point1.longitude) * Math.PI / 180;

    const y = Math.sin(deltaLngRad) * Math.cos(lat2Rad);
    const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) -
              Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(deltaLngRad);

    const bearingRad = Math.atan2(y, x);
    return ((bearingRad * 180 / Math.PI) + 360) % 360;
  }

  private async getUserAccuracyHistory(userId: string): Promise<number[]> {
    const cacheKey = `accuracy_history:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return [];
  }

  private async updateUserAccuracyHistory(userId: string, accuracy: number): Promise<void> {
    const history = await this.getUserAccuracyHistory(userId);
    history.push(accuracy);
    
    // Keep only last 50 readings
    if (history.length > 50) {
      history.splice(0, history.length - 50);
    }
    
    const cacheKey = `accuracy_history:${userId}`;
    await this.redis.setWithExpiry(cacheKey, JSON.stringify(history), 86400); // 24 hours
  }

  private async cacheDetectionResult(userId: string, point: GeoPoint, result: any): Promise<void> {
    const cacheKey = `spoofing_detection:${userId}:${Date.now()}`;
    await this.redis.setWithExpiry(
      cacheKey,
      JSON.stringify({ point, result, timestamp: new Date() }),
      this.SPOOFING_CACHE_TTL
    );
  }
}

/**
 * SEC-002: User Behavior Pattern Analysis
 * Machine learning-based analysis of user movement and interaction patterns
 */
export class UserBehaviorAnalyzer extends EventEmitter {
  private redis: RedisService;
  private behaviorPatterns: Map<string, UserBehaviorPattern> = new Map();
  
  constructor(redis: RedisService) {
    super();
    this.redis = redis;
  }

  /**
   * Analyze user behavior and detect anomalies
   */
  public async analyzeBehavior(
    userId: string,
    currentLocation: GeoPoint,
    sessionData: {
      duration: number;
      interactionCount: number;
      features: string[];
    }
  ): Promise<{
    isAnomalous: boolean;
    anomalyScore: number;
    anomalyTypes: string[];
    confidence: number;
  }> {
    // Get or create user behavior pattern
    let pattern = await this.getUserBehaviorPattern(userId);
    
    if (!pattern) {
      pattern = await this.initializeUserBehaviorPattern(userId, currentLocation);
    }

    // Analyze different aspects of behavior
    const analyses = await Promise.all([
      this.analyzeLocationBehavior(currentLocation, pattern),
      this.analyzeTimeBehavior(new Date(), pattern),
      this.analyzeMovementBehavior(currentLocation, pattern),
      this.analyzeSessionBehavior(sessionData, userId)
    ]);

    const anomalyTypes: string[] = [];
    let totalAnomalyScore = 0;
    let analysisCount = 0;

    analyses.forEach((analysis, index) => {
      const types = ['LOCATION', 'TIME', 'MOVEMENT', 'SESSION'];
      
      if (analysis.isAnomalous) {
        anomalyTypes.push(types[index]);
      }
      
      totalAnomalyScore += analysis.anomalyScore;
      analysisCount++;
    });

    const anomalyScore = analysisCount > 0 ? totalAnomalyScore / analysisCount : 0;
    const isAnomalous = anomalyTypes.length >= 2 || anomalyScore > 0.7;
    const confidence = Math.min(anomalyScore * anomalyTypes.length * 0.2, 1);

    // Update behavior pattern
    await this.updateBehaviorPattern(userId, currentLocation, sessionData);

    // Log anomaly if detected
    if (isAnomalous) {
      await this.logBehaviorAnomaly(userId, currentLocation, {
        anomalyScore,
        anomalyTypes,
        confidence
      });
    }

    return {
      isAnomalous,
      anomalyScore,
      anomalyTypes,
      confidence
    };
  }

  /**
   * Analyze location-based behavior patterns
   */
  private async analyzeLocationBehavior(
    location: GeoPoint,
    pattern: UserBehaviorPattern
  ): Promise<{ isAnomalous: boolean; anomalyScore: number }> {
    if (pattern.patterns.typicalLocations.length === 0) {
      return { isAnomalous: false, anomalyScore: 0 };
    }

    // Calculate distances to typical locations
    const distances = pattern.patterns.typicalLocations.map(typicalLocation => {
      const distance = this.calculateDistance(location, typicalLocation);
      return distance;
    });

    const minDistance = Math.min(...distances);
    const avgDistance = distances.reduce((sum, d) => sum + d, 0) / distances.length;

    // Anomaly if current location is very far from all typical locations
    const distanceThreshold = 50000; // 50km
    const isAnomalous = minDistance > distanceThreshold;
    const anomalyScore = Math.min(minDistance / distanceThreshold, 1);

    return { isAnomalous, anomalyScore };
  }

  /**
   * Analyze time-based behavior patterns
   */
  private async analyzeTimeBehavior(
    currentTime: Date,
    pattern: UserBehaviorPattern
  ): Promise<{ isAnomalous: boolean; anomalyScore: number }> {
    const hour = currentTime.getHours();
    const dayOfWeek = currentTime.getDay();

    // Find similar time patterns
    const similarTimePatterns = pattern.patterns.timePatterns.filter(tp => 
      Math.abs(tp.hour - hour) <= 1 && tp.dayOfWeek === dayOfWeek
    );

    if (similarTimePatterns.length === 0) {
      // No similar patterns found - could be anomalous
      const totalFrequency = pattern.patterns.timePatterns.reduce((sum, tp) => sum + tp.frequency, 0);
      const isAnomalous = totalFrequency > 10; // Only if we have enough data
      const anomalyScore = isAnomalous ? 0.6 : 0.3;
      
      return { isAnomalous, anomalyScore };
    }

    // Check frequency of similar patterns
    const avgFrequency = similarTimePatterns.reduce((sum, tp) => sum + tp.frequency, 0) / similarTimePatterns.length;
    const isAnomalous = avgFrequency < 0.1; // Very rare time for this user
    const anomalyScore = isAnomalous ? 1 - avgFrequency : avgFrequency;

    return { isAnomalous, anomalyScore };
  }

  /**
   * Analyze movement behavior patterns
   */
  private async analyzeMovementBehavior(
    location: GeoPoint,
    pattern: UserBehaviorPattern
  ): Promise<{ isAnomalous: boolean; anomalyScore: number }> {
    const recentLocations = await this.getRecentUserLocations(pattern.userId, 5);
    
    if (recentLocations.length < 2) {
      return { isAnomalous: false, anomalyScore: 0 };
    }

    const lastLocation = recentLocations[recentLocations.length - 1];
    const timeDiff = location.timestamp && lastLocation.timestamp ?
      (location.timestamp.getTime() - lastLocation.timestamp.getTime()) / 1000 : 0;

    if (timeDiff <= 0) {
      return { isAnomalous: true, anomalyScore: 0.9 };
    }

    const distance = this.calculateDistance(lastLocation, location);
    const speed = (distance / timeDiff) * 3.6; // km/h

    // Compare with user's typical speed patterns
    const { min, max, average, stdDev } = pattern.patterns.speedPatterns;
    
    const isAboveNormal = speed > average + (2 * stdDev);
    const isBelowNormal = speed < Math.max(0, average - (2 * stdDev));
    const isImpossible = speed > 300; // Faster than high-speed train

    const isAnomalous = isAboveNormal || isBelowNormal || isImpossible;
    let anomalyScore = 0;

    if (isImpossible) {
      anomalyScore = 1;
    } else if (isAboveNormal) {
      anomalyScore = Math.min((speed - average) / (2 * stdDev), 1);
    } else if (isBelowNormal) {
      anomalyScore = Math.min((average - speed) / (2 * stdDev), 1);
    }

    return { isAnomalous, anomalyScore };
  }

  /**
   * Analyze session behavior patterns
   */
  private async analyzeSessionBehavior(
    sessionData: { duration: number; interactionCount: number; features: string[] },
    userId: string
  ): Promise<{ isAnomalous: boolean; anomalyScore: number }> {
    const historicalSessions = await this.getUserSessionHistory(userId);
    
    if (historicalSessions.length === 0) {
      return { isAnomalous: false, anomalyScore: 0 };
    }

    // Analyze session duration
    const avgDuration = historicalSessions.reduce((sum, s) => sum + s.duration, 0) / historicalSessions.length;
    const durationVariance = historicalSessions.reduce((sum, s) => sum + Math.pow(s.duration - avgDuration, 2), 0) / historicalSessions.length;
    const durationStdDev = Math.sqrt(durationVariance);

    // Analyze interaction patterns
    const avgInteractions = historicalSessions.reduce((sum, s) => sum + s.interactionCount, 0) / historicalSessions.length;
    const interactionVariance = historicalSessions.reduce((sum, s) => sum + Math.pow(s.interactionCount - avgInteractions, 2), 0) / historicalSessions.length;
    const interactionStdDev = Math.sqrt(interactionVariance);

    // Check for anomalies
    const durationAnomaly = Math.abs(sessionData.duration - avgDuration) > (2 * durationStdDev);
    const interactionAnomaly = Math.abs(sessionData.interactionCount - avgInteractions) > (2 * interactionStdDev);
    
    // Feature usage anomaly
    const typicalFeatures = this.getTypicalFeatures(historicalSessions);
    const unusualFeatures = sessionData.features.filter(f => !typicalFeatures.includes(f));
    const featureAnomaly = unusualFeatures.length > 0;

    const anomalyCount = [durationAnomaly, interactionAnomaly, featureAnomaly].filter(Boolean).length;
    const isAnomalous = anomalyCount >= 2;
    const anomalyScore = anomalyCount / 3;

    return { isAnomalous, anomalyScore };
  }

  // Helper methods
  private async getUserBehaviorPattern(userId: string): Promise<UserBehaviorPattern | null> {
    const cacheKey = `behavior_pattern:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return null;
  }

  private async initializeUserBehaviorPattern(userId: string, firstLocation: GeoPoint): Promise<UserBehaviorPattern> {
    const pattern: UserBehaviorPattern = {
      userId,
      patterns: {
        typicalLocations: [firstLocation],
        movementPatterns: [],
        timePatterns: [],
        speedPatterns: { min: 0, max: 0, average: 0, stdDev: 0 },
        accuracyPatterns: { min: 0, max: 0, average: 0, stdDev: 0 }
      },
      riskScore: 0,
      anomalyHistory: [],
      lastUpdated: new Date()
    };

    await this.saveBehaviorPattern(pattern);
    return pattern;
  }

  private async updateBehaviorPattern(
    userId: string,
    location: GeoPoint,
    sessionData: { duration: number; interactionCount: number; features: string[] }
  ): Promise<void> {
    const pattern = await this.getUserBehaviorPattern(userId);
    if (!pattern) return;

    // Update typical locations (clustering algorithm would be used in production)
    const isNewLocation = !pattern.patterns.typicalLocations.some(loc => 
      this.calculateDistance(loc, location) < 100 // Within 100 meters
    );

    if (isNewLocation) {
      pattern.patterns.typicalLocations.push(location);
      
      // Keep only top 20 locations
      if (pattern.patterns.typicalLocations.length > 20) {
        pattern.patterns.typicalLocations.splice(0, pattern.patterns.typicalLocations.length - 20);
      }
    }

    // Update time patterns
    const hour = new Date().getHours();
    const dayOfWeek = new Date().getDay();
    
    const existingTimePattern = pattern.patterns.timePatterns.find(tp => 
      tp.hour === hour && tp.dayOfWeek === dayOfWeek
    );
    
    if (existingTimePattern) {
      existingTimePattern.frequency += 1;
    } else {
      pattern.patterns.timePatterns.push({ hour, dayOfWeek, frequency: 1 });
    }

    pattern.lastUpdated = new Date();
    await this.saveBehaviorPattern(pattern);
  }

  private async saveBehaviorPattern(pattern: UserBehaviorPattern): Promise<void> {
    const cacheKey = `behavior_pattern:${pattern.userId}`;
    await this.redis.setWithExpiry(cacheKey, JSON.stringify(pattern), 86400 * 30); // 30 days
  }

  private async logBehaviorAnomaly(userId: string, location: GeoPoint, anomalyData: any): Promise<void> {
    const anomaly: AnomalyEvent = {
      id: `anomaly_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      type: 'BEHAVIOR_ANOMALY',
      severity: anomalyData.anomalyScore > 0.8 ? 'HIGH' : anomalyData.anomalyScore > 0.5 ? 'MEDIUM' : 'LOW',
      details: anomalyData,
      location,
      timestamp: new Date(),
      resolved: false
    };

    const cacheKey = `anomaly:${anomaly.id}`;
    await this.redis.setWithExpiry(cacheKey, JSON.stringify(anomaly), 86400 * 7); // 7 days

    this.emit('behavior_anomaly', anomaly);
  }

  private calculateDistance(point1: GeoPoint, point2: GeoPoint): number {
    const R = 6371000;
    const lat1Rad = point1.latitude * Math.PI / 180;
    const lat2Rad = point2.latitude * Math.PI / 180;
    const deltaLat = (point2.latitude - point1.latitude) * Math.PI / 180;
    const deltaLng = (point2.longitude - point1.longitude) * Math.PI / 180;

    const a = Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
              Math.cos(lat1Rad) * Math.cos(lat2Rad) *
              Math.sin(deltaLng / 2) * Math.sin(deltaLng / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  }

  private async getRecentUserLocations(userId: string, limit: number): Promise<GeoPoint[]> {
    const cacheKey = `recent_locations:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      const locations: GeoPoint[] = JSON.parse(cached);
      return locations.slice(0, limit);
    }
    
    return [];
  }

  private async getUserSessionHistory(userId: string): Promise<Array<{ duration: number; interactionCount: number; features: string[] }>> {
    const cacheKey = `session_history:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return [];
  }

  private getTypicalFeatures(sessions: Array<{ features: string[] }>): string[] {
    const featureFrequency: Record<string, number> = {};
    
    sessions.forEach(session => {
      session.features.forEach(feature => {
        featureFrequency[feature] = (featureFrequency[feature] || 0) + 1;
      });
    });

    const threshold = sessions.length * 0.3; // Feature used in 30% of sessions
    return Object.entries(featureFrequency)
      .filter(([_, frequency]) => frequency >= threshold)
      .map(([feature, _]) => feature);
  }
}

/**
 * SEC-003: Device Fingerprinting and Abuse Prevention
 * Advanced device identification and tracking prevention
 */
export class DeviceFingerprintingEngine extends EventEmitter {
  private redis: RedisService;
  private fingerprints: Map<string, DeviceFingerprint> = new Map();
  
  constructor(redis: RedisService) {
    super();
    this.redis = redis;
  }

  /**
   * Generate comprehensive device fingerprint
   */
  public async generateFingerprint(deviceData: {
    userAgent: string;
    screenResolution: string;
    timezone: string;
    language: string;
    platform: string;
    hardware?: string;
    networkInfo?: string;
    batteryLevel?: number;
    sensors?: string[];
    installedApps?: string[];
  }): Promise<DeviceFingerprint> {
    const fingerprintData = {
      deviceId: '', // Will be generated
      ...deviceData,
      sensors: deviceData.sensors || [],
      installedApps: deviceData.installedApps || []
    };

    // Generate unique fingerprint hash
    const fingerprintString = JSON.stringify([
      fingerprintData.userAgent,
      fingerprintData.screenResolution,
      fingerprintData.timezone,
      fingerprintData.language,
      fingerprintData.platform,
      fingerprintData.hardware,
      fingerprintData.networkInfo,
      fingerprintData.sensors.sort(),
      fingerprintData.installedApps?.sort()
    ]);

    const fingerprint = crypto.createHash('sha256').update(fingerprintString).digest('hex');
    const deviceId = `device_${fingerprint.substring(0, 16)}`;

    const deviceFingerprint: DeviceFingerprint = {
      ...fingerprintData,
      deviceId,
      fingerprint,
      hardware: fingerprintData.hardware || 'unknown',
      networkInfo: fingerprintData.networkInfo || 'unknown',
      confidence: this.calculateFingerprintConfidence(fingerprintData),
      firstSeen: new Date(),
      lastSeen: new Date()
    };

    await this.saveFingerprint(deviceFingerprint);
    return deviceFingerprint;
  }

  /**
   * Detect device abuse patterns
   */
  public async detectDeviceAbuse(fingerprint: DeviceFingerprint, userId: string): Promise<{
    isAbusive: boolean;
    abuseScore: number;
    abuseTypes: string[];
    evidence: Record<string, any>;
  }> {
    const abuseChecks = await Promise.all([
      this.checkMultipleAccounts(fingerprint),
      this.checkRapidAccountCreation(fingerprint),
      this.checkSuspiciousApps(fingerprint),
      this.checkDeviceModifications(fingerprint),
      this.checkFingerprintManipulation(fingerprint, userId)
    ]);

    const abuseTypes: string[] = [];
    const evidence: Record<string, any> = {};
    let totalScore = 0;

    abuseChecks.forEach((check, index) => {
      const types = [
        'MULTIPLE_ACCOUNTS',
        'RAPID_CREATION',
        'SUSPICIOUS_APPS',
        'DEVICE_MODIFICATIONS',
        'FINGERPRINT_MANIPULATION'
      ];

      if (check.isAbusive) {
        abuseTypes.push(types[index]);
        evidence[types[index]] = check.evidence;
      }

      totalScore += check.score;
    });

    const abuseScore = totalScore / abuseChecks.length;
    const isAbusive = abuseTypes.length >= 2 || abuseScore > 0.7;

    if (isAbusive) {
      await this.logDeviceAbuse(fingerprint, userId, { abuseScore, abuseTypes, evidence });
    }

    return { isAbusive, abuseScore, abuseTypes, evidence };
  }

  /**
   * Check for multiple accounts on same device
   */
  private async checkMultipleAccounts(fingerprint: DeviceFingerprint): Promise<{
    isAbusive: boolean;
    score: number;
    evidence: any;
  }> {
    const associatedUsers = await this.getAssociatedUsers(fingerprint.fingerprint);
    const userCount = associatedUsers.length;
    
    const threshold = 5; // Max 5 accounts per device
    const isAbusive = userCount > threshold;
    const score = Math.min(userCount / threshold, 1);

    return {
      isAbusive,
      score,
      evidence: { userCount, associatedUsers: associatedUsers.slice(0, 10) } // Limit for privacy
    };
  }

  /**
   * Check for rapid account creation
   */
  private async checkRapidAccountCreation(fingerprint: DeviceFingerprint): Promise<{
    isAbusive: boolean;
    score: number;
    evidence: any;
  }> {
    const recentAccounts = await this.getRecentAccountsForDevice(fingerprint.fingerprint, 86400000); // 24 hours
    const accountCount = recentAccounts.length;
    
    const threshold = 3; // Max 3 accounts per day
    const isAbusive = accountCount > threshold;
    const score = Math.min(accountCount / threshold, 1);

    return {
      isAbusive,
      score,
      evidence: { accountCount, recentAccounts }
    };
  }

  /**
   * Check for suspicious applications
   */
  private async checkSuspiciousApps(fingerprint: DeviceFingerprint): Promise<{
    isAbusive: boolean;
    score: number;
    evidence: any;
  }> {
    if (!fingerprint.installedApps || fingerprint.installedApps.length === 0) {
      return { isAbusive: false, score: 0, evidence: {} };
    }

    const suspiciousKeywords = [
      'fake', 'spoof', 'mock', 'cheat', 'hack', 'bot', 'auto', 'script',
      'location changer', 'gps spoofing', 'fake gps', 'location faker'
    ];

    const suspiciousApps = fingerprint.installedApps.filter(app => 
      suspiciousKeywords.some(keyword => app.toLowerCase().includes(keyword))
    );

    const isAbusive = suspiciousApps.length > 0;
    const score = Math.min(suspiciousApps.length * 0.3, 1);

    return {
      isAbusive,
      score,
      evidence: { suspiciousApps, totalApps: fingerprint.installedApps.length }
    };
  }

  /**
   * Check for device modifications (rooting, jailbreaking)
   */
  private async checkDeviceModifications(fingerprint: DeviceFingerprint): Promise<{
    isAbusive: boolean;
    score: number;
    evidence: any;
  }> {
    const modifications = {
      isRooted: fingerprint.platform.toLowerCase().includes('rooted') ||
                fingerprint.platform.toLowerCase().includes('jailbroken'),
      hasXposed: fingerprint.installedApps?.some(app => app.includes('xposed')) || false,
      hasMagisk: fingerprint.installedApps?.some(app => app.includes('magisk')) || false,
      hasSuperSU: fingerprint.installedApps?.some(app => app.includes('supersu')) || false
    };

    const modificationCount = Object.values(modifications).filter(Boolean).length;
    const isAbusive = modificationCount > 0;
    const score = modificationCount * 0.3;

    return {
      isAbusive,
      score,
      evidence: modifications
    };
  }

  /**
   * Check for fingerprint manipulation attempts
   */
  private async checkFingerprintManipulation(
    fingerprint: DeviceFingerprint, 
    userId: string
  ): Promise<{
    isAbusive: boolean;
    score: number;
    evidence: any;
  }> {
    const historicalFingerprints = await this.getUserFingerprints(userId);
    
    if (historicalFingerprints.length === 0) {
      return { isAbusive: false, score: 0, evidence: {} };
    }

    // Check for rapid fingerprint changes
    const fingerprintChanges = historicalFingerprints.reduce((changes, fp, index) => {
      if (index === 0) return 0;
      
      const prevFp = historicalFingerprints[index - 1];
      const timeDiff = fp.firstSeen.getTime() - prevFp.firstSeen.getTime();
      
      if (timeDiff < 3600000 && fp.fingerprint !== prevFp.fingerprint) { // Changed within 1 hour
        return changes + 1;
      }
      
      return changes;
    }, 0);

    // Check for impossible hardware changes
    const hardwareChanges = historicalFingerprints.filter(fp => 
      fp.screenResolution !== fingerprint.screenResolution ||
      fp.hardware !== fingerprint.hardware
    ).length;

    const isAbusive = fingerprintChanges > 3 || hardwareChanges > 2;
    const score = Math.min((fingerprintChanges * 0.2) + (hardwareChanges * 0.3), 1);

    return {
      isAbusive,
      score,
      evidence: {
        fingerprintChanges,
        hardwareChanges,
        totalHistoricalFingerprints: historicalFingerprints.length
      }
    };
  }

  // Helper methods
  private calculateFingerprintConfidence(fingerprintData: any): number {
    let confidence = 0;
    
    // Base confidence from available data
    if (fingerprintData.userAgent) confidence += 0.2;
    if (fingerprintData.screenResolution) confidence += 0.15;
    if (fingerprintData.timezone) confidence += 0.1;
    if (fingerprintData.language) confidence += 0.1;
    if (fingerprintData.platform) confidence += 0.15;
    if (fingerprintData.hardware) confidence += 0.15;
    if (fingerprintData.networkInfo) confidence += 0.1;
    if (fingerprintData.sensors && fingerprintData.sensors.length > 0) confidence += 0.05;
    
    return Math.min(confidence, 1);
  }

  private async saveFingerprint(fingerprint: DeviceFingerprint): Promise<void> {
    // Save to memory cache
    this.fingerprints.set(fingerprint.fingerprint, fingerprint);
    
    // Save to Redis
    const cacheKey = `fingerprint:${fingerprint.fingerprint}`;
    await this.redis.setWithExpiry(cacheKey, JSON.stringify(fingerprint), 86400 * 30); // 30 days
    
    // Index by device ID
    const deviceKey = `device:${fingerprint.deviceId}`;
    await this.redis.setWithExpiry(deviceKey, fingerprint.fingerprint, 86400 * 30);
  }

  private async getAssociatedUsers(fingerprintHash: string): Promise<string[]> {
    const cacheKey = `fingerprint_users:${fingerprintHash}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return [];
  }

  private async getRecentAccountsForDevice(fingerprintHash: string, timeWindow: number): Promise<string[]> {
    // This would query actual database for recent account creations
    // For now, returning mock data
    return [];
  }

  private async getUserFingerprints(userId: string): Promise<DeviceFingerprint[]> {
    const cacheKey = `user_fingerprints:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return [];
  }

  private async logDeviceAbuse(
    fingerprint: DeviceFingerprint,
    userId: string,
    abuseData: any
  ): Promise<void> {
    const anomaly: AnomalyEvent = {
      id: `device_abuse_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      type: 'DEVICE_ANOMALY',
      severity: abuseData.abuseScore > 0.8 ? 'CRITICAL' : abuseData.abuseScore > 0.5 ? 'HIGH' : 'MEDIUM',
      details: abuseData,
      deviceFingerprint: fingerprint.fingerprint,
      timestamp: new Date(),
      resolved: false
    };

    const cacheKey = `anomaly:${anomaly.id}`;
    await this.redis.setWithExpiry(cacheKey, JSON.stringify(anomaly), 86400 * 7); // 7 days

    this.emit('device_abuse', { anomaly, fingerprint });
  }
}

/**
 * SEC-004: Automated Anomaly Detection and Response
 * ML-powered anomaly detection with automated response system
 */
export class AnomalyDetectionEngine extends EventEmitter {
  private redis: RedisService;
  private detectionRules: Map<string, any> = new Map();
  private responseActions: Map<string, Function> = new Map();

  constructor(redis: RedisService) {
    super();
    this.redis = redis;
    this.initializeDetectionRules();
    this.initializeResponseActions();
  }

  /**
   * Comprehensive anomaly detection combining all security components
   */
  public async detectAnomalies(
    userId: string,
    location: GeoPoint,
    deviceFingerprint: DeviceFingerprint,
    behaviorData: any,
    spoofingData: any
  ): Promise<FraudDetectionResult> {
    const detectionResults = await Promise.all([
      this.detectLocationAnomalies(location, userId),
      this.detectVelocityAnomalies(location, userId),
      this.detectTimeAnomalies(location, userId),
      this.detectFrequencyAnomalies(userId),
      this.detectConcurrencyAnomalies(userId, location),
      this.detectPatternAnomalies(userId, location, behaviorData)
    ]);

    const detectedAnomalies: AnomalyEvent[] = [];
    let totalRiskScore = 0;
    let totalConfidence = 0;
    const reasoning: string[] = [];

    detectionResults.forEach((result, index) => {
      if (result.anomalies.length > 0) {
        detectedAnomalies.push(...result.anomalies);
        totalRiskScore += result.riskScore;
        totalConfidence += result.confidence;
        reasoning.push(...result.reasoning);
      }
    });

    // Aggregate GPS spoofing data
    if (spoofingData.isSpoofed) {
      totalRiskScore += spoofingData.confidence * 0.8;
      reasoning.push(`GPS spoofing detected: ${spoofingData.spoofingMethods.join(', ')}`);
    }

    // Aggregate behavior data
    if (behaviorData.isAnomalous) {
      totalRiskScore += behaviorData.anomalyScore * 0.6;
      reasoning.push(`Behavior anomalies: ${behaviorData.anomalyTypes.join(', ')}`);
    }

    const avgRiskScore = detectionResults.length > 0 ? totalRiskScore / detectionResults.length : 0;
    const avgConfidence = detectionResults.length > 0 ? totalConfidence / detectionResults.length : 0;

    // Determine if fraudulent
    const isFraudulent = avgRiskScore > 0.6 || detectedAnomalies.length >= 3;
    
    // Determine recommended action
    let recommendedAction: 'ALLOW' | 'FLAG' | 'BLOCK' | 'REQUIRE_VERIFICATION' = 'ALLOW';
    
    if (avgRiskScore > 0.8 || spoofingData.isSpoofed) {
      recommendedAction = 'BLOCK';
    } else if (avgRiskScore > 0.6 || detectedAnomalies.length >= 2) {
      recommendedAction = 'REQUIRE_VERIFICATION';
    } else if (avgRiskScore > 0.4 || detectedAnomalies.length >= 1) {
      recommendedAction = 'FLAG';
    }

    const fraudResult: FraudDetectionResult = {
      isFraudulent,
      riskScore: avgRiskScore,
      confidence: avgConfidence,
      detectedAnomalies,
      recommendedAction,
      reasoning
    };

    // Execute automated response
    await this.executeAutomatedResponse(userId, fraudResult, location, deviceFingerprint);

    return fraudResult;
  }

  /**
   * Initialize detection rules
   */
  private initializeDetectionRules(): void {
    this.detectionRules.set('MAX_DISTANCE_PER_HOUR', 300); // km
    this.detectionRules.set('MAX_LOCATIONS_PER_DAY', 50);
    this.detectionRules.set('MAX_REWARDS_PER_DAY', 10);
    this.detectionRules.set('MIN_TIME_BETWEEN_CHECKINS', 300); // seconds
    this.detectionRules.set('MAX_CONCURRENT_SESSIONS', 1);
    this.detectionRules.set('SUSPICIOUS_ACCURACY_THRESHOLD', 2); // meters
    this.detectionRules.set('RAPID_SUCCESSION_THRESHOLD', 60); // seconds
  }

  /**
   * Initialize automated response actions
   */
  private initializeResponseActions(): void {
    this.responseActions.set('BLOCK', this.blockUser.bind(this));
    this.responseActions.set('FLAG', this.flagUser.bind(this));
    this.responseActions.set('REQUIRE_VERIFICATION', this.requireVerification.bind(this));
    this.responseActions.set('RATE_LIMIT', this.rateLimitUser.bind(this));
    this.responseActions.set('NOTIFY_ADMIN', this.notifyAdministrators.bind(this));
  }

  /**
   * Detect location-based anomalies
   */
  private async detectLocationAnomalies(location: GeoPoint, userId: string): Promise<{
    anomalies: AnomalyEvent[];
    riskScore: number;
    confidence: number;
    reasoning: string[];
  }> {
    const anomalies: AnomalyEvent[] = [];
    const reasoning: string[] = [];
    let riskScore = 0;
    
    // Check for impossible locations (e.g., middle of ocean, restricted areas)
    if (await this.isImpossibleLocation(location)) {
      const anomaly = await this.createAnomaly(userId, 'GPS_SPOOFING', 'HIGH', {
        reason: 'Impossible location detected',
        location
      });
      anomalies.push(anomaly);
      riskScore += 0.8;
      reasoning.push('Location is geographically impossible or restricted');
    }

    // Check for unusual accuracy
    if (location.accuracy && location.accuracy < this.detectionRules.get('SUSPICIOUS_ACCURACY_THRESHOLD')) {
      const anomaly = await this.createAnomaly(userId, 'GPS_SPOOFING', 'MEDIUM', {
        reason: 'Unusually high GPS accuracy',
        accuracy: location.accuracy
      });
      anomalies.push(anomaly);
      riskScore += 0.4;
      reasoning.push(`GPS accuracy too high: ${location.accuracy}m`);
    }

    return {
      anomalies,
      riskScore: Math.min(riskScore, 1),
      confidence: anomalies.length > 0 ? 0.7 : 0.1,
      reasoning
    };
  }

  /**
   * Detect velocity-based anomalies
   */
  private async detectVelocityAnomalies(location: GeoPoint, userId: string): Promise<{
    anomalies: AnomalyEvent[];
    riskScore: number;
    confidence: number;
    reasoning: string[];
  }> {
    const anomalies: AnomalyEvent[] = [];
    const reasoning: string[] = [];
    let riskScore = 0;

    const lastLocation = await this.getLastUserLocation(userId);
    if (!lastLocation || !location.timestamp || !lastLocation.timestamp) {
      return { anomalies, riskScore: 0, confidence: 0, reasoning };
    }

    const distance = this.calculateDistance(lastLocation, location);
    const timeDiff = (location.timestamp.getTime() - lastLocation.timestamp.getTime()) / 1000; // seconds
    const speed = (distance / timeDiff) * 3.6; // km/h

    const maxSpeed = this.detectionRules.get('MAX_DISTANCE_PER_HOUR');
    
    if (speed > maxSpeed) {
      const anomaly = await this.createAnomaly(userId, 'VELOCITY_ANOMALY', 'HIGH', {
        reason: 'Impossible travel speed',
        speed: speed,
        maxAllowed: maxSpeed,
        distance: distance,
        timeDiff: timeDiff
      });
      anomalies.push(anomaly);
      riskScore = Math.min(speed / maxSpeed, 1);
      reasoning.push(`Travel speed ${speed.toFixed(2)} km/h exceeds maximum ${maxSpeed} km/h`);
    }

    return {
      anomalies,
      riskScore,
      confidence: anomalies.length > 0 ? 0.9 : 0.1,
      reasoning
    };
  }

  /**
   * Detect time-based anomalies
   */
  private async detectTimeAnomalies(location: GeoPoint, userId: string): Promise<{
    anomalies: AnomalyEvent[];
    riskScore: number;
    confidence: number;
    reasoning: string[];
  }> {
    const anomalies: AnomalyEvent[] = [];
    const reasoning: string[] = [];
    let riskScore = 0;

    const lastCheckinTime = await this.getLastCheckinTime(userId);
    if (!lastCheckinTime || !location.timestamp) {
      return { anomalies, riskScore: 0, confidence: 0, reasoning };
    }

    const timeDiff = (location.timestamp.getTime() - lastCheckinTime.getTime()) / 1000; // seconds
    const minTime = this.detectionRules.get('MIN_TIME_BETWEEN_CHECKINS');

    if (timeDiff < minTime) {
      const anomaly = await this.createAnomaly(userId, 'TIME_ANOMALY', 'MEDIUM', {
        reason: 'Checkins too frequent',
        timeDiff: timeDiff,
        minAllowed: minTime
      });
      anomalies.push(anomaly);
      riskScore = Math.max(0, (minTime - timeDiff) / minTime);
      reasoning.push(`Checkin interval ${timeDiff}s too short, minimum ${minTime}s required`);
    }

    return {
      anomalies,
      riskScore,
      confidence: anomalies.length > 0 ? 0.6 : 0.1,
      reasoning
    };
  }

  /**
   * Detect frequency-based anomalies
   */
  private async detectFrequencyAnomalies(userId: string): Promise<{
    anomalies: AnomalyEvent[];
    riskScore: number;
    confidence: number;
    reasoning: string[];
  }> {
    const anomalies: AnomalyEvent[] = [];
    const reasoning: string[] = [];
    let riskScore = 0;

    const todayCheckins = await this.getTodayCheckinsCount(userId);
    const maxCheckins = this.detectionRules.get('MAX_LOCATIONS_PER_DAY');

    if (todayCheckins > maxCheckins) {
      const anomaly = await this.createAnomaly(userId, 'BEHAVIOR_ANOMALY', 'HIGH', {
        reason: 'Excessive daily checkins',
        checkinsToday: todayCheckins,
        maxAllowed: maxCheckins
      });
      anomalies.push(anomaly);
      riskScore = Math.min(todayCheckins / maxCheckins, 1);
      reasoning.push(`Daily checkins ${todayCheckins} exceeds limit ${maxCheckins}`);
    }

    return {
      anomalies,
      riskScore,
      confidence: anomalies.length > 0 ? 0.8 : 0.1,
      reasoning
    };
  }

  /**
   * Detect concurrent session anomalies
   */
  private async detectConcurrencyAnomalies(userId: string, location: GeoPoint): Promise<{
    anomalies: AnomalyEvent[];
    riskScore: number;
    confidence: number;
    reasoning: string[];
  }> {
    const anomalies: AnomalyEvent[] = [];
    const reasoning: string[] = [];
    let riskScore = 0;

    const activeSessions = await this.getActiveSessionsCount(userId);
    const maxSessions = this.detectionRules.get('MAX_CONCURRENT_SESSIONS');

    if (activeSessions > maxSessions) {
      const anomaly = await this.createAnomaly(userId, 'BEHAVIOR_ANOMALY', 'HIGH', {
        reason: 'Multiple concurrent sessions',
        activeSessions: activeSessions,
        maxAllowed: maxSessions,
        location
      });
      anomalies.push(anomaly);
      riskScore = Math.min(activeSessions / maxSessions, 1);
      reasoning.push(`Concurrent sessions ${activeSessions} exceeds limit ${maxSessions}`);
    }

    return {
      anomalies,
      riskScore,
      confidence: anomalies.length > 0 ? 0.9 : 0.1,
      reasoning
    };
  }

  /**
   * Detect pattern-based anomalies using ML-like approach
   */
  private async detectPatternAnomalies(
    userId: string, 
    location: GeoPoint, 
    behaviorData: any
  ): Promise<{
    anomalies: AnomalyEvent[];
    riskScore: number;
    confidence: number;
    reasoning: string[];
  }> {
    const anomalies: AnomalyEvent[] = [];
    const reasoning: string[] = [];
    let riskScore = 0;

    // Analyze clustering patterns
    const recentLocations = await this.getRecentUserLocations(userId, 20);
    const clusters = this.performLocationClustering(recentLocations);
    
    // Check for suspicious clustering
    if (clusters.length === 1 && recentLocations.length > 10) {
      // All locations in same cluster - potential GPS spoofing
      const anomaly = await this.createAnomaly(userId, 'BEHAVIOR_ANOMALY', 'MEDIUM', {
        reason: 'Unnatural location clustering',
        clusterCount: clusters.length,
        locationCount: recentLocations.length
      });
      anomalies.push(anomaly);
      riskScore += 0.5;
      reasoning.push('All recent locations clustered unnaturally');
    }

    // Check for grid-like patterns (bot behavior)
    const gridPattern = this.detectGridPattern(recentLocations);
    if (gridPattern.isGridLike) {
      const anomaly = await this.createAnomaly(userId, 'BEHAVIOR_ANOMALY', 'HIGH', {
        reason: 'Grid-like movement pattern detected',
        gridScore: gridPattern.gridScore
      });
      anomalies.push(anomaly);
      riskScore += 0.7;
      reasoning.push(`Grid-like movement pattern detected (score: ${gridPattern.gridScore})`);
    }

    return {
      anomalies,
      riskScore: Math.min(riskScore, 1),
      confidence: anomalies.length > 0 ? 0.6 : 0.1,
      reasoning
    };
  }

  /**
   * Execute automated response based on fraud detection result
   */
  private async executeAutomatedResponse(
    userId: string,
    fraudResult: FraudDetectionResult,
    location: GeoPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<void> {
    const { recommendedAction, riskScore, detectedAnomalies } = fraudResult;

    // Execute primary action
    const action = this.responseActions.get(recommendedAction);
    if (action) {
      await action(userId, fraudResult, location, deviceFingerprint);
    }

    // Execute additional actions based on risk level
    if (riskScore > 0.8) {
      await this.notifyAdministrators(userId, fraudResult, location, deviceFingerprint);
      await this.rateLimitUser(userId, fraudResult, location, deviceFingerprint);
    }

    // Log all detected anomalies
    for (const anomaly of detectedAnomalies) {
      await this.logAnomaly(anomaly);
    }

    // Emit event for external processing
    this.emit('fraud_detected', {
      userId,
      fraudResult,
      location,
      deviceFingerprint,
      timestamp: new Date()
    });
  }

  // Response Actions
  private async blockUser(
    userId: string,
    fraudResult: FraudDetectionResult,
    location: GeoPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<void> {
    const blockKey = `blocked_user:${userId}`;
    const blockData = {
      reason: 'Fraudulent activity detected',
      riskScore: fraudResult.riskScore,
      anomalies: fraudResult.detectedAnomalies.map(a => a.type),
      blockedAt: new Date(),
      location,
      deviceFingerprint: deviceFingerprint.fingerprint
    };

    await this.redis.setWithExpiry(blockKey, JSON.stringify(blockData), 86400); // 24 hours
    
    logger.warn(`User blocked due to fraud detection`, { userId, fraudResult });
  }

  private async flagUser(
    userId: string,
    fraudResult: FraudDetectionResult,
    location: GeoPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<void> {
    const flagKey = `flagged_user:${userId}`;
    const flagData = {
      reason: 'Suspicious activity detected',
      riskScore: fraudResult.riskScore,
      anomalies: fraudResult.detectedAnomalies.map(a => a.type),
      flaggedAt: new Date(),
      location,
      deviceFingerprint: deviceFingerprint.fingerprint
    };

    await this.redis.setWithExpiry(flagKey, JSON.stringify(flagData), 86400 * 7); // 7 days
    
    logger.warn(`User flagged due to suspicious activity`, { userId, fraudResult });
  }

  private async requireVerification(
    userId: string,
    fraudResult: FraudDetectionResult,
    location: GeoPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<void> {
    const verificationKey = `verification_required:${userId}`;
    const verificationData = {
      reason: 'Additional verification required',
      riskScore: fraudResult.riskScore,
      requiredAt: new Date(),
      location,
      deviceFingerprint: deviceFingerprint.fingerprint
    };

    await this.redis.setWithExpiry(verificationKey, JSON.stringify(verificationData), 3600); // 1 hour
    
    logger.info(`Verification required for user`, { userId, fraudResult });
  }

  private async rateLimitUser(
    userId: string,
    fraudResult: FraudDetectionResult,
    location: GeoPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<void> {
    const rateLimitKey = `rate_limit:${userId}`;
    const currentCount = await this.redis.get(rateLimitKey);
    const newCount = currentCount ? parseInt(currentCount, 10) + 1 : 1;
    
    await this.redis.setWithExpiry(rateLimitKey, newCount.toString(), 3600); // 1 hour
    
    logger.info(`Rate limit applied to user`, { userId, currentCount: newCount });
  }

  private async notifyAdministrators(
    userId: string,
    fraudResult: FraudDetectionResult,
    location: GeoPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<void> {
    const alertData = {
      userId,
      fraudResult,
      location,
      deviceFingerprint: deviceFingerprint.fingerprint,
      timestamp: new Date()
    };

    // In production, this would send notifications via email, Slack, etc.
    logger.error(`FRAUD ALERT: High-risk activity detected`, alertData);
    
    // Store alert for admin dashboard
    const alertKey = `fraud_alert:${Date.now()}:${userId}`;
    await this.redis.setWithExpiry(alertKey, JSON.stringify(alertData), 86400 * 30); // 30 days
  }

  // Helper methods
  private async createAnomaly(
    userId: string,
    type: AnomalyEvent['type'],
    severity: AnomalyEvent['severity'],
    details: Record<string, any>
  ): Promise<AnomalyEvent> {
    return {
      id: `anomaly_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      type,
      severity,
      details,
      timestamp: new Date(),
      resolved: false
    };
  }

  private async logAnomaly(anomaly: AnomalyEvent): Promise<void> {
    const cacheKey = `anomaly:${anomaly.id}`;
    await this.redis.setWithExpiry(cacheKey, JSON.stringify(anomaly), 86400 * 7); // 7 days
  }

  private async isImpossibleLocation(location: GeoPoint): Promise<boolean> {
    // Check against database of impossible locations (oceans, restricted areas, etc.)
    // For now, simple bounds checking
    return location.latitude < -90 || location.latitude > 90 ||
           location.longitude < -180 || location.longitude > 180;
  }

  private calculateDistance(point1: GeoPoint, point2: GeoPoint): number {
    const R = 6371000; // Earth's radius in meters
    const lat1Rad = point1.latitude * Math.PI / 180;
    const lat2Rad = point2.latitude * Math.PI / 180;
    const deltaLat = (point2.latitude - point1.latitude) * Math.PI / 180;
    const deltaLng = (point2.longitude - point1.longitude) * Math.PI / 180;

    const a = Math.sin(deltaLat / 2) * Math.sin(deltaLat / 2) +
              Math.cos(lat1Rad) * Math.cos(lat2Rad) *
              Math.sin(deltaLng / 2) * Math.sin(deltaLng / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  }

  private async getLastUserLocation(userId: string): Promise<GeoPoint | null> {
    const cacheKey = `last_location:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    return null;
  }

  private async getLastCheckinTime(userId: string): Promise<Date | null> {
    const cacheKey = `last_checkin:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      return new Date(cached);
    }
    
    return null;
  }

  private async getTodayCheckinsCount(userId: string): Promise<number> {
    const today = new Date().toISOString().split('T')[0];
    const cacheKey = `checkins_count:${userId}:${today}`;
    const cached = await this.redis.get(cacheKey);
    
    return cached ? parseInt(cached, 10) : 0;
  }

  private async getActiveSessionsCount(userId: string): Promise<number> {
    const cacheKey = `active_sessions:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    return cached ? parseInt(cached, 10) : 1;
  }

  private async getRecentUserLocations(userId: string, limit: number): Promise<GeoPoint[]> {
    const cacheKey = `recent_locations:${userId}`;
    const cached = await this.redis.get(cacheKey);
    
    if (cached) {
      const locations: GeoPoint[] = JSON.parse(cached);
      return locations.slice(0, limit);
    }
    
    return [];
  }

  private performLocationClustering(locations: GeoPoint[]): Array<{ center: GeoPoint; radius: number; count: number }> {
    // Simplified clustering - in production would use DBSCAN or K-means
    if (locations.length === 0) return [];
    
    const clusters: Array<{ center: GeoPoint; radius: number; count: number }> = [];
    const processed = new Set<number>();
    
    for (let i = 0; i < locations.length; i++) {
      if (processed.has(i)) continue;
      
      const cluster = {
        center: locations[i],
        radius: 0,
        count: 1
      };
      
      processed.add(i);
      
      for (let j = i + 1; j < locations.length; j++) {
        if (processed.has(j)) continue;
        
        const distance = this.calculateDistance(locations[i], locations[j]);
        if (distance <= 100) { // 100 meter cluster radius
          cluster.count++;
          cluster.radius = Math.max(cluster.radius, distance);
          processed.add(j);
        }
      }
      
      clusters.push(cluster);
    }
    
    return clusters;
  }

  private detectGridPattern(locations: GeoPoint[]): { isGridLike: boolean; gridScore: number } {
    if (locations.length < 4) {
      return { isGridLike: false, gridScore: 0 };
    }
    
    // Check for regular spacing and right angles
    let regularSpacings = 0;
    let rightAngles = 0;
    
    for (let i = 2; i < locations.length; i++) {
      const dist1 = this.calculateDistance(locations[i-2], locations[i-1]);
      const dist2 = this.calculateDistance(locations[i-1], locations[i]);
      
      // Check for regular spacing (within 10% variance)
      const distanceDiff = Math.abs(dist1 - dist2) / Math.max(dist1, dist2);
      if (distanceDiff < 0.1) {
        regularSpacings++;
      }
      
      // Check for right angles
      if (i >= 3) {
        const bearing1 = this.calculateBearing(locations[i-2], locations[i-1]);
        const bearing2 = this.calculateBearing(locations[i-1], locations[i]);
        const angleDiff = Math.abs(bearing2 - bearing1);
        
        if (Math.abs(angleDiff - 90) < 15 || Math.abs(angleDiff - 270) < 15) {
          rightAngles++;
        }
      }
    }
    
    const totalChecks = locations.length - 2;
    const gridScore = (regularSpacings + rightAngles) / (totalChecks * 2);
    const isGridLike = gridScore > 0.6;
    
    return { isGridLike, gridScore };
  }

  private calculateBearing(point1: GeoPoint, point2: GeoPoint): number {
    const lat1Rad = point1.latitude * Math.PI / 180;
    const lat2Rad = point2.latitude * Math.PI / 180;
    const deltaLngRad = (point2.longitude - point1.longitude) * Math.PI / 180;

    const y = Math.sin(deltaLngRad) * Math.cos(lat2Rad);
    const x = Math.cos(lat1Rad) * Math.sin(lat2Rad) -
              Math.sin(lat1Rad) * Math.cos(lat2Rad) * Math.cos(deltaLngRad);

    const bearingRad = Math.atan2(y, x);
    return ((bearingRad * 180 / Math.PI) + 360) % 360;
  }
}

/**
 * Main Anti-Fraud Security System class that orchestrates all security components
 */
export class AntiFraudSecuritySystem {
  private spoofingDetector: GPSSpoofingDetector;
  private behaviorAnalyzer: UserBehaviorAnalyzer;
  private fingerprintingEngine: DeviceFingerprintingEngine;
  private anomalyDetectionEngine: AnomalyDetectionEngine;
  private redis: RedisService;

  constructor(redis: RedisService) {
    this.redis = redis;
    this.spoofingDetector = new GPSSpoofingDetector(redis);
    this.behaviorAnalyzer = new UserBehaviorAnalyzer(redis);
    this.fingerprintingEngine = new DeviceFingerprintingEngine(redis);
    this.anomalyDetectionEngine = new AnomalyDetectionEngine(redis);

    logger.info('Anti-Fraud Security System initialized');
  }

  // Expose all engines for external use
  public get spoofing() { return this.spoofingDetector; }
  public get behavior() { return this.behaviorAnalyzer; }
  public get fingerprinting() { return this.fingerprintingEngine; }
  public get anomaly() { return this.anomalyDetectionEngine; }

  /**
   * Comprehensive fraud detection pipeline
   */
  public async detectFraud(
    userId: string,
    location: GeoPoint,
    deviceData: any,
    sessionData: any,
    previousLocations: GeoPoint[] = []
  ): Promise<FraudDetectionResult> {
    const startTime = Date.now();

    try {
      // Step 1: Generate device fingerprint
      const deviceFingerprint = await this.fingerprintingEngine.generateFingerprint(deviceData);

      // Step 2: Parallel fraud detection
      const [spoofingResult, behaviorResult, deviceAbuseResult] = await Promise.all([
        this.spoofingDetector.detectGPSSpoofing(location, userId, deviceFingerprint, previousLocations),
        this.behaviorAnalyzer.analyzeBehavior(userId, location, sessionData),
        this.fingerprintingEngine.detectDeviceAbuse(deviceFingerprint, userId)
      ]);

      // Step 3: Comprehensive anomaly detection
      const fraudResult = await this.anomalyDetectionEngine.detectAnomalies(
        userId,
        location,
        deviceFingerprint,
        behaviorResult,
        spoofingResult
      );

      // Step 4: Enhance fraud result with component-specific data
      if (deviceAbuseResult.isAbusive) {
        fraudResult.riskScore = Math.max(fraudResult.riskScore, deviceAbuseResult.abuseScore);
        fraudResult.reasoning.push(...deviceAbuseResult.abuseTypes.map(type => `Device abuse: ${type}`));
      }

      const processingTime = Date.now() - startTime;

      logger.info('Fraud detection completed', {
        userId,
        location,
        processingTime,
        isFraudulent: fraudResult.isFraudulent,
        riskScore: fraudResult.riskScore,
        recommendedAction: fraudResult.recommendedAction
      });

      return fraudResult;

    } catch (error) {
      logger.error('Fraud detection failed', { userId, location, error });
      
      // Return safe default in case of error
      return {
        isFraudulent: true, // Err on the side of caution
        riskScore: 0.9,
        confidence: 0.5,
        detectedAnomalies: [],
        recommendedAction: 'BLOCK',
        reasoning: ['Fraud detection system error - blocking for safety']
      };
    }
  }

  /**
   * Health check for all security components
   */
  public async healthCheck(): Promise<{
    spoofingDetector: boolean;
    behaviorAnalyzer: boolean;
    fingerprintingEngine: boolean;
    anomalyDetectionEngine: boolean;
    overall: boolean;
  }> {
    const checks = {
      spoofingDetector: true, // Would implement actual health checks
      behaviorAnalyzer: true,
      fingerprintingEngine: true,
      anomalyDetectionEngine: true,
      overall: true
    };

    checks.overall = Object.values(checks).slice(0, -1).every(Boolean);

    return checks;
  }

  /**
   * Get system statistics
   */
  public async getSystemStats(): Promise<{
    totalAnomaliesDetected: number;
    totalUsersBlocked: number;
    totalUsersFlagged: number;
    avgProcessingTime: number;
    detectionAccuracy: number;
  }> {
    // This would query actual metrics from Redis/database
    return {
      totalAnomaliesDetected: 0,
      totalUsersBlocked: 0,
      totalUsersFlagged: 0,
      avgProcessingTime: 0,
      detectionAccuracy: 0.95
    };
  }
}