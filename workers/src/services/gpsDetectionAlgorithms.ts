/**
 * Advanced GPS Detection Algorithms
 * Sophisticated algorithms for detecting GPS spoofing and location fraud
 */

import { LocationPoint } from './antiFraudService';
import { calculateHaversineDistance, calculateVincentyDistance } from './geofencing';

export interface GPSAnalysisResult {
  spoofing_probability: number; // 0-1, higher means more likely to be spoofed
  confidence_score: number; // 0-1, confidence in the analysis
  detection_methods: {
    signal_analysis: GPSSignalAnalysis;
    temporal_analysis: TemporalAnalysis;
    spatial_analysis: SpatialAnalysis;
    device_analysis: DeviceConsistencyAnalysis;
    behavioral_analysis: BehavioralPatternAnalysis;
  };
  risk_indicators: string[];
  recommendations: string[];
}

export interface GPSSignalAnalysis {
  accuracy_anomaly: boolean;
  precision_suspicion: number; // 0-1
  satellite_data_available: boolean;
  signal_strength_pattern: 'normal' | 'suspicious' | 'impossible';
  timing_inconsistencies: boolean;
}

export interface TemporalAnalysis {
  timestamp_drift: number; // milliseconds
  update_frequency_anomaly: boolean;
  stale_location_detected: boolean;
  time_zone_consistency: boolean;
}

export interface SpatialAnalysis {
  coordinate_clustering: number; // 0-1, higher means more clustered
  decimal_precision_analysis: {
    latitude_precision: number;
    longitude_precision: number;
    suspicion_level: number; // 0-1
  };
  geographic_plausibility: number; // 0-1
  altitude_consistency: number; // 0-1
}

export interface DeviceConsistencyAnalysis {
  platform_gps_capability: number; // 0-1
  expected_accuracy_range: {
    min: number;
    max: number;
  };
  device_type_consistency: boolean;
  sensor_data_correlation: number; // 0-1
}

export interface BehavioralPatternAnalysis {
  movement_realism: number; // 0-1
  speed_consistency: number; // 0-1
  direction_changes: {
    frequency: number;
    naturalness: number; // 0-1
  };
  stop_go_patterns: {
    natural_stops: boolean;
    artificial_patterns: boolean;
  };
}

export class GPSDetectionAlgorithms {
  /**
   * Main GPS authenticity analysis
   */
  static analyzeGPSAuthenticity(
    location: LocationPoint,
    deviceInfo: any,
    recentHistory: LocationPoint[] = [],
    context: {
      user_agent: string;
      ip_geolocation?: { lat: number; lng: number; accuracy_km: number };
      timezone?: string;
    }
  ): GPSAnalysisResult {
    const signalAnalysis = this.analyzeGPSSignal(location, deviceInfo);
    const temporalAnalysis = this.analyzeTemporalPatterns(location, recentHistory);
    const spatialAnalysis = this.analyzeSpatialPatterns(location, recentHistory);
    const deviceAnalysis = this.analyzeDeviceConsistency(location, deviceInfo, context);
    const behavioralAnalysis = this.analyzeBehavioralPatterns(location, recentHistory);

    // Calculate overall spoofing probability
    const spoofingProbability = this.calculateSpoofingProbability({
      signalAnalysis,
      temporalAnalysis,
      spatialAnalysis,
      deviceAnalysis,
      behavioralAnalysis
    });

    // Calculate confidence in analysis
    const confidenceScore = this.calculateConfidenceScore({
      signalAnalysis,
      temporalAnalysis,
      spatialAnalysis,
      deviceAnalysis,
      behavioralAnalysis,
      historyLength: recentHistory.length
    });

    // Generate risk indicators and recommendations
    const riskIndicators = this.generateRiskIndicators({
      signalAnalysis,
      temporalAnalysis,
      spatialAnalysis,
      deviceAnalysis,
      behavioralAnalysis
    });

    const recommendations = this.generateRecommendations(spoofingProbability, riskIndicators);

    return {
      spoofing_probability: spoofingProbability,
      confidence_score: confidenceScore,
      detection_methods: {
        signal_analysis: signalAnalysis,
        temporal_analysis: temporalAnalysis,
        spatial_analysis: spatialAnalysis,
        device_analysis: deviceAnalysis,
        behavioral_analysis: behavioralAnalysis
      },
      risk_indicators: riskIndicators,
      recommendations: recommendations
    };
  }

  /**
   * Analyze GPS signal characteristics
   */
  private static analyzeGPSSignal(location: LocationPoint, deviceInfo: any): GPSSignalAnalysis {
    let accuracyAnomaly = false;
    let precisionSuspicion = 0;
    let signalStrengthPattern: 'normal' | 'suspicious' | 'impossible' = 'normal';
    let timingInconsistencies = false;

    // Check accuracy anomalies
    if (location.accuracy !== undefined) {
      // Too perfect accuracy (< 1m) is suspicious for most consumer devices
      if (location.accuracy < 1) {
        accuracyAnomaly = true;
        precisionSuspicion += 0.4;
        signalStrengthPattern = 'impossible';
      }
      
      // Very poor accuracy (> 1000m) might indicate spoofing or poor implementation
      else if (location.accuracy > 1000) {
        accuracyAnomaly = true;
        precisionSuspicion += 0.2;
        signalStrengthPattern = 'suspicious';
      }

      // Desktop browsers with high accuracy are suspicious
      const isDesktop = deviceInfo?.userAgent && 
        !(/Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(deviceInfo.userAgent));
      
      if (isDesktop && location.accuracy < 50) {
        accuracyAnomaly = true;
        precisionSuspicion += 0.3;
        signalStrengthPattern = 'suspicious';
      }
    }

    // Check timing inconsistencies
    if (location.timestamp) {
      const timeDiff = Math.abs(Date.now() - location.timestamp);
      if (timeDiff > 60000) { // More than 1 minute old
        timingInconsistencies = true;
        precisionSuspicion += 0.2;
      }
    }

    return {
      accuracy_anomaly: accuracyAnomaly,
      precision_suspicion: Math.min(precisionSuspicion, 1),
      satellite_data_available: false, // This would require additional API data
      signal_strength_pattern: signalStrengthPattern,
      timing_inconsistencies: timingInconsistencies
    };
  }

  /**
   * Analyze temporal patterns in GPS data
   */
  private static analyzeTemporalPatterns(
    location: LocationPoint, 
    history: LocationPoint[]
  ): TemporalAnalysis {
    let timestampDrift = 0;
    let updateFrequencyAnomaly = false;
    let staleLocationDetected = false;
    let timeZoneConsistency = true;

    if (location.timestamp) {
      timestampDrift = Math.abs(Date.now() - location.timestamp);
      
      if (timestampDrift > 30000) { // More than 30 seconds
        staleLocationDetected = true;
      }
    }

    // Analyze update frequency patterns
    if (history.length > 1) {
      const intervals = [];
      for (let i = 1; i < history.length; i++) {
        if (history[i].timestamp && history[i-1].timestamp) {
          intervals.push(history[i].timestamp - history[i-1].timestamp);
        }
      }

      if (intervals.length > 2) {
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
        
        // Too regular updates might indicate automation
        if (variance < 1000 && avgInterval > 0) { // Very low variance (< 1 second)
          updateFrequencyAnomaly = true;
        }
      }
    }

    return {
      timestamp_drift: timestampDrift,
      update_frequency_anomaly: updateFrequencyAnomaly,
      stale_location_detected: staleLocationDetected,
      time_zone_consistency: timeZoneConsistency
    };
  }

  /**
   * Analyze spatial patterns and coordinate characteristics
   */
  private static analyzeSpatialPatterns(
    location: LocationPoint,
    history: LocationPoint[]
  ): SpatialAnalysis {
    // Analyze coordinate precision
    const latStr = location.latitude.toString();
    const lngStr = location.longitude.toString();
    const latPrecision = latStr.split('.')[1]?.length || 0;
    const lngPrecision = lngStr.split('.')[1]?.length || 0;

    // Low precision (< 4 decimal places) is suspicious for GPS
    let precisionSuspicion = 0;
    if (latPrecision < 4 || lngPrecision < 4) {
      precisionSuspicion = 0.5;
    }
    if (latPrecision < 2 || lngPrecision < 2) {
      precisionSuspicion = 0.8;
    }

    // Check for obvious round numbers
    const isRoundLat = location.latitude % 0.001 === 0;
    const isRoundLng = location.longitude % 0.001 === 0;
    if (isRoundLat || isRoundLng) {
      precisionSuspicion = Math.max(precisionSuspicion, 0.6);
    }

    // Analyze clustering if we have history
    let coordinateClustering = 0;
    if (history.length > 2) {
      const distances = history.map(h => 
        calculateHaversineDistance(location.latitude, location.longitude, h.latitude, h.longitude)
      );
      const avgDistance = distances.reduce((a, b) => a + b, 0) / distances.length;
      const closePoints = distances.filter(d => d < 10).length; // Within 10 meters
      coordinateClustering = closePoints / distances.length;
    }

    // Geographic plausibility check
    let geographicPlausibility = 1;
    const lat = location.latitude;
    const lng = location.longitude;
    
    // Check if coordinates are in obviously impossible locations
    if (lat === 0 && lng === 0) {
      geographicPlausibility = 0; // Null Island
    }
    if (Math.abs(lat) > 85) {
      geographicPlausibility = 0.2; // Very close to poles
    }

    // Altitude consistency
    let altitudeConsistency = 1;
    if (location.altitude !== undefined) {
      if (location.altitude < -500 || location.altitude > 9000) { // Below Dead Sea or above Everest
        altitudeConsistency = 0.1;
      }
    }

    return {
      coordinate_clustering: coordinateClustering,
      decimal_precision_analysis: {
        latitude_precision: latPrecision,
        longitude_precision: lngPrecision,
        suspicion_level: precisionSuspicion
      },
      geographic_plausibility: geographicPlausibility,
      altitude_consistency: altitudeConsistency
    };
  }

  /**
   * Analyze device consistency with reported GPS data
   */
  private static analyzeDeviceConsistency(
    location: LocationPoint,
    deviceInfo: any,
    context: { user_agent: string; ip_geolocation?: any; timezone?: string }
  ): DeviceConsistencyAnalysis {
    let platformGPSCapability = 1;
    let deviceTypeConsistency = true;
    let sensorDataCorrelation = 1;

    // Analyze device GPS capabilities based on user agent
    const userAgent = context.user_agent || deviceInfo?.userAgent || '';
    const isMobile = /Mobile|Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(userAgent);
    const isDesktop = !isMobile;

    // Expected accuracy ranges by device type
    let expectedAccuracyRange = { min: 5, max: 100 };
    
    if (isMobile) {
      expectedAccuracyRange = { min: 3, max: 50 }; // Mobile devices have better GPS
      platformGPSCapability = 0.9;
    } else if (isDesktop) {
      expectedAccuracyRange = { min: 50, max: 1000 }; // Desktop relies on IP/WiFi
      platformGPSCapability = 0.3;
    }

    // Check if reported accuracy matches device capabilities
    if (location.accuracy !== undefined) {
      if (isDesktop && location.accuracy < 20) {
        deviceTypeConsistency = false;
        sensorDataCorrelation = 0.2;
      }
      
      if (isMobile && location.accuracy > 500) {
        sensorDataCorrelation = 0.5;
      }
    }

    // Cross-check with IP geolocation if available
    if (context.ip_geolocation) {
      const ipDistance = calculateHaversineDistance(
        location.latitude, location.longitude,
        context.ip_geolocation.lat, context.ip_geolocation.lng
      ) / 1000; // Convert to km

      // If GPS and IP are very far apart, it's suspicious
      if (ipDistance > 1000) { // More than 1000km apart
        sensorDataCorrelation *= 0.5;
      }
    }

    return {
      platform_gps_capability: platformGPSCapability,
      expected_accuracy_range: expectedAccuracyRange,
      device_type_consistency: deviceTypeConsistency,
      sensor_data_correlation: sensorDataCorrelation
    };
  }

  /**
   * Analyze behavioral movement patterns
   */
  private static analyzeBehavioralPatterns(
    location: LocationPoint,
    history: LocationPoint[]
  ): BehavioralPatternAnalysis {
    let movementRealism = 1;
    let speedConsistency = 1;
    let naturalStops = true;
    let artificialPatterns = false;

    if (history.length < 2) {
      return {
        movement_realism: movementRealism,
        speed_consistency: speedConsistency,
        direction_changes: { frequency: 0, naturalness: 1 },
        stop_go_patterns: { natural_stops: naturalStops, artificial_patterns: artificialPatterns }
      };
    }

    // Calculate speeds and direction changes
    const movements = [];
    for (let i = 1; i < history.length; i++) {
      const prev = history[i - 1];
      const curr = history[i];
      
      if (prev.timestamp && curr.timestamp) {
        const distance = calculateVincentyDistance(
          prev.latitude, prev.longitude,
          curr.latitude, curr.longitude
        );
        const timeDiff = (curr.timestamp - prev.timestamp) / 1000; // seconds
        
        if (timeDiff > 0) {
          const speed = (distance / timeDiff) * 3.6; // km/h
          movements.push({ distance, timeDiff, speed });
        }
      }
    }

    if (movements.length > 0) {
      const speeds = movements.map(m => m.speed);
      const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
      
      // Check for impossible speeds
      const maxSpeed = Math.max(...speeds);
      if (maxSpeed > 300) { // Faster than commercial aircraft
        movementRealism = 0.1;
      } else if (maxSpeed > 120) { // Very fast driving
        movementRealism = 0.7;
      }

      // Check speed variance - too consistent speeds are suspicious
      const speedVariance = speeds.reduce((sum, speed) => sum + Math.pow(speed - avgSpeed, 2), 0) / speeds.length;
      if (speedVariance < 1 && avgSpeed > 5) { // Very consistent non-zero speed
        speedConsistency = 0.3;
        artificialPatterns = true;
      }

      // Check for unnatural stop-start patterns
      const stopCount = speeds.filter(s => s < 1).length;
      const movingCount = speeds.filter(s => s > 5).length;
      
      if (stopCount === 0 && movingCount > 5) { // Never stops
        naturalStops = false;
        artificialPatterns = true;
      }
    }

    // Direction change analysis
    let directionChanges = 0;
    let totalDirectionDiff = 0;
    
    if (history.length > 2) {
      for (let i = 2; i < history.length; i++) {
        const p1 = history[i - 2];
        const p2 = history[i - 1];
        const p3 = history[i];
        
        const bearing1 = this.calculateBearing(p1, p2);
        const bearing2 = this.calculateBearing(p2, p3);
        const angleDiff = Math.abs(bearing2 - bearing1);
        
        if (angleDiff > 15) { // More than 15 degree change
          directionChanges++;
          totalDirectionDiff += angleDiff;
        }
      }
    }

    const directionFrequency = history.length > 2 ? directionChanges / (history.length - 2) : 0;
    const avgDirectionChange = directionChanges > 0 ? totalDirectionDiff / directionChanges : 0;
    
    // Very frequent sharp turns are suspicious
    let directionalNaturalness = 1;
    if (directionFrequency > 0.8 && avgDirectionChange > 90) {
      directionalNaturalness = 0.3;
      artificialPatterns = true;
    }

    return {
      movement_realism: movementRealism,
      speed_consistency: speedConsistency,
      direction_changes: {
        frequency: directionFrequency,
        naturalness: directionalNaturalness
      },
      stop_go_patterns: {
        natural_stops: naturalStops,
        artificial_patterns: artificialPatterns
      }
    };
  }

  /**
   * Calculate overall spoofing probability
   */
  private static calculateSpoofingProbability(analyses: {
    signalAnalysis: GPSSignalAnalysis;
    temporalAnalysis: TemporalAnalysis;
    spatialAnalysis: SpatialAnalysis;
    deviceAnalysis: DeviceConsistencyAnalysis;
    behavioralAnalysis: BehavioralPatternAnalysis;
  }): number {
    let probability = 0;

    // Weight factors for different analyses
    const weights = {
      signal: 0.25,
      temporal: 0.15,
      spatial: 0.20,
      device: 0.20,
      behavioral: 0.20
    };

    // Signal analysis contribution
    probability += analyses.signalAnalysis.precision_suspicion * weights.signal;
    if (analyses.signalAnalysis.signal_strength_pattern === 'impossible') {
      probability += 0.3 * weights.signal;
    } else if (analyses.signalAnalysis.signal_strength_pattern === 'suspicious') {
      probability += 0.15 * weights.signal;
    }

    // Temporal analysis contribution
    if (analyses.temporalAnalysis.stale_location_detected) {
      probability += 0.4 * weights.temporal;
    }
    if (analyses.temporalAnalysis.update_frequency_anomaly) {
      probability += 0.3 * weights.temporal;
    }

    // Spatial analysis contribution
    probability += analyses.spatialAnalysis.decimal_precision_analysis.suspicion_level * weights.spatial;
    probability += (1 - analyses.spatialAnalysis.geographic_plausibility) * weights.spatial;

    // Device analysis contribution
    probability += (1 - analyses.deviceAnalysis.sensor_data_correlation) * weights.device;
    if (!analyses.deviceAnalysis.device_type_consistency) {
      probability += 0.5 * weights.device;
    }

    // Behavioral analysis contribution
    probability += (1 - analyses.behavioralAnalysis.movement_realism) * weights.behavioral;
    probability += (1 - analyses.behavioralAnalysis.speed_consistency) * weights.behavioral;
    if (analyses.behavioralAnalysis.stop_go_patterns.artificial_patterns) {
      probability += 0.3 * weights.behavioral;
    }

    return Math.min(probability, 1);
  }

  /**
   * Calculate confidence score in the analysis
   */
  private static calculateConfidenceScore(data: {
    signalAnalysis: GPSSignalAnalysis;
    temporalAnalysis: TemporalAnalysis;
    spatialAnalysis: SpatialAnalysis;
    deviceAnalysis: DeviceConsistencyAnalysis;
    behavioralAnalysis: BehavioralPatternAnalysis;
    historyLength: number;
  }): number {
    let confidence = 0.5; // Base confidence

    // More history increases confidence
    const historyFactor = Math.min(data.historyLength / 10, 1);
    confidence += historyFactor * 0.3;

    // Device capability information increases confidence
    if (data.deviceAnalysis.platform_gps_capability > 0.5) {
      confidence += 0.1;
    }

    // Behavioral analysis requires history
    if (data.historyLength > 3) {
      confidence += 0.1;
    }

    return Math.min(confidence, 1);
  }

  /**
   * Generate risk indicators
   */
  private static generateRiskIndicators(analyses: {
    signalAnalysis: GPSSignalAnalysis;
    temporalAnalysis: TemporalAnalysis;
    spatialAnalysis: SpatialAnalysis;
    deviceAnalysis: DeviceConsistencyAnalysis;
    behavioralAnalysis: BehavioralPatternAnalysis;
  }): string[] {
    const indicators: string[] = [];

    if (analyses.signalAnalysis.accuracy_anomaly) {
      indicators.push('GPS accuracy anomaly detected');
    }
    if (analyses.signalAnalysis.signal_strength_pattern === 'impossible') {
      indicators.push('Impossible GPS signal characteristics');
    }
    if (analyses.temporalAnalysis.stale_location_detected) {
      indicators.push('Stale location timestamp');
    }
    if (analyses.spatialAnalysis.decimal_precision_analysis.suspicion_level > 0.5) {
      indicators.push('Suspicious coordinate precision');
    }
    if (!analyses.deviceAnalysis.device_type_consistency) {
      indicators.push('Device type inconsistent with GPS capability');
    }
    if (analyses.behavioralAnalysis.movement_realism < 0.5) {
      indicators.push('Unrealistic movement patterns');
    }
    if (analyses.behavioralAnalysis.stop_go_patterns.artificial_patterns) {
      indicators.push('Artificial movement patterns detected');
    }

    return indicators;
  }

  /**
   * Generate recommendations
   */
  private static generateRecommendations(
    spoofingProbability: number,
    riskIndicators: string[]
  ): string[] {
    const recommendations: string[] = [];

    if (spoofingProbability > 0.8) {
      recommendations.push('Block submission - high fraud probability');
      recommendations.push('Flag user account for investigation');
    } else if (spoofingProbability > 0.6) {
      recommendations.push('Require manual review');
      recommendations.push('Request additional verification');
    } else if (spoofingProbability > 0.4) {
      recommendations.push('Monitor user for patterns');
      recommendations.push('Apply additional validation checks');
    } else if (spoofingProbability > 0.2) {
      recommendations.push('Normal processing with monitoring');
    } else {
      recommendations.push('Accept with standard processing');
    }

    if (riskIndicators.length > 3) {
      recommendations.push('Multiple risk factors present - increase scrutiny');
    }

    return recommendations;
  }

  /**
   * Calculate bearing between two points
   */
  private static calculateBearing(from: LocationPoint, to: LocationPoint): number {
    const lat1 = (from.latitude * Math.PI) / 180;
    const lat2 = (to.latitude * Math.PI) / 180;
    const deltaLng = ((to.longitude - from.longitude) * Math.PI) / 180;

    const y = Math.sin(deltaLng) * Math.cos(lat2);
    const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(deltaLng);

    const bearing = Math.atan2(y, x);
    return ((bearing * 180) / Math.PI + 360) % 360;
  }
}

export default GPSDetectionAlgorithms;