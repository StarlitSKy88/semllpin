/**
 * SmellPin Anti-Fraud Service
 * Comprehensive GPS location verification and fraud detection system
 * 
 * Features:
 * - GPS spoofing detection
 * - User behavior pattern analysis  
 * - Device fingerprinting
 * - Location history verification
 * - Real-time risk scoring
 * - Automated fraud prevention
 */

import { NeonDatabase } from '../utils/neon-database';
import { GeofencingService, calculateHaversineDistance, calculateVincentyDistance } from './geofencing';
import { Env } from '../index';
import { z } from 'zod';
import crypto from 'crypto';
import GPSDetectionAlgorithms, { GPSAnalysisResult } from './gpsDetectionAlgorithms';
import UserRiskAssessmentService, { RiskAssessmentContext } from './userRiskAssessment';

// Validation schemas
const locationSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  accuracy: z.number().positive().optional(),
  altitude: z.number().optional(),
  speed: z.number().min(0).optional(),
  heading: z.number().min(0).max(360).optional(),
  timestamp: z.number().optional()
});

const deviceInfoSchema = z.object({
  userAgent: z.string(),
  screen: z.object({
    width: z.number(),
    height: z.number(),
    colorDepth: z.number().optional(),
    pixelRatio: z.number().optional()
  }),
  timezone: z.string(),
  language: z.string(),
  platform: z.string(),
  cookieEnabled: z.boolean().optional(),
  doNotTrack: z.boolean().optional(),
  plugins: z.array(z.string()).optional(),
  webgl: z.object({
    vendor: z.string().optional(),
    renderer: z.string().optional()
  }).optional()
});

const verificationRequestSchema = z.object({
  user_id: z.string().uuid(),
  annotation_id: z.string().uuid(),
  location: locationSchema,
  device_info: deviceInfoSchema,
  ip_address: z.string(),
  submission_time: z.number()
});

// Risk scoring constants
const RISK_THRESHOLDS = {
  LOW: 25,
  MEDIUM: 50,
  HIGH: 75,
  CRITICAL: 90
};

const SPEED_LIMITS = {
  WALKING_MAX: 8, // km/h
  CYCLING_MAX: 40, // km/h  
  DRIVING_MAX: 150, // km/h
  IMPOSSIBLE: 300 // km/h - anything above this is definitely fake
};

const DETECTION_RULES = {
  // Maximum distance jump in short time (km)
  MAX_LOCATION_JUMP: 50,
  MIN_JUMP_TIME_SECONDS: 300, // 5 minutes
  
  // Device consistency
  MAX_DEVICES_PER_USER: 3,
  DEVICE_SWITCH_PENALTY: 15,
  
  // Behavioral patterns  
  MAX_SUBMISSIONS_PER_HOUR: 10,
  MAX_SUBMISSIONS_PER_DAY: 50,
  RAPID_SUBMISSION_PENALTY: 20,
  
  // Location accuracy
  MIN_GPS_ACCURACY: 100, // meters
  POOR_ACCURACY_PENALTY: 10
};

export interface LocationPoint {
  latitude: number;
  longitude: number;
  accuracy?: number;
  altitude?: number;
  speed?: number;
  heading?: number;
  timestamp?: number;
}

export interface DeviceFingerprint {
  id?: string;
  user_id: string;
  fingerprint_hash: string;
  device_info: any;
  ip_address: string;
  user_agent: string;
  is_trusted: boolean;
  risk_score: number;
  first_seen?: Date;
  last_seen?: Date;
}

export interface VerificationResult {
  user_id: string;
  annotation_id: string;
  verification_status: 'passed' | 'failed' | 'manual_review';
  risk_score: number;
  risk_factors: {
    gps_spoofing_detected: boolean;
    impossible_speed: boolean;
    location_jump_detected: boolean;
    device_inconsistency: boolean;
    behavioral_anomaly: boolean;
    poor_gps_accuracy: boolean;
    rapid_submissions: boolean;
    mock_location_detected: boolean;
  };
  evidence: any;
  decision_reason: string;
  requires_manual_review: boolean;
  auto_action: 'none' | 'flag' | 'block' | 'suspend';
}

export interface MovementPattern {
  user_id: string;
  time_window: {
    start: Date;
    end: Date;
  };
  total_distance_km: number;
  max_speed_kmh: number;
  avg_speed_kmh: number;
  location_changes: number;
  suspicious_jumps: number;
  stationary_periods: number;
  anomalies: string[];
  risk_score: number;
}

export interface UserRiskProfile {
  user_id: string;
  overall_risk_score: number;
  trust_level: 'trusted' | 'neutral' | 'suspicious' | 'blocked';
  total_submissions: number;
  verified_submissions: number;
  fraud_incidents_count: number;
  account_age_days: number;
  device_consistency_score: number;
  location_pattern_score: number;
  behavioral_score: number;
  last_updated: Date;
}

export class AntiFraudService {
  private db: NeonDatabase;
  private env: Env;
  private geofencing: GeofencingService;
  private riskAssessment: UserRiskAssessmentService;
  
  // Caching for performance
  private userRiskCache = new Map<string, UserRiskProfile>();
  private deviceCache = new Map<string, DeviceFingerprint>();
  private ruleCache = new Map<string, any>();
  
  private readonly CACHE_TTL = 10 * 60 * 1000; // 10 minutes

  constructor(env: Env) {
    this.env = env;
    this.db = new NeonDatabase(env.DATABASE_URL);
    this.geofencing = new GeofencingService(env);
    this.riskAssessment = new UserRiskAssessmentService(env);
  }

  /**
   * Main GPS verification function - entry point for all location verification
   */
  async verifyGPSLocation(request: {
    user_id: string;
    annotation_id: string;
    location: LocationPoint;
    device_info: any;
    ip_address: string;
    submission_time?: number;
  }): Promise<VerificationResult> {
    try {
      // Validate input
      const validatedRequest = verificationRequestSchema.parse({
        ...request,
        submission_time: request.submission_time || Date.now()
      });

      console.log(`[AntiF​raud] Starting GPS verification for user ${request.user_id}, annotation ${request.annotation_id}`);

      // Initialize verification result
      const result: VerificationResult = {
        user_id: request.user_id,
        annotation_id: request.annotation_id,
        verification_status: 'passed',
        risk_score: 0,
        risk_factors: {
          gps_spoofing_detected: false,
          impossible_speed: false,
          location_jump_detected: false,
          device_inconsistency: false,
          behavioral_anomaly: false,
          poor_gps_accuracy: false,
          rapid_submissions: false,
          mock_location_detected: false
        },
        evidence: {},
        decision_reason: '',
        requires_manual_review: false,
        auto_action: 'none'
      };

      // Step 1: Device fingerprinting and validation
      const deviceFingerprint = await this.processDeviceFingerprint(
        request.user_id, 
        request.device_info, 
        request.ip_address
      );
      result.evidence.device_fingerprint = deviceFingerprint;

      // Step 2: GPS spoofing detection
      const gpsAnalysis = await this.analyzeGPSAuthenticity(request.location, deviceFingerprint);
      result.risk_score += gpsAnalysis.risk_score;
      result.risk_factors.gps_spoofing_detected = gpsAnalysis.spoofing_detected;
      result.risk_factors.mock_location_detected = gpsAnalysis.mock_location_detected;
      result.risk_factors.poor_gps_accuracy = gpsAnalysis.poor_accuracy;
      result.evidence.gps_analysis = gpsAnalysis;

      // Step 3: Movement pattern analysis  
      const movementAnalysis = await this.analyzeMovementPattern(
        request.user_id, 
        request.location, 
        validatedRequest.submission_time
      );
      result.risk_score += movementAnalysis.risk_score;
      result.risk_factors.impossible_speed = movementAnalysis.impossible_speed;
      result.risk_factors.location_jump_detected = movementAnalysis.location_jump;
      result.evidence.movement_analysis = movementAnalysis;

      // Step 4: Behavioral pattern analysis
      const behaviorAnalysis = await this.analyzeBehavioralPatterns(
        request.user_id, 
        deviceFingerprint.fingerprint_hash,
        validatedRequest.submission_time
      );
      result.risk_score += behaviorAnalysis.risk_score;
      result.risk_factors.device_inconsistency = behaviorAnalysis.device_inconsistency;
      result.risk_factors.rapid_submissions = behaviorAnalysis.rapid_submissions;
      result.risk_factors.behavioral_anomaly = behaviorAnalysis.behavioral_anomaly;
      result.evidence.behavior_analysis = behaviorAnalysis;

      // Step 5: User risk profile evaluation
      const userRisk = await this.evaluateUserRiskProfile(request.user_id);
      result.risk_score += userRisk.adjustment;
      result.evidence.user_risk_profile = userRisk;

      // Step 6: Final risk assessment and decision
      const decision = await this.makeVerificationDecision(result.risk_score, result.risk_factors);
      result.verification_status = decision.status;
      result.decision_reason = decision.reason;
      result.requires_manual_review = decision.manual_review_required;
      result.auto_action = decision.auto_action;

      // Step 7: Record verification result
      await this.recordVerificationResult(result, deviceFingerprint.fingerprint_hash);

      // Step 8: Update user risk profile
      await this.updateUserRiskProfile(request.user_id, result);

      // Step 9: Handle fraud incidents if detected
      if (result.verification_status === 'failed') {
        await this.handleFraudIncident(result);
      }

      console.log(`[AntiF​raud] Verification completed: ${result.verification_status}, Risk Score: ${result.risk_score}`);

      return result;

    } catch (error) {
      console.error('[AntiF​raud] Verification error:', error);
      
      // Return safe default for errors
      return {
        user_id: request.user_id,
        annotation_id: request.annotation_id,
        verification_status: 'manual_review',
        risk_score: 100,
        risk_factors: {
          gps_spoofing_detected: false,
          impossible_speed: false,
          location_jump_detected: false,
          device_inconsistency: false,
          behavioral_anomaly: false,
          poor_gps_accuracy: false,
          rapid_submissions: false,
          mock_location_detected: false
        },
        evidence: { error: error.message },
        decision_reason: 'System error during verification',
        requires_manual_review: true,
        auto_action: 'none'
      };
    }
  }

  /**
   * Device fingerprinting for fraud detection
   */
  private async processDeviceFingerprint(
    userId: string, 
    deviceInfo: any, 
    ipAddress: string
  ): Promise<DeviceFingerprint> {
    try {
      // Create device fingerprint hash
      const fingerprintString = JSON.stringify({
        userAgent: deviceInfo.userAgent,
        screen: deviceInfo.screen,
        timezone: deviceInfo.timezone,
        language: deviceInfo.language,
        platform: deviceInfo.platform
      });
      
      const fingerprintHash = crypto
        .createHash('sha256')
        .update(fingerprintString)
        .digest('hex');

      // Check if device exists
      let existingDevice = await this.db.sql`
        SELECT * FROM device_fingerprints 
        WHERE fingerprint_hash = ${fingerprintHash}
      `;

      if (existingDevice.length > 0) {
        // Update existing device
        const device = existingDevice[0];
        await this.db.sql`
          UPDATE device_fingerprints 
          SET last_seen = NOW(), ip_address = ${ipAddress}
          WHERE id = ${device.id}
        `;
        
        return {
          ...device,
          device_info: device.device_info,
          last_seen: new Date()
        };
      } else {
        // Create new device fingerprint
        const newDevice = await this.db.sql`
          INSERT INTO device_fingerprints (
            user_id, fingerprint_hash, device_info, ip_address, user_agent, 
            is_trusted, risk_score, first_seen, last_seen
          )
          VALUES (
            ${userId}, ${fingerprintHash}, ${JSON.stringify(deviceInfo)}, 
            ${ipAddress}, ${deviceInfo.userAgent}, false, 0, NOW(), NOW()
          )
          RETURNING *
        `;

        return {
          ...newDevice[0],
          device_info: newDevice[0].device_info,
          first_seen: new Date(newDevice[0].first_seen),
          last_seen: new Date(newDevice[0].last_seen)
        };
      }
    } catch (error) {
      console.error('[AntiF​raud] Device fingerprinting error:', error);
      throw error;
    }
  }

  /**
   * Analyze GPS location authenticity using advanced algorithms
   */
  private async analyzeGPSAuthenticity(
    location: LocationPoint,
    deviceFingerprint: DeviceFingerprint
  ): Promise<{
    spoofing_detected: boolean;
    mock_location_detected: boolean;
    poor_accuracy: boolean;
    risk_score: number;
    analysis_details: any;
  }> {
    try {
      // Get recent location history for advanced analysis
      const recentHistory = await this.db.sql`
        SELECT location, timestamp_recorded, accuracy_meters
        FROM location_history 
        WHERE user_id = ${deviceFingerprint.user_id} 
          AND timestamp_recorded >= NOW() - INTERVAL '1 hour'
        ORDER BY timestamp_recorded DESC
        LIMIT 5
      `;

      const historyPoints: LocationPoint[] = recentHistory.map(row => ({
        latitude: row.location.y, // PostGIS POINT format
        longitude: row.location.x,
        accuracy: row.accuracy_meters,
        timestamp: new Date(row.timestamp_recorded).getTime()
      }));

      // Use advanced GPS detection algorithms
      const gpsAnalysis = GPSDetectionAlgorithms.analyzeGPSAuthenticity(
        location,
        deviceFingerprint.device_info,
        historyPoints,
        {
          user_agent: deviceFingerprint.user_agent,
          timezone: deviceFingerprint.device_info.timezone
        }
      );

      // Convert advanced analysis to our format
      const riskScore = Math.round(gpsAnalysis.spoofing_probability * 100);
      const spoofingDetected = gpsAnalysis.spoofing_probability > 0.7;
      const mockLocationDetected = gpsAnalysis.detection_methods.signal_analysis.signal_strength_pattern === 'impossible';
      const poorAccuracy = gpsAnalysis.detection_methods.signal_analysis.accuracy_anomaly;

      return {
        spoofing_detected: spoofingDetected,
        mock_location_detected: mockLocationDetected,
        poor_accuracy: poorAccuracy,
        risk_score: riskScore,
        analysis_details: {
          advanced_analysis: gpsAnalysis,
          confidence_score: gpsAnalysis.confidence_score,
          risk_indicators: gpsAnalysis.risk_indicators,
          recommendations: gpsAnalysis.recommendations
        }
      };

    } catch (error) {
      console.error('[AntiF​raud] GPS analysis error:', error);
      // Fallback to basic analysis
      return this.basicGPSAnalysis(location, deviceFingerprint);
    }
  }

  /**
   * Basic GPS analysis fallback
   */
  private basicGPSAnalysis(
    location: LocationPoint,
    deviceFingerprint: DeviceFingerprint
  ): {
    spoofing_detected: boolean;
    mock_location_detected: boolean;
    poor_accuracy: boolean;
    risk_score: number;
    analysis_details: any;
  } {
    let riskScore = 0;
    let spoofingDetected = false;
    let mockLocationDetected = false;
    let poorAccuracy = false;
    const analysisDetails: any = {};

    // Check GPS accuracy
    if (location.accuracy && location.accuracy > DETECTION_RULES.MIN_GPS_ACCURACY) {
      poorAccuracy = true;
      riskScore += DETECTION_RULES.POOR_ACCURACY_PENALTY;
    }

    // Check for impossible precision
    if (location.accuracy && location.accuracy < 1) {
      spoofingDetected = true;
      riskScore += 30;
    }

    // Check coordinate precision
    const latDecimalPlaces = location.latitude.toString().split('.')[1]?.length || 0;
    const lngDecimalPlaces = location.longitude.toString().split('.')[1]?.length || 0;
    
    if (latDecimalPlaces < 4 || lngDecimalPlaces < 4) {
      spoofingDetected = true;
      riskScore += 20;
    }

    // Check timestamp
    if (location.timestamp) {
      const timeDiff = Math.abs(Date.now() - location.timestamp);
      if (timeDiff > 30000) {
        mockLocationDetected = true;
        riskScore += 15;
      }
    }

    return {
      spoofing_detected: spoofingDetected,
      mock_location_detected: mockLocationDetected,
      poor_accuracy: poorAccuracy,
      risk_score: riskScore,
      analysis_details: analysisDetails
    };
  }

  /**
   * Analyze movement patterns for anomalies
   */
  private async analyzeMovementPattern(
    userId: string,
    currentLocation: LocationPoint,
    timestamp: number
  ): Promise<{
    impossible_speed: boolean;
    location_jump: boolean;
    risk_score: number;
    movement_details: any;
  }> {
    let riskScore = 0;
    let impossibleSpeed = false;
    let locationJump = false;
    const movementDetails: any = {};

    try {
      // Get recent location history (last 24 hours)
      const recentHistory = await this.db.sql`
        SELECT location, timestamp_recorded, accuracy_meters
        FROM location_history 
        WHERE user_id = ${userId} 
          AND timestamp_recorded >= NOW() - INTERVAL '24 hours'
        ORDER BY timestamp_recorded DESC
        LIMIT 10
      `;

      if (recentHistory.length > 0) {
        const lastLocation = recentHistory[0];
        const lastLat = lastLocation.location.x; // PostGIS POINT format
        const lastLng = lastLocation.location.y;
        const lastTime = new Date(lastLocation.timestamp_recorded).getTime();

        // Calculate distance and time difference
        const distance = calculateVincentyDistance(
          lastLat, lastLng,
          currentLocation.latitude, currentLocation.longitude
        ) / 1000; // Convert to km

        const timeDiff = (timestamp - lastTime) / 1000; // Convert to seconds
        const hoursDiff = timeDiff / 3600;

        if (timeDiff > 0 && hoursDiff > 0) {
          const speed = distance / hoursDiff; // km/h

          movementDetails.distance_km = distance;
          movementDetails.time_diff_hours = hoursDiff;
          movementDetails.calculated_speed_kmh = speed;

          // Check for impossible speeds
          if (speed > SPEED_LIMITS.IMPOSSIBLE) {
            impossibleSpeed = true;
            riskScore += 50;
            movementDetails.speed_violation = 'impossible';
          } else if (speed > SPEED_LIMITS.DRIVING_MAX) {
            impossibleSpeed = true;
            riskScore += 30;
            movementDetails.speed_violation = 'very_high';
          }

          // Check for location jumps
          if (distance > DETECTION_RULES.MAX_LOCATION_JUMP && timeDiff < DETECTION_RULES.MIN_JUMP_TIME_SECONDS) {
            locationJump = true;
            riskScore += 40;
            movementDetails.location_jump = true;
          }
        }

        // Analyze movement patterns over longer period
        const patternAnalysis = await this.analyzeMovementPatterns(userId, recentHistory);
        riskScore += patternAnalysis.risk_adjustment;
        movementDetails.pattern_analysis = patternAnalysis;
      }

      // Record current location in history
      await this.recordLocationHistory(userId, currentLocation, timestamp);

      return {
        impossible_speed: impossibleSpeed,
        location_jump: locationJump,
        risk_score: riskScore,
        movement_details: movementDetails
      };

    } catch (error) {
      console.error('[AntiF​raud] Movement analysis error:', error);
      return {
        impossible_speed: false,
        location_jump: false,
        risk_score: 0,
        movement_details: { error: error.message }
      };
    }
  }

  /**
   * Analyze behavioral patterns
   */
  private async analyzeBehavioralPatterns(
    userId: string,
    deviceHash: string,
    timestamp: number
  ): Promise<{
    device_inconsistency: boolean;
    rapid_submissions: boolean;
    behavioral_anomaly: boolean;
    risk_score: number;
    behavior_details: any;
  }> {
    let riskScore = 0;
    let deviceInconsistency = false;
    let rapidSubmissions = false;
    let behavioralAnomaly = false;
    const behaviorDetails: any = {};

    try {
      // Check device usage patterns
      const userDevices = await this.db.sql`
        SELECT DISTINCT fingerprint_hash, first_seen, last_seen
        FROM device_fingerprints 
        WHERE user_id = ${userId}
      `;

      behaviorDetails.total_devices = userDevices.length;

      if (userDevices.length > DETECTION_RULES.MAX_DEVICES_PER_USER) {
        deviceInconsistency = true;
        riskScore += DETECTION_RULES.DEVICE_SWITCH_PENALTY * (userDevices.length - DETECTION_RULES.MAX_DEVICES_PER_USER);
        behaviorDetails.excessive_devices = true;
      }

      // Check submission frequency
      const recentSubmissions = await this.db.sql`
        SELECT COUNT(*) as count
        FROM gps_verifications 
        WHERE user_id = ${userId} 
          AND verification_timestamp >= NOW() - INTERVAL '1 hour'
      `;

      const hourlySubmissions = parseInt(recentSubmissions[0]?.count || 0);
      behaviorDetails.submissions_last_hour = hourlySubmissions;

      if (hourlySubmissions > DETECTION_RULES.MAX_SUBMISSIONS_PER_HOUR) {
        rapidSubmissions = true;
        riskScore += DETECTION_RULES.RAPID_SUBMISSION_PENALTY;
        behaviorDetails.rapid_submissions = true;
      }

      // Check daily submission patterns
      const dailySubmissions = await this.db.sql`
        SELECT COUNT(*) as count
        FROM gps_verifications 
        WHERE user_id = ${userId} 
          AND verification_timestamp >= NOW() - INTERVAL '24 hours'
      `;

      const dailyCount = parseInt(dailySubmissions[0]?.count || 0);
      behaviorDetails.submissions_last_24h = dailyCount;

      if (dailyCount > DETECTION_RULES.MAX_SUBMISSIONS_PER_DAY) {
        behavioralAnomaly = true;
        riskScore += DETECTION_RULES.RAPID_SUBMISSION_PENALTY;
        behaviorDetails.excessive_daily_submissions = true;
      }

      // Check submission timing patterns
      const submissionTimes = await this.db.sql`
        SELECT EXTRACT(hour FROM verification_timestamp) as hour,
               COUNT(*) as count
        FROM gps_verifications 
        WHERE user_id = ${userId} 
          AND verification_timestamp >= NOW() - INTERVAL '7 days'
        GROUP BY EXTRACT(hour FROM verification_timestamp)
        ORDER BY hour
      `;

      if (submissionTimes.length > 0) {
        const hourlyDistribution = submissionTimes.map(row => parseInt(row.count));
        const maxHourlySubmissions = Math.max(...hourlyDistribution);
        const avgHourlySubmissions = hourlyDistribution.reduce((a, b) => a + b, 0) / hourlyDistribution.length;
        
        // Detect bot-like regular patterns
        if (maxHourlySubmissions > avgHourlySubmissions * 3) {
          behavioralAnomaly = true;
          riskScore += 15;
          behaviorDetails.irregular_timing_pattern = true;
        }
      }

      return {
        device_inconsistency: deviceInconsistency,
        rapid_submissions: rapidSubmissions,
        behavioral_anomaly: behavioralAnomaly,
        risk_score: riskScore,
        behavior_details: behaviorDetails
      };

    } catch (error) {
      console.error('[AntiF​raud] Behavioral analysis error:', error);
      return {
        device_inconsistency: false,
        rapid_submissions: false,
        behavioral_anomaly: false,
        risk_score: 0,
        behavior_details: { error: error.message }
      };
    }
  }

  /**
   * Make final verification decision based on risk score and factors
   */
  private async makeVerificationDecision(
    riskScore: number,
    riskFactors: VerificationResult['risk_factors']
  ): Promise<{
    status: 'passed' | 'failed' | 'manual_review';
    reason: string;
    manual_review_required: boolean;
    auto_action: 'none' | 'flag' | 'block' | 'suspend';
  }> {
    let status: 'passed' | 'failed' | 'manual_review' = 'passed';
    let reason = 'Location verification passed';
    let manualReviewRequired = false;
    let autoAction: 'none' | 'flag' | 'block' | 'suspend' = 'none';

    try {
      // Critical risk factors that trigger immediate failure
      if (riskFactors.impossible_speed || riskFactors.gps_spoofing_detected) {
        status = 'failed';
        autoAction = 'block';
        reason = 'Critical fraud indicators detected: ';
        const criticalFactors = [];
        if (riskFactors.impossible_speed) criticalFactors.push('impossible travel speed');
        if (riskFactors.gps_spoofing_detected) criticalFactors.push('GPS spoofing');
        reason += criticalFactors.join(', ');
      }
      // High risk score triggers manual review
      else if (riskScore >= RISK_THRESHOLDS.CRITICAL) {
        status = 'manual_review';
        manualReviewRequired = true;
        autoAction = 'flag';
        reason = `High risk score (${riskScore}), requires manual review`;
      }
      // Medium-high risk score triggers failure
      else if (riskScore >= RISK_THRESHOLDS.HIGH) {
        status = 'failed';
        autoAction = 'flag';
        reason = `High risk score (${riskScore}), verification failed`;
      }
      // Medium risk score triggers manual review
      else if (riskScore >= RISK_THRESHOLDS.MEDIUM) {
        status = 'manual_review';
        manualReviewRequired = true;
        reason = `Medium risk score (${riskScore}), requires review`;
      }
      // Low risk passes but may be flagged for monitoring
      else if (riskScore >= RISK_THRESHOLDS.LOW) {
        status = 'passed';
        autoAction = 'flag';
        reason = `Low risk score (${riskScore}), passed with monitoring`;
      }

      return {
        status,
        reason,
        manual_review_required: manualReviewRequired,
        auto_action: autoAction
      };

    } catch (error) {
      console.error('[AntiF​raud] Decision making error:', error);
      return {
        status: 'manual_review',
        reason: 'Error during decision making',
        manual_review_required: true,
        auto_action: 'none'
      };
    }
  }

  /**
   * Helper methods for data persistence and analysis
   */
  private async recordLocationHistory(
    userId: string,
    location: LocationPoint,
    timestamp: number
  ): Promise<void> {
    try {
      await this.db.sql`
        INSERT INTO location_history (
          user_id, location, accuracy_meters, altitude_meters, 
          speed_mps, heading_degrees, timestamp_recorded, source
        )
        VALUES (
          ${userId}, 
          POINT(${location.longitude}, ${location.latitude}),
          ${location.accuracy || null},
          ${location.altitude || null},
          ${location.speed || null},
          ${location.heading || null},
          ${new Date(timestamp).toISOString()},
          'gps'
        )
      `;
    } catch (error) {
      console.error('[AntiF​raud] Failed to record location history:', error);
    }
  }

  private async recordVerificationResult(
    result: VerificationResult,
    deviceHash: string
  ): Promise<void> {
    try {
      await this.db.sql`
        INSERT INTO gps_verifications (
          user_id, annotation_id, submitted_location, verification_method,
          verification_status, risk_score, risk_factors, decision_reason
        )
        VALUES (
          ${result.user_id},
          ${result.annotation_id},
          POINT(${(result.evidence as any).movement_analysis?.current_location?.longitude || 0}, ${(result.evidence as any).movement_analysis?.current_location?.latitude || 0}),
          'comprehensive_analysis',
          ${result.verification_status},
          ${result.risk_score},
          ${JSON.stringify(result.risk_factors)},
          ${result.decision_reason}
        )
      `;
    } catch (error) {
      console.error('[AntiF​raud] Failed to record verification result:', error);
    }
  }

  private async evaluateUserRiskProfile(userId: string): Promise<{ adjustment: number; profile: any }> {
    try {
      // Check cache first
      if (this.userRiskCache.has(userId)) {
        const cached = this.userRiskCache.get(userId)!;
        const cacheAge = Date.now() - cached.last_updated.getTime();
        if (cacheAge < this.CACHE_TTL) {
          const adjustment = this.calculateRiskAdjustment(cached.overall_risk_score);
          return { adjustment, profile: cached };
        }
      }

      // Get or create risk profile using risk assessment service
      const assessmentContext: RiskAssessmentContext = {
        user_id: userId,
        assessment_time: new Date(),
        lookback_period_days: 7,
        include_device_analysis: true,
        include_behavioral_analysis: true,
        include_location_analysis: true
      };

      const assessment = await this.riskAssessment.assessUserRisk(assessmentContext);
      
      // Cache the result
      this.userRiskCache.set(userId, assessment.risk_profile);
      
      const adjustment = this.calculateRiskAdjustment(assessment.risk_profile.overall_risk_score);
      return { adjustment, profile: assessment.risk_profile };

    } catch (error) {
      console.error('[AntiF​raud] User risk evaluation error:', error);
      return { adjustment: 0, profile: {} };
    }
  }

  private async updateUserRiskProfile(userId: string, result: VerificationResult): Promise<void> {
    try {
      // Update risk profile based on verification result
      const existingProfile = await this.db.sql`
        SELECT * FROM user_risk_profiles WHERE user_id = ${userId}
      `;

      if (existingProfile.length > 0) {
        // Update existing profile
        const profile = existingProfile[0];
        let newRiskScore = profile.overall_risk_score;
        
        // Adjust risk score based on verification result
        if (result.verification_status === 'failed') {
          newRiskScore = Math.min(100, newRiskScore + 10);
        } else if (result.verification_status === 'passed' && result.risk_score < 25) {
          newRiskScore = Math.max(0, newRiskScore - 2);
        }

        await this.db.sql`
          UPDATE user_risk_profiles 
          SET overall_risk_score = ${newRiskScore},
              total_submissions = total_submissions + 1,
              verified_submissions = verified_submissions + ${result.verification_status === 'passed' ? 1 : 0},
              last_updated = NOW()
          WHERE user_id = ${userId}
        `;

        // Clear cache to force refresh
        this.userRiskCache.delete(userId);
      }
    } catch (error) {
      console.error('[AntiF​raud] Failed to update user risk profile:', error);
    }
  }

  private async handleFraudIncident(result: VerificationResult): Promise<void> {
    try {
      // Determine incident type and severity
      let incidentType = 'general_fraud';
      let severity = 'medium';

      if (result.risk_factors.gps_spoofing_detected) {
        incidentType = 'gps_spoofing';
        severity = 'high';
      } else if (result.risk_factors.impossible_speed) {
        incidentType = 'impossible_speed';
        severity = 'high';
      } else if (result.risk_factors.device_inconsistency) {
        incidentType = 'device_farming';
        severity = 'medium';
      } else if (result.risk_factors.rapid_submissions) {
        incidentType = 'automated_behavior';
        severity = 'medium';
      }

      // Create fraud incident record
      await this.db.sql`
        INSERT INTO fraud_incidents (
          user_id, annotation_id, incident_type, severity, risk_score,
          evidence, detection_method, status, auto_action_taken,
          manual_review_required, created_at
        ) VALUES (
          ${result.user_id}, ${result.annotation_id}, ${incidentType}, ${severity},
          ${result.risk_score}, ${JSON.stringify(result.evidence)}, 
          'gps_verification_system', 'open', ${result.auto_action},
          ${result.requires_manual_review}, NOW()
        )
      `;

      console.log(`[AntiF​raud] Fraud incident created: ${incidentType} for user ${result.user_id}`);

    } catch (error) {
      console.error('[AntiF​raud] Failed to handle fraud incident:', error);
    }
  }

  private async analyzeMovementPatterns(userId: string, history: any[]): Promise<{ risk_adjustment: number }> {
    try {
      if (history.length < 2) {
        return { risk_adjustment: 0 };
      }

      let riskAdjustment = 0;
      const movements = [];

      // Calculate movement statistics
      for (let i = 1; i < history.length; i++) {
        const prev = history[i - 1];
        const curr = history[i];
        
        const distance = calculateVincentyDistance(
          prev.location.y, prev.location.x,
          curr.location.y, curr.location.x
        ) / 1000; // km

        const timeDiff = (new Date(prev.timestamp_recorded).getTime() - 
                         new Date(curr.timestamp_recorded).getTime()) / (1000 * 3600); // hours

        if (timeDiff > 0) {
          const speed = distance / timeDiff;
          movements.push({ distance, timeDiff, speed });

          // Check for impossible speeds
          if (speed > 300) { // Faster than commercial aircraft
            riskAdjustment += 30;
          } else if (speed > 150) { // Very fast
            riskAdjustment += 15;
          }
        }
      }

      // Analyze pattern regularity
      if (movements.length > 3) {
        const speeds = movements.map(m => m.speed);
        const avgSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
        const variance = speeds.reduce((sum, speed) => sum + Math.pow(speed - avgSpeed, 2), 0) / speeds.length;
        
        // Too consistent speeds are suspicious
        if (variance < 1 && avgSpeed > 5) {
          riskAdjustment += 20;
        }
      }

      return { risk_adjustment: Math.min(riskAdjustment, 50) }; // Cap at 50 points

    } catch (error) {
      console.error('[AntiF​raud] Movement pattern analysis error:', error);
      return { risk_adjustment: 0 };
    }
  }

  private calculateRiskAdjustment(riskScore: number): number {
    // Convert risk score to risk adjustment for verification
    if (riskScore >= 80) return 20;
    if (riskScore >= 60) return 10;
    if (riskScore >= 40) return 5;
    if (riskScore <= 20) return -5;
    return 0;
  }

  /**
   * Public utility methods
   */
  async getUserRiskScore(userId: string): Promise<number> {
    try {
      const profile = await this.db.sql`
        SELECT overall_risk_score FROM user_risk_profiles WHERE user_id = ${userId}
      `;
      return profile[0]?.overall_risk_score || 0;
    } catch (error) {
      console.error('[AntiF​raud] Failed to get user risk score:', error);
      return 0;
    }
  }

  async getRecentFraudIncidents(limit = 10): Promise<any[]> {
    try {
      return await this.db.sql`
        SELECT fi.*, u.username
        FROM fraud_incidents fi
        JOIN users u ON fi.user_id = u.id
        ORDER BY fi.created_at DESC
        LIMIT ${limit}
      `;
    } catch (error) {
      console.error('[AntiF​raud] Failed to get fraud incidents:', error);
      return [];
    }
  }

  async initializeAntiFraudTables(): Promise<boolean> {
    try {
      // This would typically be handled by migrations
      console.log('[AntiF​raud] Tables should be initialized via migrations');
      return true;
    } catch (error) {
      console.error('[AntiF​raud] Failed to initialize tables:', error);
      return false;
    }
  }
}

export default AntiFraudService;