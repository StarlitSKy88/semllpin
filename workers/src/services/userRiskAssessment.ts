/**
 * User Risk Assessment Service
 * Comprehensive user behavior and risk profiling system
 */

import { NeonDatabase } from '../utils/neon-database';
import { Env } from '../index';
import { LocationPoint, VerificationResult, UserRiskProfile } from './antiFraudService';
import { calculateHaversineDistance } from './geofencing';

export interface RiskAssessmentContext {
  user_id: string;
  assessment_time: Date;
  lookback_period_days: number;
  include_device_analysis: boolean;
  include_behavioral_analysis: boolean;
  include_location_analysis: boolean;
}

export interface RiskMetrics {
  submission_frequency: {
    daily_average: number;
    peak_hour: number;
    variance_score: number; // Higher variance = more human-like
  };
  location_patterns: {
    home_location_consistency: number; // 0-1
    travel_radius_km: number;
    unusual_locations_count: number;
    speed_violations_count: number;
  };
  device_patterns: {
    device_count: number;
    device_switching_frequency: number;
    consistent_fingerprint: boolean;
    suspicious_device_changes: number;
  };
  verification_history: {
    total_submissions: number;
    passed_rate: number;
    failed_rate: number;
    manual_review_rate: number;
    avg_risk_score: number;
  };
  temporal_patterns: {
    active_hours: number[];
    timezone_consistency: boolean;
    submission_timing_regularity: number; // 0-1, higher = more regular/bot-like
  };
}

export interface RiskAdjustment {
  factor: string;
  adjustment: number; // +/- risk score points
  reason: string;
}

export class UserRiskAssessmentService {
  private db: NeonDatabase;
  private env: Env;

  constructor(env: Env) {
    this.env = env;
    this.db = new NeonDatabase(env.DATABASE_URL);
  }

  /**
   * Perform comprehensive user risk assessment
   */
  async assessUserRisk(context: RiskAssessmentContext): Promise<{
    risk_profile: UserRiskProfile;
    risk_metrics: RiskMetrics;
    risk_adjustments: RiskAdjustment[];
    recommendations: string[];
  }> {
    try {
      console.log(`[RiskAssessment] Starting assessment for user ${context.user_id}`);

      // Gather user activity data
      const userActivity = await this.gatherUserActivityData(context);
      
      // Calculate risk metrics
      const riskMetrics = await this.calculateRiskMetrics(userActivity, context);
      
      // Calculate base risk score
      let baseRiskScore = this.calculateBaseRiskScore(riskMetrics);
      
      // Apply risk adjustments
      const riskAdjustments = await this.calculateRiskAdjustments(userActivity, riskMetrics, context);
      
      // Apply adjustments to base score
      let finalRiskScore = baseRiskScore;
      for (const adjustment of riskAdjustments) {
        finalRiskScore += adjustment.adjustment;
      }
      finalRiskScore = Math.max(0, Math.min(100, finalRiskScore)); // Clamp to 0-100

      // Determine trust level
      const trustLevel = this.determineTrustLevel(finalRiskScore, riskMetrics);

      // Create or update risk profile
      const riskProfile = await this.createOrUpdateRiskProfile({
        user_id: context.user_id,
        overall_risk_score: finalRiskScore,
        trust_level: trustLevel,
        total_submissions: riskMetrics.verification_history.total_submissions,
        verified_submissions: Math.round(riskMetrics.verification_history.total_submissions * (riskMetrics.verification_history.passed_rate / 100)),
        fraud_incidents_count: await this.getFraudIncidentsCount(context.user_id),
        account_age_days: await this.getAccountAgeDays(context.user_id),
        device_consistency_score: this.calculateDeviceConsistencyScore(riskMetrics.device_patterns),
        location_pattern_score: this.calculateLocationPatternScore(riskMetrics.location_patterns),
        behavioral_score: this.calculateBehavioralScore(riskMetrics.submission_frequency, riskMetrics.temporal_patterns)
      });

      // Generate recommendations
      const recommendations = this.generateRecommendations(finalRiskScore, riskMetrics, riskAdjustments);

      console.log(`[RiskAssessment] Assessment completed for user ${context.user_id}, Risk Score: ${finalRiskScore}`);

      return {
        risk_profile: riskProfile,
        risk_metrics: riskMetrics,
        risk_adjustments: riskAdjustments,
        recommendations: recommendations
      };

    } catch (error) {
      console.error('[RiskAssessment] Assessment error:', error);
      throw error;
    }
  }

  /**
   * Gather comprehensive user activity data
   */
  private async gatherUserActivityData(context: RiskAssessmentContext): Promise<any> {
    const lookbackDate = new Date(context.assessment_time);
    lookbackDate.setDate(lookbackDate.getDate() - context.lookback_period_days);

    // Get verification history
    const verifications = await this.db.sql`
      SELECT verification_status, risk_score, verification_timestamp, 
             submitted_location, risk_factors
      FROM gps_verifications 
      WHERE user_id = ${context.user_id} 
        AND verification_timestamp >= ${lookbackDate.toISOString()}
      ORDER BY verification_timestamp DESC
    `;

    // Get location history
    const locations = await this.db.sql`
      SELECT location, timestamp_recorded, accuracy_meters, speed_mps
      FROM location_history 
      WHERE user_id = ${context.user_id} 
        AND timestamp_recorded >= ${lookbackDate.toISOString()}
      ORDER BY timestamp_recorded DESC
    `;

    // Get device history
    const devices = await this.db.sql`
      SELECT fingerprint_hash, device_info, first_seen, last_seen, risk_score
      FROM device_fingerprints 
      WHERE user_id = ${context.user_id}
      ORDER BY first_seen DESC
    `;

    // Get fraud incidents
    const fraudIncidents = await this.db.sql`
      SELECT incident_type, severity, risk_score, created_at
      FROM fraud_incidents 
      WHERE user_id = ${context.user_id} 
        AND created_at >= ${lookbackDate.toISOString()}
      ORDER BY created_at DESC
    `;

    // Get user account info
    const userInfo = await this.db.sql`
      SELECT created_at, email_verified, status, role
      FROM users 
      WHERE id = ${context.user_id}
    `;

    return {
      verifications: verifications || [],
      locations: locations || [],
      devices: devices || [],
      fraud_incidents: fraudIncidents || [],
      user_info: userInfo[0] || null
    };
  }

  /**
   * Calculate comprehensive risk metrics
   */
  private async calculateRiskMetrics(userActivity: any, context: RiskAssessmentContext): Promise<RiskMetrics> {
    const verifications = userActivity.verifications;
    const locations = userActivity.locations;
    const devices = userActivity.devices;

    // Submission frequency analysis
    const submissionFrequency = this.analyzeSubmissionFrequency(verifications, context.lookback_period_days);
    
    // Location pattern analysis
    const locationPatterns = this.analyzeLocationPatterns(locations);
    
    // Device pattern analysis
    const devicePatterns = this.analyzeDevicePatterns(devices);
    
    // Verification history analysis
    const verificationHistory = this.analyzeVerificationHistory(verifications);
    
    // Temporal pattern analysis
    const temporalPatterns = this.analyzeTemporalPatterns(verifications);

    return {
      submission_frequency: submissionFrequency,
      location_patterns: locationPatterns,
      device_patterns: devicePatterns,
      verification_history: verificationHistory,
      temporal_patterns: temporalPatterns
    };
  }

  private analyzeSubmissionFrequency(verifications: any[], lookbackDays: number): RiskMetrics['submission_frequency'] {
    if (verifications.length === 0) {
      return { daily_average: 0, peak_hour: 12, variance_score: 1 };
    }

    const dailyAverage = verifications.length / lookbackDays;
    
    // Analyze hourly distribution
    const hourlySubmissions = new Array(24).fill(0);
    verifications.forEach(v => {
      const hour = new Date(v.verification_timestamp).getHours();
      hourlySubmissions[hour]++;
    });
    
    const peakHour = hourlySubmissions.indexOf(Math.max(...hourlySubmissions));
    
    // Calculate variance (higher variance = more human-like)
    const avgHourly = verifications.length / 24;
    const variance = hourlySubmissions.reduce((sum, count) => sum + Math.pow(count - avgHourly, 2), 0) / 24;
    const varianceScore = Math.min(variance / 10, 1); // Normalize to 0-1

    return {
      daily_average: dailyAverage,
      peak_hour: peakHour,
      variance_score: varianceScore
    };
  }

  private analyzeLocationPatterns(locations: any[]): RiskMetrics['location_patterns'] {
    if (locations.length < 2) {
      return {
        home_location_consistency: 1,
        travel_radius_km: 0,
        unusual_locations_count: 0,
        speed_violations_count: 0
      };
    }

    // Find most common location (home base)
    const locationClusters = this.clusterLocations(locations);
    const homeLocation = locationClusters[0]; // Most frequent cluster
    
    // Calculate consistency with home location
    const homeDistance = locations.map(loc => {
      const lat = typeof loc.location === 'object' ? loc.location.y : parseFloat(loc.location.split(',')[1]);
      const lng = typeof loc.location === 'object' ? loc.location.x : parseFloat(loc.location.split(',')[0]);
      return calculateHaversineDistance(homeLocation.lat, homeLocation.lng, lat, lng) / 1000; // km
    });
    
    const avgHomeDistance = homeDistance.reduce((a, b) => a + b, 0) / homeDistance.length;
    const homeConsistency = Math.max(0, 1 - (avgHomeDistance / 50)); // 50km threshold
    
    // Calculate travel radius
    const maxDistance = Math.max(...homeDistance);
    
    // Count unusual locations (far from clusters)
    const unusualCount = homeDistance.filter(d => d > 100).length; // More than 100km
    
    // Count speed violations (if speed data available)
    let speedViolations = 0;
    for (let i = 1; i < locations.length; i++) {
      if (locations[i].speed_mps && locations[i].speed_mps > 83) { // > 300 km/h
        speedViolations++;
      }
    }

    return {
      home_location_consistency: homeConsistency,
      travel_radius_km: maxDistance,
      unusual_locations_count: unusualCount,
      speed_violations_count: speedViolations
    };
  }

  private analyzeDevicePatterns(devices: any[]): RiskMetrics['device_patterns'] {
    if (devices.length === 0) {
      return {
        device_count: 0,
        device_switching_frequency: 0,
        consistent_fingerprint: true,
        suspicious_device_changes: 0
      };
    }

    const deviceCount = devices.length;
    
    // Calculate switching frequency (devices used in short time periods)
    const recentDevices = devices.filter(d => {
      const daysSince = (Date.now() - new Date(d.last_seen).getTime()) / (1000 * 60 * 60 * 24);
      return daysSince <= 7; // Last 7 days
    });
    const switchingFrequency = recentDevices.length > 1 ? recentDevices.length / 7 : 0;
    
    // Check fingerprint consistency
    const uniqueFingerprints = new Set(devices.map(d => d.fingerprint_hash));
    const consistentFingerprint = uniqueFingerprints.size <= 3; // Allow up to 3 different fingerprints
    
    // Count suspicious device changes (too many devices in short time)
    const suspiciousChanges = deviceCount > 5 ? deviceCount - 5 : 0;

    return {
      device_count: deviceCount,
      device_switching_frequency: switchingFrequency,
      consistent_fingerprint: consistentFingerprint,
      suspicious_device_changes: suspiciousChanges
    };
  }

  private analyzeVerificationHistory(verifications: any[]): RiskMetrics['verification_history'] {
    if (verifications.length === 0) {
      return {
        total_submissions: 0,
        passed_rate: 100,
        failed_rate: 0,
        manual_review_rate: 0,
        avg_risk_score: 0
      };
    }

    const totalSubmissions = verifications.length;
    const passedCount = verifications.filter(v => v.verification_status === 'passed').length;
    const failedCount = verifications.filter(v => v.verification_status === 'failed').length;
    const reviewCount = verifications.filter(v => v.verification_status === 'manual_review').length;
    
    const passedRate = (passedCount / totalSubmissions) * 100;
    const failedRate = (failedCount / totalSubmissions) * 100;
    const reviewRate = (reviewCount / totalSubmissions) * 100;
    
    const avgRiskScore = verifications.reduce((sum, v) => sum + (v.risk_score || 0), 0) / totalSubmissions;

    return {
      total_submissions: totalSubmissions,
      passed_rate: passedRate,
      failed_rate: failedRate,
      manual_review_rate: reviewRate,
      avg_risk_score: avgRiskScore
    };
  }

  private analyzeTemporalPatterns(verifications: any[]): RiskMetrics['temporal_patterns'] {
    if (verifications.length === 0) {
      return {
        active_hours: [],
        timezone_consistency: true,
        submission_timing_regularity: 0
      };
    }

    // Find active hours
    const hourCounts = new Array(24).fill(0);
    verifications.forEach(v => {
      const hour = new Date(v.verification_timestamp).getHours();
      hourCounts[hour]++;
    });
    
    const activeHours = hourCounts
      .map((count, hour) => ({ hour, count }))
      .filter(h => h.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 8) // Top 8 active hours
      .map(h => h.hour);

    // Analyze timing regularity (bot detection)
    const intervals = [];
    for (let i = 1; i < verifications.length; i++) {
      const diff = new Date(verifications[i-1].verification_timestamp).getTime() - 
                   new Date(verifications[i].verification_timestamp).getTime();
      intervals.push(diff);
    }
    
    let regularity = 0;
    if (intervals.length > 2) {
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
      const variance = intervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
      regularity = Math.max(0, 1 - (Math.sqrt(variance) / avgInterval)); // High regularity = bot-like
    }

    return {
      active_hours: activeHours,
      timezone_consistency: true, // Would need timezone data to calculate
      submission_timing_regularity: regularity
    };
  }

  private calculateBaseRiskScore(metrics: RiskMetrics): number {
    let riskScore = 0;

    // Submission frequency risk (0-25 points)
    if (metrics.submission_frequency.daily_average > 20) riskScore += 20;
    else if (metrics.submission_frequency.daily_average > 10) riskScore += 10;
    else if (metrics.submission_frequency.daily_average > 5) riskScore += 5;
    
    if (metrics.submission_frequency.variance_score < 0.2) riskScore += 15; // Too regular

    // Location pattern risk (0-25 points)
    if (metrics.location_patterns.speed_violations_count > 0) riskScore += 20;
    if (metrics.location_patterns.unusual_locations_count > 5) riskScore += 10;
    if (metrics.location_patterns.home_location_consistency < 0.3) riskScore += 10;

    // Device pattern risk (0-25 points)
    if (metrics.device_patterns.device_count > 5) riskScore += 15;
    if (metrics.device_patterns.suspicious_device_changes > 0) riskScore += 10;
    if (!metrics.device_patterns.consistent_fingerprint) riskScore += 10;

    // Verification history risk (0-25 points)
    if (metrics.verification_history.failed_rate > 20) riskScore += 20;
    else if (metrics.verification_history.failed_rate > 10) riskScore += 10;
    
    if (metrics.verification_history.avg_risk_score > 50) riskScore += 15;

    return Math.min(riskScore, 100);
  }

  // Utility methods
  private clusterLocations(locations: any[]): Array<{lat: number, lng: number, count: number}> {
    // Simple clustering - in production, use more sophisticated algorithms
    const clusters: Array<{lat: number, lng: number, count: number}> = [];
    
    locations.forEach(loc => {
      const lat = typeof loc.location === 'object' ? loc.location.y : parseFloat(loc.location.split(',')[1]);
      const lng = typeof loc.location === 'object' ? loc.location.x : parseFloat(loc.location.split(',')[0]);
      
      // Find existing cluster within 1km
      let foundCluster = false;
      for (const cluster of clusters) {
        const distance = calculateHaversineDistance(lat, lng, cluster.lat, cluster.lng);
        if (distance < 1000) { // 1km
          cluster.count++;
          foundCluster = true;
          break;
        }
      }
      
      if (!foundCluster) {
        clusters.push({ lat, lng, count: 1 });
      }
    });
    
    return clusters.sort((a, b) => b.count - a.count);
  }

  private async calculateRiskAdjustments(userActivity: any, metrics: RiskMetrics, context: RiskAssessmentContext): Promise<RiskAdjustment[]> {
    const adjustments: RiskAdjustment[] = [];

    // Account age adjustment
    const accountAgeDays = await this.getAccountAgeDays(context.user_id);
    if (accountAgeDays < 7) {
      adjustments.push({
        factor: 'account_age',
        adjustment: 15,
        reason: 'New account (less than 7 days old)'
      });
    } else if (accountAgeDays > 365) {
      adjustments.push({
        factor: 'account_age',
        adjustment: -5,
        reason: 'Established account (more than 1 year old)'
      });
    }

    // Verification success rate adjustment
    if (metrics.verification_history.passed_rate > 95 && metrics.verification_history.total_submissions > 10) {
      adjustments.push({
        factor: 'high_success_rate',
        adjustment: -10,
        reason: 'High verification success rate with sufficient history'
      });
    }

    // Fraud incidents penalty
    const fraudCount = await this.getFraudIncidentsCount(context.user_id);
    if (fraudCount > 0) {
      adjustments.push({
        factor: 'fraud_history',
        adjustment: fraudCount * 25,
        reason: `Previous fraud incidents detected (${fraudCount})`
      });
    }

    return adjustments;
  }

  private determineTrustLevel(riskScore: number, metrics: RiskMetrics): 'trusted' | 'neutral' | 'suspicious' | 'blocked' {
    if (riskScore >= 90 || metrics.verification_history.failed_rate > 50) return 'blocked';
    if (riskScore >= 70 || metrics.verification_history.failed_rate > 25) return 'suspicious';
    if (riskScore <= 25 && metrics.verification_history.passed_rate > 90) return 'trusted';
    return 'neutral';
  }

  private async createOrUpdateRiskProfile(profileData: Partial<UserRiskProfile>): Promise<UserRiskProfile> {
    try {
      const existingProfile = await this.db.sql`
        SELECT * FROM user_risk_profiles WHERE user_id = ${profileData.user_id}
      `;

      let result;
      if (existingProfile.length > 0) {
        // Update existing profile
        result = await this.db.sql`
          UPDATE user_risk_profiles 
          SET overall_risk_score = ${profileData.overall_risk_score},
              trust_level = ${profileData.trust_level},
              total_submissions = ${profileData.total_submissions},
              verified_submissions = ${profileData.verified_submissions},
              fraud_incidents_count = ${profileData.fraud_incidents_count},
              account_age_days = ${profileData.account_age_days},
              device_consistency_score = ${profileData.device_consistency_score},
              location_pattern_score = ${profileData.location_pattern_score},
              behavioral_score = ${profileData.behavioral_score},
              last_updated = NOW()
          WHERE user_id = ${profileData.user_id}
          RETURNING *
        `;
      } else {
        // Create new profile
        result = await this.db.sql`
          INSERT INTO user_risk_profiles (
            user_id, overall_risk_score, trust_level, total_submissions,
            verified_submissions, fraud_incidents_count, account_age_days,
            device_consistency_score, location_pattern_score, behavioral_score,
            last_updated, created_at
          ) VALUES (
            ${profileData.user_id}, ${profileData.overall_risk_score}, ${profileData.trust_level},
            ${profileData.total_submissions}, ${profileData.verified_submissions}, ${profileData.fraud_incidents_count},
            ${profileData.account_age_days}, ${profileData.device_consistency_score}, ${profileData.location_pattern_score},
            ${profileData.behavioral_score}, NOW(), NOW()
          ) RETURNING *
        `;
      }

      return {
        user_id: result[0].user_id,
        overall_risk_score: result[0].overall_risk_score,
        trust_level: result[0].trust_level,
        total_submissions: result[0].total_submissions,
        verified_submissions: result[0].verified_submissions,
        fraud_incidents_count: result[0].fraud_incidents_count,
        account_age_days: result[0].account_age_days,
        device_consistency_score: result[0].device_consistency_score,
        location_pattern_score: result[0].location_pattern_score,
        behavioral_score: result[0].behavioral_score,
        last_updated: new Date(result[0].last_updated)
      };
    } catch (error) {
      console.error('[RiskAssessment] Failed to create/update risk profile:', error);
      throw error;
    }
  }

  private generateRecommendations(riskScore: number, metrics: RiskMetrics, adjustments: RiskAdjustment[]): string[] {
    const recommendations: string[] = [];

    if (riskScore >= 90) {
      recommendations.push('BLOCK - Critical risk level detected');
      recommendations.push('Suspend user account pending investigation');
    } else if (riskScore >= 70) {
      recommendations.push('HIGH RISK - All submissions require manual review');
      recommendations.push('Flag account for enhanced monitoring');
    } else if (riskScore >= 50) {
      recommendations.push('MEDIUM RISK - Random manual review recommended');
      recommendations.push('Monitor for pattern changes');
    } else if (riskScore >= 25) {
      recommendations.push('LOW RISK - Standard processing with monitoring');
    } else {
      recommendations.push('MINIMAL RISK - Standard processing');
    }

    // Specific recommendations based on metrics
    if (metrics.device_patterns.device_count > 5) {
      recommendations.push('Investigate multiple device usage patterns');
    }
    
    if (metrics.verification_history.failed_rate > 20) {
      recommendations.push('Review historical failed verifications for patterns');
    }
    
    if (metrics.submission_frequency.daily_average > 10) {
      recommendations.push('Monitor for automated/bot behavior');
    }

    return recommendations;
  }

  // Helper methods
  private async getAccountAgeDays(userId: string): Promise<number> {
    try {
      const result = await this.db.sql`
        SELECT created_at FROM users WHERE id = ${userId}
      `;
      if (result.length > 0) {
        const createdAt = new Date(result[0].created_at);
        const now = new Date();
        return Math.floor((now.getTime() - createdAt.getTime()) / (1000 * 60 * 60 * 24));
      }
      return 0;
    } catch (error) {
      console.error('[RiskAssessment] Failed to get account age:', error);
      return 0;
    }
  }

  private async getFraudIncidentsCount(userId: string): Promise<number> {
    try {
      const result = await this.db.sql`
        SELECT COUNT(*) as count FROM fraud_incidents 
        WHERE user_id = ${userId} AND status IN ('confirmed', 'open')
      `;
      return parseInt(result[0]?.count || 0);
    } catch (error) {
      console.error('[RiskAssessment] Failed to get fraud incidents count:', error);
      return 0;
    }
  }

  private calculateDeviceConsistencyScore(patterns: RiskMetrics['device_patterns']): number {
    let score = 100;
    
    if (patterns.device_count > 3) score -= (patterns.device_count - 3) * 10;
    if (!patterns.consistent_fingerprint) score -= 20;
    if (patterns.suspicious_device_changes > 0) score -= patterns.suspicious_device_changes * 15;
    
    return Math.max(0, score);
  }

  private calculateLocationPatternScore(patterns: RiskMetrics['location_patterns']): number {
    let score = patterns.home_location_consistency * 100;
    
    if (patterns.speed_violations_count > 0) score -= patterns.speed_violations_count * 20;
    if (patterns.unusual_locations_count > 5) score -= (patterns.unusual_locations_count - 5) * 5;
    
    return Math.max(0, Math.min(100, score));
  }

  private calculateBehavioralScore(frequency: RiskMetrics['submission_frequency'], temporal: RiskMetrics['temporal_patterns']): number {
    let score = 50; // Base score
    
    // Variance in submission timing is good (more human-like)
    score += frequency.variance_score * 30;
    
    // Too regular timing is suspicious
    if (temporal.submission_timing_regularity > 0.8) score -= 30;
    
    // Reasonable submission frequency is good
    if (frequency.daily_average <= 10 && frequency.daily_average > 0) score += 20;
    
    return Math.max(0, Math.min(100, score));
  }
}

export default UserRiskAssessmentService;