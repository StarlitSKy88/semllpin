-- Create anti-fraud system tables for GPS location verification
-- Part of SmellPin's comprehensive security system

-- 1. Device fingerprints table for tracking unique devices
CREATE TABLE IF NOT EXISTS device_fingerprints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of device characteristics
    device_info JSONB NOT NULL DEFAULT '{}', -- Device characteristics (browser, OS, screen, etc.)
    ip_address INET,
    user_agent TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_trusted BOOLEAN DEFAULT false,
    risk_score INTEGER DEFAULT 0, -- 0-100, higher means more risky
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(fingerprint_hash)
);

-- 2. Location history table for tracking user movements
CREATE TABLE IF NOT EXISTS location_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint_id UUID REFERENCES device_fingerprints(id) ON DELETE SET NULL,
    location POINT NOT NULL, -- PostGIS point (longitude, latitude)
    accuracy_meters REAL, -- GPS accuracy in meters
    altitude_meters REAL, -- Altitude if available
    speed_mps REAL, -- Speed in meters per second
    heading_degrees REAL, -- Direction in degrees
    timestamp_recorded TIMESTAMP WITH TIME ZONE NOT NULL,
    timestamp_server TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    source VARCHAR(50) DEFAULT 'gps', -- 'gps', 'network', 'passive'
    is_mock_location BOOLEAN DEFAULT false,
    risk_indicators JSONB DEFAULT '{}', -- Various risk flags
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. GPS verification events table
CREATE TABLE IF NOT EXISTS gps_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint_id UUID REFERENCES device_fingerprints(id) ON DELETE SET NULL,
    annotation_id UUID REFERENCES annotations(id) ON DELETE CASCADE,
    submitted_location POINT NOT NULL,
    verified_location POINT,
    verification_method VARCHAR(50) NOT NULL, -- 'gps_analysis', 'behavioral', 'device_correlation'
    verification_status VARCHAR(20) NOT NULL DEFAULT 'pending', -- 'passed', 'failed', 'pending', 'manual_review'
    risk_score INTEGER NOT NULL DEFAULT 0, -- 0-100
    risk_factors JSONB DEFAULT '{}', -- Detailed risk analysis
    verification_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    decision_reason TEXT,
    reviewed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Movement analysis table for tracking suspicious patterns
CREATE TABLE IF NOT EXISTS movement_analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    analysis_window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    analysis_window_end TIMESTAMP WITH TIME ZONE NOT NULL,
    total_distance_km REAL NOT NULL DEFAULT 0,
    max_speed_kmh REAL NOT NULL DEFAULT 0,
    avg_speed_kmh REAL NOT NULL DEFAULT 0,
    location_changes_count INTEGER DEFAULT 0,
    suspicious_jumps_count INTEGER DEFAULT 0, -- Teleportation-like movements
    stationary_periods_count INTEGER DEFAULT 0,
    pattern_anomalies JSONB DEFAULT '{}',
    risk_score INTEGER NOT NULL DEFAULT 0,
    analysis_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. Anti-fraud rules table for configurable detection rules
CREATE TABLE IF NOT EXISTS antifraud_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_name VARCHAR(100) NOT NULL UNIQUE,
    rule_type VARCHAR(50) NOT NULL, -- 'speed_limit', 'location_jump', 'device_switching', etc.
    rule_config JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    severity VARCHAR(20) DEFAULT 'medium', -- 'low', 'medium', 'high', 'critical'
    action VARCHAR(50) DEFAULT 'flag', -- 'flag', 'block', 'manual_review'
    description TEXT,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6. Fraud incidents table for tracking detected fraud attempts
CREATE TABLE IF NOT EXISTS fraud_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint_id UUID REFERENCES device_fingerprints(id) ON DELETE SET NULL,
    annotation_id UUID REFERENCES annotations(id) ON DELETE CASCADE,
    incident_type VARCHAR(50) NOT NULL, -- 'gps_spoofing', 'impossible_speed', 'device_farming', etc.
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    risk_score INTEGER NOT NULL DEFAULT 0,
    evidence JSONB DEFAULT '{}', -- Detailed evidence of fraud
    detection_method VARCHAR(100), -- Which rule/algorithm detected this
    status VARCHAR(20) DEFAULT 'open', -- 'open', 'investigating', 'confirmed', 'false_positive', 'resolved'
    auto_action_taken VARCHAR(50), -- 'none', 'flag_user', 'block_submission', 'suspend_account'
    manual_review_required BOOLEAN DEFAULT false,
    investigated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    investigation_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 7. User risk profiles table for ongoing risk assessment
CREATE TABLE IF NOT EXISTS user_risk_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    overall_risk_score INTEGER NOT NULL DEFAULT 0, -- 0-100
    trust_level VARCHAR(20) DEFAULT 'neutral', -- 'trusted', 'neutral', 'suspicious', 'blocked'
    total_submissions INTEGER DEFAULT 0,
    verified_submissions INTEGER DEFAULT 0,
    fraud_incidents_count INTEGER DEFAULT 0,
    last_incident_date TIMESTAMP WITH TIME ZONE,
    account_age_days INTEGER DEFAULT 0,
    device_consistency_score INTEGER DEFAULT 100, -- How consistent are user's devices
    location_pattern_score INTEGER DEFAULT 50, -- How normal are location patterns
    behavioral_score INTEGER DEFAULT 50, -- Behavioral analysis score
    manual_adjustments JSONB DEFAULT '{}', -- Admin manual risk adjustments
    risk_history JSONB DEFAULT '[]', -- Historical risk scores
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for optimal performance
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_user_id ON device_fingerprints(user_id);
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_hash ON device_fingerprints(fingerprint_hash);
CREATE INDEX IF NOT EXISTS idx_device_fingerprints_last_seen ON device_fingerprints(last_seen);

CREATE INDEX IF NOT EXISTS idx_location_history_user_id ON location_history(user_id);
CREATE INDEX IF NOT EXISTS idx_location_history_timestamp ON location_history(timestamp_recorded);
CREATE INDEX IF NOT EXISTS idx_location_history_location ON location_history USING GIST(location);
CREATE INDEX IF NOT EXISTS idx_location_history_device ON location_history(device_fingerprint_id);

CREATE INDEX IF NOT EXISTS idx_gps_verifications_user_id ON gps_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_gps_verifications_annotation ON gps_verifications(annotation_id);
CREATE INDEX IF NOT EXISTS idx_gps_verifications_status ON gps_verifications(verification_status);
CREATE INDEX IF NOT EXISTS idx_gps_verifications_timestamp ON gps_verifications(verification_timestamp);

CREATE INDEX IF NOT EXISTS idx_movement_analysis_user_id ON movement_analysis(user_id);
CREATE INDEX IF NOT EXISTS idx_movement_analysis_window ON movement_analysis(analysis_window_start, analysis_window_end);
CREATE INDEX IF NOT EXISTS idx_movement_analysis_risk_score ON movement_analysis(risk_score);

CREATE INDEX IF NOT EXISTS idx_antifraud_rules_active ON antifraud_rules(is_active);
CREATE INDEX IF NOT EXISTS idx_antifraud_rules_type ON antifraud_rules(rule_type);

CREATE INDEX IF NOT EXISTS idx_fraud_incidents_user_id ON fraud_incidents(user_id);
CREATE INDEX IF NOT EXISTS idx_fraud_incidents_type ON fraud_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_fraud_incidents_status ON fraud_incidents(status);
CREATE INDEX IF NOT EXISTS idx_fraud_incidents_created ON fraud_incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_fraud_incidents_severity ON fraud_incidents(severity);

CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_user_id ON user_risk_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_risk_score ON user_risk_profiles(overall_risk_score);
CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_trust_level ON user_risk_profiles(trust_level);

-- Insert default anti-fraud rules
INSERT INTO antifraud_rules (rule_name, rule_type, rule_config, description, severity, created_by) VALUES
('Max Speed Limit', 'speed_limit', '{"max_speed_kmh": 300, "time_window_minutes": 5}', 'Detect impossible travel speeds between locations', 'high', (SELECT id FROM users WHERE email = 'admin@smellpin.com' LIMIT 1))
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO antifraud_rules (rule_name, rule_type, rule_config, description, severity, created_by) VALUES
('Location Jump Detection', 'location_jump', '{"max_distance_km": 100, "min_time_seconds": 60}', 'Detect sudden large distance jumps', 'high', (SELECT id FROM users WHERE email = 'admin@smellpin.com' LIMIT 1))
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO antifraud_rules (rule_name, rule_type, rule_config, description, severity, created_by) VALUES
('Mock Location Detection', 'mock_location', '{"check_developer_options": true, "check_location_mocking_apps": true}', 'Detect mock/fake GPS locations', 'critical', (SELECT id FROM users WHERE email = 'admin@smellpin.com' LIMIT 1))
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO antifraud_rules (rule_name, rule_type, rule_config, description, severity, created_by) VALUES
('Device Farming Detection', 'device_farming', '{"max_devices_per_user": 3, "time_window_hours": 24}', 'Detect users using multiple devices suspiciously', 'medium', (SELECT id FROM users WHERE email = 'admin@smellpin.com' LIMIT 1))
ON CONFLICT (rule_name) DO NOTHING;

INSERT INTO antifraud_rules (rule_name, rule_type, rule_config, description, severity, created_by) VALUES
('Rapid Submission Detection', 'rapid_submission', '{"max_submissions_per_hour": 10, "max_submissions_per_day": 50}', 'Detect users making too many submissions too quickly', 'medium', (SELECT id FROM users WHERE email = 'admin@smellpin.com' LIMIT 1))
ON CONFLICT (rule_name) DO NOTHING;

COMMENT ON TABLE device_fingerprints IS 'Tracks unique device characteristics for fraud detection';
COMMENT ON TABLE location_history IS 'Comprehensive location tracking with accuracy and movement data';
COMMENT ON TABLE gps_verifications IS 'GPS verification results for each annotation submission';
COMMENT ON TABLE movement_analysis IS 'Analysis of user movement patterns over time';
COMMENT ON TABLE antifraud_rules IS 'Configurable rules for fraud detection';
COMMENT ON TABLE fraud_incidents IS 'Record of detected fraud attempts and investigations';
COMMENT ON TABLE user_risk_profiles IS 'Ongoing risk assessment for each user';