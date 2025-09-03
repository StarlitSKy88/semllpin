-- SmellPin Data Integrity Verification & Constraint System
-- Purpose: Ensure data consistency, prevent corruption, and maintain referential integrity
-- Focus: Critical business logic constraints and validation

-- ============================================================================
-- ENHANCED DATA INTEGRITY CONSTRAINTS
-- ============================================================================

-- User system constraints
ALTER TABLE users 
    ADD CONSTRAINT check_email_format 
    CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    
    ADD CONSTRAINT check_username_length 
    CHECK (length(username) >= 3 AND length(username) <= 50),
    
    ADD CONSTRAINT check_username_format 
    CHECK (username ~ '^[A-Za-z0-9_]+$'),
    
    ADD CONSTRAINT check_phone_format 
    CHECK (phone IS NULL OR phone ~ '^\+?[1-9]\d{1,14}$'),
    
    ADD CONSTRAINT check_login_count_positive 
    CHECK (login_count >= 0),
    
    ADD CONSTRAINT check_failed_attempts_reasonable 
    CHECK (failed_login_attempts >= 0 AND failed_login_attempts <= 10);

-- User profiles constraints
ALTER TABLE user_profiles
    ADD CONSTRAINT check_level_range 
    CHECK (level >= 1 AND level <= 100),
    
    ADD CONSTRAINT check_experience_points_positive 
    CHECK (experience_points >= 0),
    
    ADD CONSTRAINT check_graduation_year_reasonable 
    CHECK (graduation_year IS NULL OR (graduation_year >= 1950 AND graduation_year <= EXTRACT(YEAR FROM CURRENT_DATE) + 10)),
    
    ADD CONSTRAINT check_follower_count_positive 
    CHECK (followers_count >= 0),
    
    ADD CONSTRAINT check_following_count_positive 
    CHECK (following_count >= 0),
    
    ADD CONSTRAINT check_total_rewards_positive 
    CHECK (total_rewards_earned >= 0);

-- Wallet system constraints
ALTER TABLE wallets
    ADD CONSTRAINT check_balance_consistency 
    CHECK (available_balance + pending_balance + frozen_balance >= 0),
    
    ADD CONSTRAINT check_lifetime_totals_consistency 
    CHECK (total_earned >= 0 AND total_spent >= 0 AND total_withdrawn >= 0 AND total_deposited >= 0),
    
    ADD CONSTRAINT check_wallet_version_positive 
    CHECK (wallet_version > 0);

-- Annotation system constraints
ALTER TABLE annotations
    ADD CONSTRAINT check_title_length 
    CHECK (title IS NULL OR length(title) <= 200),
    
    ADD CONSTRAINT check_content_not_empty 
    CHECK (length(trim(content)) > 0),
    
    ADD CONSTRAINT check_smell_intensity_valid 
    CHECK (smell_intensity IS NULL OR (smell_intensity >= 1 AND smell_intensity <= 10)),
    
    ADD CONSTRAINT check_air_quality_valid 
    CHECK (air_quality_index IS NULL OR (air_quality_index >= 0 AND air_quality_index <= 500)),
    
    ADD CONSTRAINT check_temperature_reasonable 
    CHECK (temperature_celsius IS NULL OR (temperature_celsius >= -50 AND temperature_celsius <= 70)),
    
    ADD CONSTRAINT check_humidity_valid 
    CHECK (humidity_percent IS NULL OR (humidity_percent >= 0 AND humidity_percent <= 100)),
    
    ADD CONSTRAINT check_engagement_metrics_positive 
    CHECK (view_count >= 0 AND like_count >= 0 AND comment_count >= 0 AND share_count >= 0 AND report_count >= 0),
    
    ADD CONSTRAINT check_payment_amount_positive 
    CHECK (payment_amount >= 0),
    
    ADD CONSTRAINT check_reward_pool_positive 
    CHECK (reward_pool_balance >= 0 AND reward_pool_total >= 0),
    
    ADD CONSTRAINT check_participants_count_positive 
    CHECK (participants_count >= 0),
    
    ADD CONSTRAINT check_cleanup_duration_positive 
    CHECK (cleanup_duration_minutes >= 0);

-- Geographic constraints for annotations
ALTER TABLE annotations
    ADD CONSTRAINT check_location_not_null 
    CHECK (location IS NOT NULL),
    
    ADD CONSTRAINT check_location_accuracy_reasonable 
    CHECK (location_accuracy IS NULL OR (location_accuracy >= 0 AND location_accuracy <= 10000));

-- Transaction constraints
ALTER TABLE transactions
    ADD CONSTRAINT check_amount_not_zero 
    CHECK (amount != 0),
    
    ADD CONSTRAINT check_fee_amount_positive 
    CHECK (fee_amount >= 0),
    
    ADD CONSTRAINT check_external_transaction_id_format 
    CHECK (external_transaction_id IS NULL OR length(external_transaction_id) >= 5);

-- LBS reward constraints
ALTER TABLE lbs_rewards
    ADD CONSTRAINT check_reward_amounts_positive 
    CHECK (base_amount >= 0 AND bonus_amount >= 0 AND final_amount >= 0),
    
    ADD CONSTRAINT check_final_amount_consistency 
    CHECK (final_amount <= base_amount + bonus_amount + 10), -- Allow some calculation tolerance
    
    ADD CONSTRAINT check_duration_positive 
    CHECK (duration_minutes >= 0),
    
    ADD CONSTRAINT check_time_decay_factor_valid 
    CHECK (time_decay_factor >= 0 AND time_decay_factor <= 2.0),
    
    ADD CONSTRAINT check_discovery_bonus_reasonable 
    CHECK (discovery_bonus >= 0 AND discovery_bonus <= base_amount * 2),
    
    ADD CONSTRAINT check_social_multiplier_reasonable 
    CHECK (social_multiplier >= 0.1 AND social_multiplier <= 5.0),
    
    ADD CONSTRAINT check_session_time_order 
    CHECK (session_end_time IS NULL OR session_end_time >= session_start_time);

-- Geofence constraints
ALTER TABLE geofence_configs
    ADD CONSTRAINT check_radius_reasonable 
    CHECK (radius_meters > 0 AND radius_meters <= 5000),
    
    ADD CONSTRAINT check_base_reward_positive 
    CHECK (base_reward_amount > 0),
    
    ADD CONSTRAINT check_max_reward_consistency 
    CHECK (max_reward_per_visit >= base_reward_amount),
    
    ADD CONSTRAINT check_daily_rewards_reasonable 
    CHECK (max_daily_rewards > 0 AND max_daily_rewards <= 1000),
    
    ADD CONSTRAINT check_stay_duration_reasonable 
    CHECK (min_stay_duration_seconds >= 0 AND min_stay_duration_seconds <= 86400),
    
    ADD CONSTRAINT check_cooldown_reasonable 
    CHECK (cooldown_minutes >= 0 AND cooldown_minutes <= 1440),
    
    ADD CONSTRAINT check_participants_reasonable 
    CHECK (max_participants_per_session > 0 AND max_participants_per_session <= 10000),
    
    ADD CONSTRAINT check_priority_level_valid 
    CHECK (priority_level >= 1 AND priority_level <= 10);

-- Location reports constraints
ALTER TABLE location_reports
    ADD CONSTRAINT check_accuracy_reasonable 
    CHECK (accuracy_meters IS NULL OR (accuracy_meters >= 0 AND accuracy_meters <= 10000)),
    
    ADD CONSTRAINT check_speed_reasonable 
    CHECK (speed_mps IS NULL OR (speed_mps >= 0 AND speed_mps <= 200)),
    
    ADD CONSTRAINT check_heading_valid 
    CHECK (heading_degrees IS NULL OR (heading_degrees >= 0 AND heading_degrees < 360)),
    
    ADD CONSTRAINT check_battery_level_valid 
    CHECK (battery_level IS NULL OR (battery_level >= 0 AND battery_level <= 100)),
    
    ADD CONSTRAINT check_fraud_score_valid 
    CHECK (fraud_score >= 0 AND fraud_score <= 1),
    
    ADD CONSTRAINT check_timestamp_order 
    CHECK (timestamp_server >= timestamp_client - INTERVAL '1 hour' AND timestamp_server <= timestamp_client + INTERVAL '1 hour');

-- Comments constraints
ALTER TABLE comments
    ADD CONSTRAINT check_content_not_empty 
    CHECK (length(trim(content)) > 0),
    
    ADD CONSTRAINT check_thread_depth_reasonable 
    CHECK (thread_depth >= 0 AND thread_depth <= 10),
    
    ADD CONSTRAINT check_engagement_positive 
    CHECK (like_count >= 0 AND reply_count >= 0);

-- Anti-fraud constraints
ALTER TABLE anti_fraud_logs
    ADD CONSTRAINT check_risk_score_valid 
    CHECK (risk_score >= 0 AND risk_score <= 1);

-- ============================================================================
-- BUSINESS LOGIC VALIDATION FUNCTIONS
-- ============================================================================

-- Validate user registration data
CREATE OR REPLACE FUNCTION validate_user_registration(
    p_email VARCHAR(255),
    p_username VARCHAR(50),
    p_password_hash VARCHAR(255)
) RETURNS TABLE(
    is_valid BOOLEAN,
    error_message TEXT
) AS $$
DECLARE
    existing_count INTEGER;
BEGIN
    -- Check email uniqueness
    SELECT COUNT(*) INTO existing_count FROM users WHERE email = p_email AND status != 'deleted';
    IF existing_count > 0 THEN
        RETURN QUERY SELECT false, 'Email already registered';
        RETURN;
    END IF;
    
    -- Check username uniqueness
    SELECT COUNT(*) INTO existing_count FROM users WHERE username = p_username AND status != 'deleted';
    IF existing_count > 0 THEN
        RETURN QUERY SELECT false, 'Username already taken';
        RETURN;
    END IF;
    
    -- Validate email format (additional check beyond constraint)
    IF NOT (p_email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') THEN
        RETURN QUERY SELECT false, 'Invalid email format';
        RETURN;
    END IF;
    
    -- Validate username format
    IF NOT (p_username ~ '^[A-Za-z0-9_]+$') THEN
        RETURN QUERY SELECT false, 'Username can only contain letters, numbers, and underscores';
        RETURN;
    END IF;
    
    -- Check password hash length (should be bcrypt hash)
    IF length(p_password_hash) < 50 THEN
        RETURN QUERY SELECT false, 'Invalid password hash';
        RETURN;
    END IF;
    
    RETURN QUERY SELECT true, 'Valid'::TEXT;
END;
$$ LANGUAGE plpgsql;

-- Validate wallet transaction
CREATE OR REPLACE FUNCTION validate_wallet_transaction(
    p_user_id UUID,
    p_transaction_type VARCHAR(30),
    p_amount DECIMAL(12,2),
    p_fee_amount DECIMAL(12,2) DEFAULT 0.00
) RETURNS TABLE(
    is_valid BOOLEAN,
    error_message TEXT,
    available_balance DECIMAL(12,2)
) AS $$
DECLARE
    wallet_record RECORD;
    required_balance DECIMAL(12,2);
BEGIN
    -- Get current wallet state
    SELECT * INTO wallet_record FROM wallets WHERE user_id = p_user_id;
    
    IF wallet_record IS NULL THEN
        RETURN QUERY SELECT false, 'Wallet not found', 0.00::DECIMAL(12,2);
        RETURN;
    END IF;
    
    -- Check withdrawal/transfer constraints
    IF p_transaction_type IN ('withdrawal', 'transfer_out') THEN
        required_balance := p_amount + p_fee_amount;
        
        IF wallet_record.available_balance < required_balance THEN
            RETURN QUERY SELECT false, 'Insufficient balance', wallet_record.available_balance;
            RETURN;
        END IF;
        
        -- Check minimum withdrawal amount
        IF p_transaction_type = 'withdrawal' AND p_amount < 10.00 THEN
            RETURN QUERY SELECT false, 'Minimum withdrawal amount is $10.00', wallet_record.available_balance;
            RETURN;
        END IF;
    END IF;
    
    -- Check maximum transaction limits
    IF p_amount > 10000.00 THEN
        RETURN QUERY SELECT false, 'Amount exceeds maximum limit ($10,000)', wallet_record.available_balance;
        RETURN;
    END IF;
    
    RETURN QUERY SELECT true, 'Valid'::TEXT, wallet_record.available_balance;
END;
$$ LANGUAGE plpgsql;

-- Validate LBS reward calculation
CREATE OR REPLACE FUNCTION validate_lbs_reward(
    p_user_id UUID,
    p_geofence_id UUID,
    p_location GEOGRAPHY,
    p_reward_amount DECIMAL(10,2)
) RETURNS TABLE(
    is_valid BOOLEAN,
    error_message TEXT,
    max_allowed_reward DECIMAL(10,2)
) AS $$
DECLARE
    geofence_config RECORD;
    recent_rewards_count INTEGER;
    user_daily_total DECIMAL(12,2);
BEGIN
    -- Get geofence configuration
    SELECT * INTO geofence_config FROM geofence_configs WHERE id = p_geofence_id AND is_active = true;
    
    IF geofence_config IS NULL THEN
        RETURN QUERY SELECT false, 'Geofence not found or inactive', 0.00::DECIMAL(10,2);
        RETURN;
    END IF;
    
    -- Check if location is within geofence
    IF NOT ST_DWithin(geofence_config.center_point, p_location, geofence_config.radius_meters) THEN
        RETURN QUERY SELECT false, 'Location outside geofence boundary', geofence_config.max_reward_per_visit;
        RETURN;
    END IF;
    
    -- Check daily reward limit
    SELECT COUNT(*), COALESCE(SUM(final_amount), 0)
    INTO recent_rewards_count, user_daily_total
    FROM lbs_rewards 
    WHERE user_id = p_user_id 
      AND geofence_id = p_geofence_id
      AND created_at >= CURRENT_DATE
      AND status IN ('pending', 'approved', 'paid');
    
    IF recent_rewards_count >= geofence_config.max_daily_rewards THEN
        RETURN QUERY SELECT false, 'Daily reward limit reached for this geofence', geofence_config.max_reward_per_visit;
        RETURN;
    END IF;
    
    -- Check reward amount reasonableness
    IF p_reward_amount > geofence_config.max_reward_per_visit THEN
        RETURN QUERY SELECT false, 'Reward amount exceeds maximum allowed', geofence_config.max_reward_per_visit;
        RETURN;
    END IF;
    
    -- Check for potential reward farming (multiple rewards in short time)
    SELECT COUNT(*) INTO recent_rewards_count
    FROM lbs_rewards 
    WHERE user_id = p_user_id 
      AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
      AND status IN ('pending', 'approved', 'paid');
      
    IF recent_rewards_count >= 10 THEN
        RETURN QUERY SELECT false, 'Too many rewards in short time period', geofence_config.max_reward_per_visit;
        RETURN;
    END IF;
    
    RETURN QUERY SELECT true, 'Valid'::TEXT, geofence_config.max_reward_per_visit;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- DATA CONSISTENCY TRIGGERS
-- ============================================================================

-- Update user profile stats when annotations are created/deleted
CREATE OR REPLACE FUNCTION update_user_annotation_stats()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE user_profiles 
        SET total_annotations = total_annotations + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = NEW.user_id;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE user_profiles 
        SET total_annotations = GREATEST(total_annotations - 1, 0),
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = OLD.user_id;
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_user_annotation_stats ON annotations;
CREATE TRIGGER trigger_update_user_annotation_stats
    AFTER INSERT OR DELETE ON annotations
    FOR EACH ROW EXECUTE FUNCTION update_user_annotation_stats();

-- Update annotation engagement counters
CREATE OR REPLACE FUNCTION update_annotation_engagement()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Update comment count
        IF TG_TABLE_NAME = 'comments' THEN
            UPDATE annotations 
            SET comment_count = comment_count + 1,
                last_activity_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = NEW.annotation_id;
        -- Update reaction count  
        ELSIF TG_TABLE_NAME = 'annotation_reactions' THEN
            UPDATE annotations 
            SET like_count = like_count + 1,
                last_activity_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = NEW.annotation_id;
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        -- Update comment count
        IF TG_TABLE_NAME = 'comments' THEN
            UPDATE annotations 
            SET comment_count = GREATEST(comment_count - 1, 0),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = OLD.annotation_id;
        -- Update reaction count
        ELSIF TG_TABLE_NAME = 'annotation_reactions' THEN
            UPDATE annotations 
            SET like_count = GREATEST(like_count - 1, 0),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = OLD.annotation_id;
        END IF;
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_annotation_engagement_comments ON comments;
DROP TRIGGER IF EXISTS trigger_update_annotation_engagement_reactions ON annotation_reactions;

CREATE TRIGGER trigger_update_annotation_engagement_comments
    AFTER INSERT OR DELETE ON comments
    FOR EACH ROW EXECUTE FUNCTION update_annotation_engagement();

CREATE TRIGGER trigger_update_annotation_engagement_reactions
    AFTER INSERT OR DELETE ON annotation_reactions  
    FOR EACH ROW EXECUTE FUNCTION update_annotation_engagement();

-- Update wallet balances on transactions
CREATE OR REPLACE FUNCTION update_wallet_on_transaction()
RETURNS TRIGGER AS $$
DECLARE
    transaction_amount DECIMAL(12,2);
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Calculate net effect on wallet
        transaction_amount := CASE 
            WHEN NEW.transaction_type IN ('withdrawal', 'transfer_out', 'penalty') 
            THEN -(NEW.amount + NEW.fee_amount)
            ELSE NEW.amount
        END;
        
        -- Update wallet balances
        UPDATE wallets 
        SET available_balance = available_balance + transaction_amount,
            total_earned = CASE 
                WHEN NEW.transaction_type IN ('lbs_reward', 'referral_bonus', 'deposit') 
                THEN total_earned + NEW.amount 
                ELSE total_earned 
            END,
            total_spent = CASE 
                WHEN NEW.transaction_type IN ('withdrawal', 'annotation_payment', 'penalty') 
                THEN total_spent + NEW.amount 
                ELSE total_spent 
            END,
            total_withdrawn = CASE 
                WHEN NEW.transaction_type = 'withdrawal' 
                THEN total_withdrawn + NEW.amount 
                ELSE total_withdrawn 
            END,
            total_deposited = CASE 
                WHEN NEW.transaction_type = 'deposit' 
                THEN total_deposited + NEW.amount 
                ELSE total_deposited 
            END,
            last_transaction_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = NEW.user_id;
        
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_wallet_on_transaction ON transactions;
CREATE TRIGGER trigger_update_wallet_on_transaction
    AFTER INSERT ON transactions
    FOR EACH ROW EXECUTE FUNCTION update_wallet_on_transaction();

-- Update follower counts
CREATE OR REPLACE FUNCTION update_follow_counts()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Increment following count for follower
        UPDATE user_profiles 
        SET following_count = following_count + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = NEW.follower_id;
        
        -- Increment follower count for followed user
        UPDATE user_profiles 
        SET followers_count = followers_count + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = NEW.following_id;
        
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        -- Decrement following count for follower
        UPDATE user_profiles 
        SET following_count = GREATEST(following_count - 1, 0),
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = OLD.follower_id;
        
        -- Decrement follower count for followed user
        UPDATE user_profiles 
        SET followers_count = GREATEST(followers_count - 1, 0),
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = OLD.following_id;
        
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_follow_counts ON user_follows;
CREATE TRIGGER trigger_update_follow_counts
    AFTER INSERT OR DELETE ON user_follows
    FOR EACH ROW EXECUTE FUNCTION update_follow_counts();

-- ============================================================================
-- DATA INTEGRITY MONITORING FUNCTIONS
-- ============================================================================

-- Function to check data consistency
CREATE OR REPLACE FUNCTION check_data_integrity()
RETURNS TABLE(
    check_name TEXT,
    status TEXT,
    issue_count BIGINT,
    description TEXT
) AS $$
BEGIN
    -- Check user profile consistency
    RETURN QUERY
    SELECT 
        'user_profiles_consistency'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
        COUNT(*),
        'Users without matching profiles'::TEXT
    FROM users u
    LEFT JOIN user_profiles up ON u.id = up.user_id
    WHERE u.status = 'active' AND up.user_id IS NULL;
    
    -- Check wallet consistency  
    RETURN QUERY
    SELECT 
        'wallet_consistency'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
        COUNT(*),
        'Users without wallets'::TEXT
    FROM users u
    LEFT JOIN wallets w ON u.id = w.user_id
    WHERE u.status = 'active' AND w.user_id IS NULL;
    
    -- Check orphaned comments
    RETURN QUERY
    SELECT 
        'orphaned_comments'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
        COUNT(*),
        'Comments without valid annotations'::TEXT
    FROM comments c
    LEFT JOIN annotations a ON c.annotation_id = a.id
    WHERE a.id IS NULL;
    
    -- Check annotation engagement counts
    RETURN QUERY
    WITH comment_counts AS (
        SELECT 
            annotation_id,
            COUNT(*) as actual_count
        FROM comments 
        WHERE status = 'active'
        GROUP BY annotation_id
    )
    SELECT 
        'annotation_comment_counts'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
        COUNT(*),
        'Annotations with incorrect comment counts'::TEXT
    FROM annotations a
    LEFT JOIN comment_counts cc ON a.id = cc.annotation_id
    WHERE COALESCE(cc.actual_count, 0) != a.comment_count;
    
    -- Check wallet balance consistency
    RETURN QUERY
    SELECT 
        'wallet_negative_balance'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
        COUNT(*),
        'Wallets with negative available balance'::TEXT
    FROM wallets
    WHERE available_balance < 0;
    
    -- Check geofence location validity
    RETURN QUERY
    SELECT 
        'invalid_geofence_locations'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
        COUNT(*),
        'Geofences with invalid geographic data'::TEXT
    FROM geofence_configs
    WHERE center_point IS NULL OR NOT ST_IsValid(center_point::geometry);
    
    -- Check annotation location validity
    RETURN QUERY
    SELECT 
        'invalid_annotation_locations'::TEXT,
        CASE WHEN COUNT(*) = 0 THEN 'PASS' ELSE 'FAIL' END,
        COUNT(*),
        'Annotations with invalid geographic data'::TEXT
    FROM annotations
    WHERE location IS NULL OR NOT ST_IsValid(location::geometry);
END;
$$ LANGUAGE plpgsql;

-- Function to fix common data integrity issues
CREATE OR REPLACE FUNCTION fix_data_integrity_issues()
RETURNS TABLE(
    fix_name TEXT,
    records_affected BIGINT,
    description TEXT
) AS $$
DECLARE
    affected_count BIGINT;
BEGIN
    -- Create missing user profiles
    INSERT INTO user_profiles (user_id, display_name, level, experience_points)
    SELECT u.id, u.username, 1, 0
    FROM users u
    LEFT JOIN user_profiles up ON u.id = up.user_id
    WHERE u.status = 'active' AND up.user_id IS NULL;
    
    GET DIAGNOSTICS affected_count = ROW_COUNT;
    RETURN QUERY SELECT 'create_missing_profiles'::TEXT, affected_count, 'Created missing user profiles'::TEXT;
    
    -- Create missing wallets
    INSERT INTO wallets (user_id)
    SELECT u.id
    FROM users u
    LEFT JOIN wallets w ON u.id = w.user_id
    WHERE u.status = 'active' AND w.user_id IS NULL;
    
    GET DIAGNOSTICS affected_count = ROW_COUNT;
    RETURN QUERY SELECT 'create_missing_wallets'::TEXT, affected_count, 'Created missing user wallets'::TEXT;
    
    -- Fix annotation comment counts
    UPDATE annotations 
    SET comment_count = COALESCE(cc.actual_count, 0),
        updated_at = CURRENT_TIMESTAMP
    FROM (
        SELECT 
            annotation_id,
            COUNT(*) as actual_count
        FROM comments 
        WHERE status = 'active'
        GROUP BY annotation_id
    ) cc
    WHERE annotations.id = cc.annotation_id 
      AND annotations.comment_count != cc.actual_count;
      
    GET DIAGNOSTICS affected_count = ROW_COUNT;
    RETURN QUERY SELECT 'fix_comment_counts'::TEXT, affected_count, 'Fixed annotation comment counts'::TEXT;
    
    -- Remove orphaned comments
    DELETE FROM comments 
    WHERE annotation_id NOT IN (SELECT id FROM annotations);
    
    GET DIAGNOSTICS affected_count = ROW_COUNT;
    RETURN QUERY SELECT 'remove_orphaned_comments'::TEXT, affected_count, 'Removed orphaned comments'::TEXT;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMPLETION MESSAGE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '===============================================';
    RAISE NOTICE 'Data Integrity Verification System Deployed!';
    RAISE NOTICE '===============================================';
    RAISE NOTICE '';
    RAISE NOTICE 'INTEGRITY FEATURES ADDED:';
    RAISE NOTICE '- Comprehensive data validation constraints';
    RAISE NOTICE '- Business logic validation functions';
    RAISE NOTICE '- Automatic data consistency triggers';
    RAISE NOTICE '- Integrity monitoring and repair functions';
    RAISE NOTICE '';
    RAISE NOTICE 'TO CHECK DATA INTEGRITY:';
    RAISE NOTICE 'SELECT * FROM check_data_integrity();';
    RAISE NOTICE '';
    RAISE NOTICE 'TO FIX INTEGRITY ISSUES:';
    RAISE NOTICE 'SELECT * FROM fix_data_integrity_issues();';
    RAISE NOTICE '';
    RAISE NOTICE 'KEY VALIDATION FUNCTIONS:';
    RAISE NOTICE '- validate_user_registration()';
    RAISE NOTICE '- validate_wallet_transaction()';
    RAISE NOTICE '- validate_lbs_reward()';
END $$;