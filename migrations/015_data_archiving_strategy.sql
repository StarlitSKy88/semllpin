-- SmellPin Data Archiving Strategy Implementation
-- Purpose: Maintain optimal performance by archiving old data while preserving important records
-- Target: Keep active tables lean for <200ms query performance

-- ============================================================================
-- ARCHIVING CONFIGURATION
-- ============================================================================

-- Create archive schema for storing historical data
CREATE SCHEMA IF NOT EXISTS archive;

-- Set up archiving configuration table
CREATE TABLE IF NOT EXISTS archive_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name VARCHAR(100) NOT NULL UNIQUE,
    archive_after_days INTEGER NOT NULL DEFAULT 365,
    retention_policy VARCHAR(50) NOT NULL DEFAULT 'delete' CHECK (retention_policy IN ('delete', 'archive', 'compress')),
    partition_strategy VARCHAR(50) DEFAULT 'monthly' CHECK (partition_strategy IN ('daily', 'weekly', 'monthly', 'yearly', 'none')),
    is_active BOOLEAN DEFAULT true,
    last_archive_run TIMESTAMP WITH TIME ZONE,
    records_archived BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert archiving policies for different table types
INSERT INTO archive_config (table_name, archive_after_days, retention_policy, partition_strategy) VALUES
-- High-volume, short-term data
('location_reports', 90, 'archive', 'monthly'),
('anti_fraud_logs', 180, 'archive', 'monthly'),
-- Medium-volume data with longer retention
('lbs_rewards', 365, 'archive', 'monthly'),
('transactions', 2555, 'archive', 'yearly'), -- 7 years for financial records
('lbs_check_ins', 365, 'archive', 'monthly'),
-- Low-volume, long-term data
('annotations', 1095, 'compress', 'yearly'), -- 3 years
('comments', 730, 'archive', 'yearly'), -- 2 years
('user_follows', -1, 'delete', 'none'), -- Never archive (permanent relationships)
-- User data (handle carefully)
('users', -1, 'delete', 'none'), -- Never auto-archive users
('user_profiles', -1, 'delete', 'none') -- Never auto-archive profiles
ON CONFLICT (table_name) DO UPDATE SET
    archive_after_days = EXCLUDED.archive_after_days,
    retention_policy = EXCLUDED.retention_policy,
    partition_strategy = EXCLUDED.partition_strategy,
    updated_at = CURRENT_TIMESTAMP;

-- ============================================================================
-- ARCHIVE TABLES CREATION
-- ============================================================================

-- Create archive tables with same structure as originals
CREATE TABLE IF NOT EXISTS archive.location_reports (LIKE location_reports INCLUDING ALL);
CREATE TABLE IF NOT EXISTS archive.anti_fraud_logs (LIKE anti_fraud_logs INCLUDING ALL);
CREATE TABLE IF NOT EXISTS archive.lbs_rewards (LIKE lbs_rewards INCLUDING ALL);
CREATE TABLE IF NOT EXISTS archive.transactions (LIKE transactions INCLUDING ALL);
CREATE TABLE IF NOT EXISTS archive.lbs_check_ins (LIKE lbs_check_ins INCLUDING ALL);
CREATE TABLE IF NOT EXISTS archive.annotations (LIKE annotations INCLUDING ALL);
CREATE TABLE IF NOT EXISTS archive.comments (LIKE comments INCLUDING ALL);

-- Add archiving metadata to archive tables
DO $$
DECLARE
    table_name TEXT;
    archive_tables TEXT[] := ARRAY['location_reports', 'anti_fraud_logs', 'lbs_rewards', 
                                  'transactions', 'lbs_check_ins', 'annotations', 'comments'];
BEGIN
    FOREACH table_name IN ARRAY archive_tables
    LOOP
        -- Add archive metadata columns if they don't exist
        BEGIN
            EXECUTE format('ALTER TABLE archive.%I ADD COLUMN IF NOT EXISTS archived_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP', table_name);
            EXECUTE format('ALTER TABLE archive.%I ADD COLUMN IF NOT EXISTS archive_reason VARCHAR(100) DEFAULT ''scheduled_archive''', table_name);
            EXECUTE format('ALTER TABLE archive.%I ADD COLUMN IF NOT EXISTS original_table VARCHAR(100) DEFAULT ''%I''', table_name, table_name);
        EXCEPTION WHEN OTHERS THEN
            -- Column might already exist, continue
            NULL;
        END;
    END LOOP;
END $$;

-- ============================================================================
-- ARCHIVING FUNCTIONS
-- ============================================================================

-- Function to archive old records from a table
CREATE OR REPLACE FUNCTION archive_old_records(
    p_table_name TEXT,
    p_archive_before_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    p_batch_size INTEGER DEFAULT 10000,
    p_max_batches INTEGER DEFAULT 100
) RETURNS TABLE(
    archived_count BIGINT,
    deleted_count BIGINT,
    batches_processed INTEGER,
    execution_time_ms BIGINT
) AS $$
DECLARE
    archive_policy RECORD;
    start_time TIMESTAMP WITH TIME ZONE := CURRENT_TIMESTAMP;
    batch_count INTEGER := 0;
    total_archived BIGINT := 0;
    total_deleted BIGINT := 0;
    archive_date TIMESTAMP WITH TIME ZONE;
    batch_archived INTEGER;
    batch_deleted INTEGER;
BEGIN
    -- Get archiving policy for the table
    SELECT * INTO archive_policy 
    FROM archive_config 
    WHERE table_name = p_table_name AND is_active = true;
    
    IF archive_policy IS NULL THEN
        RAISE NOTICE 'No active archiving policy found for table: %', p_table_name;
        RETURN QUERY SELECT 0::BIGINT, 0::BIGINT, 0, 0::BIGINT;
        RETURN;
    END IF;
    
    -- Skip if archive_after_days is -1 (never archive)
    IF archive_policy.archive_after_days = -1 THEN
        RAISE NOTICE 'Table % configured to never archive', p_table_name;
        RETURN QUERY SELECT 0::BIGINT, 0::BIGINT, 0, 0::BIGINT;
        RETURN;
    END IF;
    
    -- Calculate archive date
    archive_date := COALESCE(
        p_archive_before_date,
        CURRENT_TIMESTAMP - (archive_policy.archive_after_days || ' days')::INTERVAL
    );
    
    RAISE NOTICE 'Starting archive process for % (records before %)', p_table_name, archive_date;
    
    -- Process in batches
    LOOP
        batch_archived := 0;
        batch_deleted := 0;
        
        -- Handle different retention policies
        IF archive_policy.retention_policy = 'archive' THEN
            -- Move to archive table
            EXECUTE format('
                WITH moved_records AS (
                    DELETE FROM %I 
                    WHERE created_at < $1 
                    LIMIT $2
                    RETURNING *
                )
                INSERT INTO archive.%I 
                SELECT *, CURRENT_TIMESTAMP as archived_at, ''scheduled_archive'' as archive_reason, ''%I'' as original_table
                FROM moved_records
            ', p_table_name, p_table_name, p_table_name)
            USING archive_date, p_batch_size;
            
            GET DIAGNOSTICS batch_archived = ROW_COUNT;
            
        ELSIF archive_policy.retention_policy = 'delete' THEN
            -- Delete old records
            EXECUTE format('DELETE FROM %I WHERE created_at < $1 LIMIT $2', p_table_name)
            USING archive_date, p_batch_size;
            
            GET DIAGNOSTICS batch_deleted = ROW_COUNT;
            
        ELSIF archive_policy.retention_policy = 'compress' THEN
            -- For now, treat compress as archive (future enhancement: actual compression)
            EXECUTE format('
                WITH moved_records AS (
                    DELETE FROM %I 
                    WHERE created_at < $1 
                    LIMIT $2
                    RETURNING *
                )
                INSERT INTO archive.%I 
                SELECT *, CURRENT_TIMESTAMP as archived_at, ''compressed_archive'' as archive_reason, ''%I'' as original_table
                FROM moved_records
            ', p_table_name, p_table_name, p_table_name)
            USING archive_date, p_batch_size;
            
            GET DIAGNOSTICS batch_archived = ROW_COUNT;
        END IF;
        
        total_archived := total_archived + batch_archived;
        total_deleted := total_deleted + batch_deleted;
        batch_count := batch_count + 1;
        
        -- Exit if no more records to process or reached max batches
        EXIT WHEN (batch_archived = 0 AND batch_deleted = 0) OR batch_count >= p_max_batches;
        
        -- Brief pause between batches to avoid overwhelming the system
        PERFORM pg_sleep(0.1);
    END LOOP;
    
    -- Update archive config
    UPDATE archive_config 
    SET last_archive_run = CURRENT_TIMESTAMP,
        records_archived = records_archived + total_archived,
        updated_at = CURRENT_TIMESTAMP
    WHERE table_name = p_table_name;
    
    RAISE NOTICE 'Archive complete for %: % archived, % deleted in % batches', 
        p_table_name, total_archived, total_deleted, batch_count;
    
    RETURN QUERY SELECT 
        total_archived,
        total_deleted, 
        batch_count,
        EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time) * 1000)::BIGINT;
END;
$$ LANGUAGE plpgsql;

-- Function to run archiving for all configured tables
CREATE OR REPLACE FUNCTION run_scheduled_archiving(
    p_force_run BOOLEAN DEFAULT false
) RETURNS TABLE(
    table_name TEXT,
    archived_count BIGINT,
    deleted_count BIGINT,
    execution_time_ms BIGINT,
    status TEXT
) AS $$
DECLARE
    config_record RECORD;
    archive_result RECORD;
    should_run BOOLEAN;
BEGIN
    FOR config_record IN 
        SELECT * FROM archive_config 
        WHERE is_active = true 
        ORDER BY table_name
    LOOP
        -- Skip if table should never be archived
        IF config_record.archive_after_days = -1 THEN
            CONTINUE;
        END IF;
        
        -- Check if we should run (daily archiving, or forced)
        should_run := p_force_run OR 
                     config_record.last_archive_run IS NULL OR 
                     config_record.last_archive_run < CURRENT_TIMESTAMP - INTERVAL '1 day';
        
        IF should_run THEN
            BEGIN
                -- Run archiving for this table
                SELECT * INTO archive_result
                FROM archive_old_records(
                    config_record.table_name,
                    NULL, -- Use default archive date
                    CASE 
                        WHEN config_record.table_name IN ('location_reports', 'anti_fraud_logs') THEN 50000
                        ELSE 10000
                    END,
                    50 -- max batches
                );
                
                RETURN QUERY SELECT 
                    config_record.table_name,
                    archive_result.archived_count,
                    archive_result.deleted_count,
                    archive_result.execution_time_ms,
                    'success'::TEXT;
                    
            EXCEPTION WHEN OTHERS THEN
                RAISE WARNING 'Archiving failed for table %: %', config_record.table_name, SQLERRM;
                
                RETURN QUERY SELECT 
                    config_record.table_name,
                    0::BIGINT,
                    0::BIGINT,
                    0::BIGINT,
                    ('error: ' || SQLERRM)::TEXT;
            END;
        ELSE
            RETURN QUERY SELECT 
                config_record.table_name,
                0::BIGINT,
                0::BIGINT,
                0::BIGINT,
                'skipped'::TEXT;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- PARTITION MANAGEMENT FOR HIGH-VOLUME TABLES
-- ============================================================================

-- Function to create monthly partitions for high-volume tables
CREATE OR REPLACE FUNCTION create_monthly_partitions(
    p_table_name TEXT,
    p_months_ahead INTEGER DEFAULT 3
) RETURNS TEXT[] AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
    current_date DATE := CURRENT_DATE;
    month_offset INTEGER;
    created_partitions TEXT[] := '{}';
BEGIN
    -- Create partitions for next several months
    FOR month_offset IN 0..p_months_ahead LOOP
        start_date := date_trunc('month', current_date + (month_offset || ' months')::INTERVAL)::DATE;
        end_date := (start_date + INTERVAL '1 month')::DATE;
        partition_name := p_table_name || '_' || to_char(start_date, 'YYYY_MM');
        
        -- Check if partition already exists
        IF NOT EXISTS (
            SELECT 1 FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relname = partition_name AND n.nspname = 'public'
        ) THEN
            -- Create partition
            EXECUTE format(
                'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                partition_name, p_table_name, start_date, end_date
            );
            
            created_partitions := array_append(created_partitions, partition_name);
            
            RAISE NOTICE 'Created partition: %', partition_name;
        END IF;
    END LOOP;
    
    RETURN created_partitions;
END;
$$ LANGUAGE plpgsql;

-- Function to drop old partitions
CREATE OR REPLACE FUNCTION drop_old_partitions(
    p_table_name TEXT,
    p_keep_months INTEGER DEFAULT 12
) RETURNS TEXT[] AS $$
DECLARE
    partition_record RECORD;
    cutoff_date DATE := (CURRENT_DATE - (p_keep_months || ' months')::INTERVAL)::DATE;
    dropped_partitions TEXT[] := '{}';
    partition_date DATE;
BEGIN
    -- Find partitions older than cutoff date
    FOR partition_record IN
        SELECT schemaname, tablename 
        FROM pg_tables 
        WHERE schemaname = 'public' 
          AND tablename LIKE p_table_name || '_%'
          AND tablename ~ '^' || p_table_name || '_[0-9]{4}_[0-9]{2}$'
    LOOP
        -- Extract date from partition name
        BEGIN
            partition_date := to_date(
                substring(partition_record.tablename from length(p_table_name) + 2), 
                'YYYY_MM'
            );
            
            IF partition_date < cutoff_date THEN
                -- Archive data from partition before dropping
                PERFORM archive_old_records(partition_record.tablename);
                
                -- Drop the partition
                EXECUTE format('DROP TABLE IF EXISTS %I', partition_record.tablename);
                dropped_partitions := array_append(dropped_partitions, partition_record.tablename);
                
                RAISE NOTICE 'Dropped old partition: %', partition_record.tablename;
            END IF;
            
        EXCEPTION WHEN OTHERS THEN
            RAISE WARNING 'Could not process partition %: %', partition_record.tablename, SQLERRM;
        END;
    END LOOP;
    
    RETURN dropped_partitions;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- VACUUM AND ANALYZE OPTIMIZATION
-- ============================================================================

-- Function to run optimized VACUUM and ANALYZE
CREATE OR REPLACE FUNCTION optimize_table_maintenance() RETURNS TABLE(
    table_name TEXT,
    operation TEXT,
    duration_ms BIGINT,
    pages_removed BIGINT,
    status TEXT
) AS $$
DECLARE
    table_record RECORD;
    start_time TIMESTAMP WITH TIME ZONE;
    vacuum_result TEXT;
BEGIN
    -- Get tables that need maintenance
    FOR table_record IN
        SELECT 
            schemaname,
            tablename,
            n_dead_tup,
            n_live_tup,
            COALESCE(last_autovacuum, last_vacuum) as last_vacuum,
            COALESCE(last_autoanalyze, last_analyze) as last_analyze
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
        ORDER BY n_dead_tup DESC
    LOOP
        start_time := CURRENT_TIMESTAMP;
        
        -- VACUUM if needed (more than 20% dead tuples or hasn't been vacuumed in 24 hours)
        IF (table_record.n_dead_tup > table_record.n_live_tup * 0.2 AND table_record.n_dead_tup > 1000)
           OR table_record.last_vacuum < CURRENT_TIMESTAMP - INTERVAL '24 hours' THEN
            
            BEGIN
                EXECUTE format('VACUUM (ANALYZE, VERBOSE) %I.%I', 
                    table_record.schemaname, table_record.tablename);
                
                RETURN QUERY SELECT 
                    table_record.tablename,
                    'VACUUM',
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time) * 1000)::BIGINT,
                    table_record.n_dead_tup,
                    'success'::TEXT;
                    
            EXCEPTION WHEN OTHERS THEN
                RETURN QUERY SELECT 
                    table_record.tablename,
                    'VACUUM',
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time) * 1000)::BIGINT,
                    0::BIGINT,
                    ('error: ' || SQLERRM)::TEXT;
            END;
            
        -- ANALYZE if statistics are stale
        ELSIF table_record.last_analyze < CURRENT_TIMESTAMP - INTERVAL '12 hours' THEN
            start_time := CURRENT_TIMESTAMP;
            
            BEGIN
                EXECUTE format('ANALYZE %I.%I', table_record.schemaname, table_record.tablename);
                
                RETURN QUERY SELECT 
                    table_record.tablename,
                    'ANALYZE',
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time) * 1000)::BIGINT,
                    0::BIGINT,
                    'success'::TEXT;
                    
            EXCEPTION WHEN OTHERS THEN
                RETURN QUERY SELECT 
                    table_record.tablename,
                    'ANALYZE',
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time) * 1000)::BIGINT,
                    0::BIGINT,
                    ('error: ' || SQLERRM)::TEXT;
            END;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- AUTOMATED MAINTENANCE SCHEDULING
-- ============================================================================

-- Create a maintenance log table
CREATE TABLE IF NOT EXISTS maintenance_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_type VARCHAR(50) NOT NULL,
    table_name VARCHAR(100),
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    records_processed BIGINT DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'running',
    details JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Function to run all maintenance tasks
CREATE OR REPLACE FUNCTION run_database_maintenance(
    p_maintenance_type VARCHAR(50) DEFAULT 'scheduled'
) RETURNS UUID AS $$
DECLARE
    maintenance_id UUID := gen_random_uuid();
    start_time TIMESTAMP WITH TIME ZONE := CURRENT_TIMESTAMP;
    operation_result RECORD;
    total_processed BIGINT := 0;
BEGIN
    -- Log maintenance start
    INSERT INTO maintenance_log (id, operation_type, start_time, status, details)
    VALUES (maintenance_id, p_maintenance_type, start_time, 'running', 
            jsonb_build_object('started_by', 'system', 'maintenance_type', p_maintenance_type));
    
    -- 1. Run archiving
    RAISE NOTICE 'Starting archiving process...';
    FOR operation_result IN SELECT * FROM run_scheduled_archiving(false) LOOP
        total_processed := total_processed + operation_result.archived_count + operation_result.deleted_count;
    END LOOP;
    
    -- 2. Create future partitions
    RAISE NOTICE 'Creating future partitions...';
    PERFORM create_monthly_partitions('location_reports', 3);
    
    -- 3. Drop old partitions
    RAISE NOTICE 'Dropping old partitions...';
    PERFORM drop_old_partitions('location_reports', 6);
    
    -- 4. Run vacuum/analyze
    RAISE NOTICE 'Running table maintenance...';
    FOR operation_result IN SELECT * FROM optimize_table_maintenance() LOOP
        -- Log each vacuum/analyze operation
        NULL; -- Results are already returned
    END LOOP;
    
    -- 5. Update statistics
    RAISE NOTICE 'Updating query planner statistics...';
    ANALYZE;
    
    -- Log maintenance completion
    UPDATE maintenance_log 
    SET end_time = CURRENT_TIMESTAMP,
        status = 'completed',
        records_processed = total_processed,
        details = details || jsonb_build_object(
            'duration_minutes', EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) / 60,
            'completion_time', CURRENT_TIMESTAMP
        )
    WHERE id = maintenance_id;
    
    RAISE NOTICE 'Database maintenance completed in % minutes', 
        EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - start_time)) / 60;
    
    RETURN maintenance_id;
    
EXCEPTION WHEN OTHERS THEN
    -- Log maintenance failure
    UPDATE maintenance_log 
    SET end_time = CURRENT_TIMESTAMP,
        status = 'failed',
        details = details || jsonb_build_object('error', SQLERRM)
    WHERE id = maintenance_id;
    
    RAISE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- MONITORING AND REPORTING
-- ============================================================================

-- Create view for archiving status
CREATE OR REPLACE VIEW archiving_status AS
SELECT 
    ac.table_name,
    ac.archive_after_days,
    ac.retention_policy,
    ac.last_archive_run,
    ac.records_archived,
    CASE 
        WHEN ac.archive_after_days = -1 THEN 'Never archived'
        WHEN ac.last_archive_run IS NULL THEN 'Never run'
        WHEN ac.last_archive_run < CURRENT_TIMESTAMP - INTERVAL '2 days' THEN 'Overdue'
        WHEN ac.last_archive_run < CURRENT_TIMESTAMP - INTERVAL '1 day' THEN 'Due soon'
        ELSE 'Up to date'
    END as archive_status,
    -- Estimate current table size
    pg_size_pretty(pg_total_relation_size(quote_ident(ac.table_name))) as current_size,
    -- Count records eligible for archiving
    (SELECT COUNT(*) FROM information_schema.tables 
     WHERE table_name = ac.table_name AND table_schema = 'public') as table_exists
FROM archive_config ac
WHERE ac.is_active = true
ORDER BY ac.last_archive_run ASC NULLS FIRST;

-- Function to get database storage summary
CREATE OR REPLACE FUNCTION get_storage_summary() 
RETURNS TABLE(
    schema_name TEXT,
    table_name TEXT,
    size_pretty TEXT,
    size_bytes BIGINT,
    row_estimate BIGINT,
    last_vacuum TIMESTAMP WITH TIME ZONE,
    dead_tuple_percent DECIMAL(5,2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        n.nspname::TEXT as schema_name,
        c.relname::TEXT as table_name,
        pg_size_pretty(pg_total_relation_size(c.oid))::TEXT as size_pretty,
        pg_total_relation_size(c.oid) as size_bytes,
        c.reltuples::BIGINT as row_estimate,
        s.last_vacuum,
        CASE 
            WHEN s.n_live_tup > 0 
            THEN ROUND((s.n_dead_tup::DECIMAL / s.n_live_tup::DECIMAL) * 100, 2)
            ELSE 0.00
        END as dead_tuple_percent
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
    WHERE c.relkind = 'r' 
      AND n.nspname IN ('public', 'archive')
      AND c.relname NOT LIKE 'pg_%'
    ORDER BY pg_total_relation_size(c.oid) DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- COMPLETION AND RECOMMENDATIONS
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '===========================================';
    RAISE NOTICE 'SmellPin Data Archiving Strategy Deployed!';
    RAISE NOTICE '===========================================';
    RAISE NOTICE '';
    RAISE NOTICE 'ARCHIVING POLICIES CONFIGURED:';
    RAISE NOTICE '- location_reports: Archive after 90 days';
    RAISE NOTICE '- anti_fraud_logs: Archive after 180 days';
    RAISE NOTICE '- lbs_rewards: Archive after 365 days';
    RAISE NOTICE '- transactions: Archive after 7 years (compliance)';
    RAISE NOTICE '- annotations: Compress after 3 years';
    RAISE NOTICE '';
    RAISE NOTICE 'AUTOMATION FEATURES:';
    RAISE NOTICE '- Automatic monthly partitioning for high-volume tables';
    RAISE NOTICE '- Scheduled archiving (daily runs)';
    RAISE NOTICE '- Intelligent VACUUM/ANALYZE optimization';
    RAISE NOTICE '- Storage monitoring and reporting';
    RAISE NOTICE '';
    RAISE NOTICE 'TO START AUTOMATED MAINTENANCE:';
    RAISE NOTICE 'SELECT run_database_maintenance();';
    RAISE NOTICE '';
    RAISE NOTICE 'TO CHECK ARCHIVING STATUS:';
    RAISE NOTICE 'SELECT * FROM archiving_status;';
    RAISE NOTICE '';
    RAISE NOTICE 'TO GET STORAGE SUMMARY:';
    RAISE NOTICE 'SELECT * FROM get_storage_summary();';
END $$;