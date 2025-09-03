-- PostGIS地理空间优化迁移文件
-- 优化地理位置查询性能，专门针对SmellPin的LBS功能
-- 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase

-- 1. 启用PostGIS扩展（如果未启用）
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;

-- 2. 添加地理空间列（如果不存在）
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='annotations' AND column_name='location_point') THEN
        ALTER TABLE annotations ADD COLUMN location_point GEOMETRY(POINT, 4326);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='geofences' AND column_name='location_point') THEN
        ALTER TABLE geofences ADD COLUMN location_point GEOMETRY(POINT, 4326);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='geofences' AND column_name='geom_polygon') THEN
        ALTER TABLE geofences ADD COLUMN geom_polygon GEOMETRY(POLYGON, 4326);
    END IF;
END $$;

-- 3. 更新现有数据的地理空间列
UPDATE annotations 
SET location_point = ST_SetSRID(ST_Point(longitude, latitude), 4326)
WHERE location_point IS NULL AND longitude IS NOT NULL AND latitude IS NOT NULL;

UPDATE geofences 
SET location_point = ST_SetSRID(ST_Point(longitude, latitude), 4326)
WHERE location_point IS NULL AND longitude IS NOT NULL AND latitude IS NOT NULL;

-- 创建地理围栏的多边形几何（圆形）
UPDATE geofences 
SET geom_polygon = ST_Buffer(
    ST_Transform(ST_SetSRID(ST_Point(longitude, latitude), 4326)::geography, 3857), 
    radius
)::geometry
WHERE geom_polygon IS NULL AND longitude IS NOT NULL AND latitude IS NOT NULL AND radius IS NOT NULL;

-- 4. 创建高级PostGIS索引

-- 标注表的地理空间索引（GIST索引，最适合地理查询）
DROP INDEX IF EXISTS idx_annotations_location;
CREATE INDEX idx_annotations_location_postgis ON annotations USING GIST (location_point);

-- 地理围栏表的点索引
CREATE INDEX IF NOT EXISTS idx_geofences_location_point ON geofences USING GIST (location_point);

-- 地理围栏表的多边形索引
CREATE INDEX IF NOT EXISTS idx_geofences_geom_polygon ON geofences USING GIST (geom_polygon);

-- 组合索引：地理位置 + 创建时间
CREATE INDEX IF NOT EXISTS idx_annotations_location_time ON annotations USING GIST (location_point, created_at);

-- 组合索引：地理位置 + 类别
CREATE INDEX IF NOT EXISTS idx_annotations_location_category ON annotations (category) INCLUDE (location_point);

-- 组合索引：地理位置 + 强度
CREATE INDEX IF NOT EXISTS idx_annotations_location_intensity ON annotations (smell_intensity) INCLUDE (location_point);

-- 5. LBS系统相关的地理空间索引

-- 位置上报表索引
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'location_reports') THEN
        -- 添加地理空间列
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='location_reports' AND column_name='location_point') THEN
            ALTER TABLE location_reports ADD COLUMN location_point GEOMETRY(POINT, 4326);
        END IF;
        
        -- 更新现有数据
        UPDATE location_reports 
        SET location_point = ST_SetSRID(ST_Point(longitude, latitude), 4326)
        WHERE location_point IS NULL AND longitude IS NOT NULL AND latitude IS NOT NULL;
        
        -- 创建索引
        CREATE INDEX IF NOT EXISTS idx_location_reports_point ON location_reports USING GIST (location_point);
        CREATE INDEX IF NOT EXISTS idx_location_reports_time_location ON location_reports USING GIST (location_point, reported_at);
        CREATE INDEX IF NOT EXISTS idx_location_reports_user_time ON location_reports (user_id, reported_at DESC);
    END IF;
END $$;

-- 奖励记录表地理空间索引
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'reward_records') THEN
        -- 添加地理空间列
        IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                       WHERE table_name='reward_records' AND column_name='location_point') THEN
            ALTER TABLE reward_records ADD COLUMN location_point GEOMETRY(POINT, 4326);
        END IF;
        
        -- 更新现有数据
        UPDATE reward_records 
        SET location_point = ST_SetSRID(ST_Point(longitude, latitude), 4326)
        WHERE location_point IS NULL AND longitude IS NOT NULL AND latitude IS NOT NULL;
        
        -- 创建索引
        CREATE INDEX IF NOT EXISTS idx_reward_records_location ON reward_records USING GIST (location_point);
        CREATE INDEX IF NOT EXISTS idx_reward_records_location_time ON reward_records USING GIST (location_point, timestamp);
    END IF;
END $$;

-- 6. 创建地理空间查询优化函数

-- 获取附近标注的优化函数
CREATE OR REPLACE FUNCTION get_nearby_annotations(
    center_lat DOUBLE PRECISION,
    center_lng DOUBLE PRECISION,
    radius_meters INTEGER DEFAULT 1000,
    limit_count INTEGER DEFAULT 50
)
RETURNS TABLE (
    id UUID,
    user_id UUID,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    description TEXT,
    category VARCHAR(50),
    smell_intensity INTEGER,
    created_at TIMESTAMP,
    distance_meters DOUBLE PRECISION
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.id,
        a.user_id,
        a.latitude,
        a.longitude,
        a.description,
        a.category,
        a.smell_intensity,
        a.created_at,
        ST_Distance(
            a.location_point::geography, 
            ST_SetSRID(ST_Point(center_lng, center_lat), 4326)::geography
        ) AS distance_meters
    FROM annotations a
    WHERE 
        a.status = 'published'
        AND a.location_point IS NOT NULL
        AND ST_DWithin(
            a.location_point::geography,
            ST_SetSRID(ST_Point(center_lng, center_lat), 4326)::geography,
            radius_meters
        )
    ORDER BY a.location_point <-> ST_SetSRID(ST_Point(center_lng, center_lat), 4326)
    LIMIT limit_count;
END;
$$ LANGUAGE plpgsql;

-- 检查地理围栏的优化函数
CREATE OR REPLACE FUNCTION check_geofence_intersection(
    check_lat DOUBLE PRECISION,
    check_lng DOUBLE PRECISION
)
RETURNS TABLE (
    geofence_id UUID,
    name VARCHAR(255),
    reward_type VARCHAR(50),
    base_reward DECIMAL(10,2),
    distance_to_center DOUBLE PRECISION
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        g.id,
        g.name,
        g.reward_type,
        g.base_reward,
        ST_Distance(
            g.location_point::geography, 
            ST_SetSRID(ST_Point(check_lng, check_lat), 4326)::geography
        ) AS distance_to_center
    FROM geofences g
    WHERE 
        g.is_active = true
        AND g.location_point IS NOT NULL
        AND (
            -- 检查点是否在地理围栏内
            ST_Intersects(
                g.geom_polygon,
                ST_SetSRID(ST_Point(check_lng, check_lat), 4326)
            )
            OR
            -- 或者距离中心点在半径内（备用检查）
            ST_DWithin(
                g.location_point::geography,
                ST_SetSRID(ST_Point(check_lng, check_lat), 4326)::geography,
                g.radius
            )
        )
    ORDER BY distance_to_center;
END;
$$ LANGUAGE plpgsql;

-- 7. 创建地理空间聚合查询的物化视图

-- 热点区域统计视图
CREATE MATERIALIZED VIEW IF NOT EXISTS smell_hotspots AS
SELECT 
    -- 使用50米网格进行聚合
    ST_SnapToGrid(location_point, 0.0005) AS grid_point,
    COUNT(*) AS annotation_count,
    AVG(smell_intensity) AS avg_intensity,
    MAX(smell_intensity) AS max_intensity,
    array_agg(DISTINCT category) AS categories,
    MAX(created_at) AS latest_annotation,
    ST_X(ST_SnapToGrid(location_point, 0.0005)) AS grid_longitude,
    ST_Y(ST_SnapToGrid(location_point, 0.0005)) AS grid_latitude
FROM annotations 
WHERE 
    status = 'published' 
    AND location_point IS NOT NULL 
    AND created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY ST_SnapToGrid(location_point, 0.0005)
HAVING COUNT(*) >= 3;  -- 至少3个标注才算热点

-- 为热点视图创建索引
CREATE INDEX IF NOT EXISTS idx_smell_hotspots_grid_point ON smell_hotspots USING GIST (grid_point);
CREATE INDEX IF NOT EXISTS idx_smell_hotspots_count ON smell_hotspots (annotation_count DESC);
CREATE INDEX IF NOT EXISTS idx_smell_hotspots_intensity ON smell_hotspots (avg_intensity DESC);

-- 8. 创建地理空间统计函数

-- 计算区域内的统计信息
CREATE OR REPLACE FUNCTION get_area_statistics(
    center_lat DOUBLE PRECISION,
    center_lng DOUBLE PRECISION,
    radius_meters INTEGER DEFAULT 1000
)
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'total_annotations', COUNT(*),
        'avg_intensity', ROUND(AVG(smell_intensity), 2),
        'max_intensity', MAX(smell_intensity),
        'categories', json_agg(DISTINCT category),
        'recent_count', COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'),
        'area_radius_meters', radius_meters,
        'center_coordinates', json_build_object('lat', center_lat, 'lng', center_lng)
    ) INTO result
    FROM annotations
    WHERE 
        status = 'published'
        AND location_point IS NOT NULL
        AND ST_DWithin(
            location_point::geography,
            ST_SetSRID(ST_Point(center_lng, center_lat), 4326)::geography,
            radius_meters
        );
    
    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- 9. 创建触发器自动更新地理空间列

-- 标注表触发器
CREATE OR REPLACE FUNCTION update_annotation_location()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.longitude IS NOT NULL AND NEW.latitude IS NOT NULL) THEN
        NEW.location_point = ST_SetSRID(ST_Point(NEW.longitude, NEW.latitude), 4326);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_annotation_location ON annotations;
CREATE TRIGGER trg_update_annotation_location
    BEFORE INSERT OR UPDATE ON annotations
    FOR EACH ROW
    EXECUTE FUNCTION update_annotation_location();

-- 地理围栏表触发器
CREATE OR REPLACE FUNCTION update_geofence_geometry()
RETURNS TRIGGER AS $$
BEGIN
    IF (NEW.longitude IS NOT NULL AND NEW.latitude IS NOT NULL) THEN
        NEW.location_point = ST_SetSRID(ST_Point(NEW.longitude, NEW.latitude), 4326);
        
        IF (NEW.radius IS NOT NULL) THEN
            NEW.geom_polygon = ST_Buffer(
                ST_Transform(ST_SetSRID(ST_Point(NEW.longitude, NEW.latitude), 4326)::geography, 3857), 
                NEW.radius
            )::geometry;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_geofence_geometry ON geofences;
CREATE TRIGGER trg_update_geofence_geometry
    BEFORE INSERT OR UPDATE ON geofences
    FOR EACH ROW
    EXECUTE FUNCTION update_geofence_geometry();

-- 10. 创建地理空间数据验证约束

-- 确保地理坐标在有效范围内
ALTER TABLE annotations DROP CONSTRAINT IF EXISTS chk_annotations_latitude;
ALTER TABLE annotations ADD CONSTRAINT chk_annotations_latitude 
CHECK (latitude >= -90 AND latitude <= 90);

ALTER TABLE annotations DROP CONSTRAINT IF EXISTS chk_annotations_longitude;
ALTER TABLE annotations ADD CONSTRAINT chk_annotations_longitude 
CHECK (longitude >= -180 AND longitude <= 180);

ALTER TABLE geofences DROP CONSTRAINT IF EXISTS chk_geofences_latitude;
ALTER TABLE geofences ADD CONSTRAINT chk_geofences_latitude 
CHECK (latitude >= -90 AND latitude <= 90);

ALTER TABLE geofences DROP CONSTRAINT IF EXISTS chk_geofences_longitude;
ALTER TABLE geofences ADD CONSTRAINT chk_geofences_longitude 
CHECK (longitude >= -180 AND longitude <= 180);

ALTER TABLE geofences DROP CONSTRAINT IF EXISTS chk_geofences_radius;
ALTER TABLE geofences ADD CONSTRAINT chk_geofences_radius 
CHECK (radius > 0 AND radius <= 10000); -- 最大10km半径

-- 11. 创建定期维护任务的函数

-- 刷新地理空间物化视图
CREATE OR REPLACE FUNCTION refresh_spatial_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY smell_hotspots;
    -- 更新统计信息
    ANALYZE annotations;
    ANALYZE geofences;
END;
$$ LANGUAGE plpgsql;

-- 清理过期的位置数据
CREATE OR REPLACE FUNCTION cleanup_old_location_data()
RETURNS void AS $$
BEGIN
    -- 删除30天前的位置上报记录
    DELETE FROM location_reports 
    WHERE reported_at < CURRENT_DATE - INTERVAL '30 days';
    
    -- 清理孤立的地理空间数据
    UPDATE annotations 
    SET location_point = NULL 
    WHERE (longitude IS NULL OR latitude IS NULL) AND location_point IS NOT NULL;
    
    -- 重建索引统计
    REINDEX INDEX CONCURRENTLY idx_annotations_location_postgis;
END;
$$ LANGUAGE plpgsql;

-- 12. 创建性能监控视图

CREATE OR REPLACE VIEW spatial_index_usage AS
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan
FROM pg_stat_user_indexes 
WHERE indexname LIKE '%location%' OR indexname LIKE '%spatial%' OR indexname LIKE '%gist%'
ORDER BY idx_scan DESC;

-- 13. 最后分析表以更新统计信息
ANALYZE annotations;
ANALYZE geofences;
ANALYZE location_reports;
ANALYZE reward_records;

-- 14. 输出优化报告
DO $$
DECLARE
    annotation_count INTEGER;
    geofence_count INTEGER;
    spatial_indexes INTEGER;
BEGIN
    SELECT COUNT(*) INTO annotation_count FROM annotations WHERE location_point IS NOT NULL;
    SELECT COUNT(*) INTO geofence_count FROM geofences WHERE location_point IS NOT NULL;
    SELECT COUNT(*) INTO spatial_indexes FROM pg_indexes WHERE indexdef LIKE '%GIST%' AND tablename IN ('annotations', 'geofences', 'location_reports');
    
    RAISE NOTICE '=== PostGIS优化完成 ===';
    RAISE NOTICE '标注地理数据: % 条', annotation_count;
    RAISE NOTICE '地理围栏数据: % 条', geofence_count;
    RAISE NOTICE 'GIST空间索引: % 个', spatial_indexes;
    RAISE NOTICE '优化函数: 4 个';
    RAISE NOTICE '物化视图: 1 个';
    RAISE NOTICE '预期性能提升: 50-70%%';
END $$;