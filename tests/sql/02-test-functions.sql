-- 测试辅助函数
-- SmellPin自动化测试方案2.0

-- 清理测试数据函数
CREATE OR REPLACE FUNCTION cleanup_test_data() 
RETURNS void AS $$
BEGIN
    -- 清理用户相关数据
    TRUNCATE TABLE annotation_likes RESTART IDENTITY CASCADE;
    TRUNCATE TABLE comments RESTART IDENTITY CASCADE;
    TRUNCATE TABLE media_files RESTART IDENTITY CASCADE;
    TRUNCATE TABLE annotations RESTART IDENTITY CASCADE;
    TRUNCATE TABLE user_follows RESTART IDENTITY CASCADE;
    TRUNCATE TABLE users RESTART IDENTITY CASCADE;
    
    -- 重置序列
    ALTER SEQUENCE users_id_seq RESTART WITH 1;
    ALTER SEQUENCE annotations_id_seq RESTART WITH 1;
    
    RAISE NOTICE 'Test data cleanup completed';
END;
$$ LANGUAGE plpgsql;

-- 创建测试用户函数
CREATE OR REPLACE FUNCTION create_test_user(
    p_username varchar(50),
    p_email varchar(100),
    p_password_hash text
) RETURNS integer AS $$
DECLARE
    user_id integer;
BEGIN
    INSERT INTO users (username, email, password_hash, status, email_verified, created_at, updated_at)
    VALUES (p_username, p_email, p_password_hash, 'active', true, NOW(), NOW())
    RETURNING id INTO user_id;
    
    RETURN user_id;
END;
$$ LANGUAGE plpgsql;

-- 创建测试标注函数
CREATE OR REPLACE FUNCTION create_test_annotation(
    p_user_id integer,
    p_title varchar(200),
    p_latitude numeric(10,8),
    p_longitude numeric(11,8),
    p_smell_type varchar(50)
) RETURNS integer AS $$
DECLARE
    annotation_id integer;
BEGIN
    INSERT INTO annotations (
        user_id, title, latitude, longitude, smell_type, 
        status, visibility, created_at, updated_at
    )
    VALUES (
        p_user_id, p_title, p_latitude, p_longitude, p_smell_type,
        'published', 'public', NOW(), NOW()
    )
    RETURNING id INTO annotation_id;
    
    RETURN annotation_id;
END;
$$ LANGUAGE plpgsql;

-- 生成随机测试数据函数
CREATE OR REPLACE FUNCTION generate_test_data(
    p_users_count integer DEFAULT 10,
    p_annotations_per_user integer DEFAULT 5
) RETURNS void AS $$
DECLARE
    user_rec record;
    i integer;
    j integer;
    smell_types text[] := ARRAY['食物香味', '垃圾异味', '化学品味', '花香', '汽油味'];
    beijing_lat numeric := 39.9042;
    beijing_lng numeric := 116.4074;
BEGIN
    -- 生成测试用户
    FOR i IN 1..p_users_count LOOP
        PERFORM create_test_user(
            'testuser' || i,
            'test' || i || '@smellpin.test',
            '$2b$10$test.hash.for.user.' || i
        );
    END LOOP;
    
    -- 为每个用户生成测试标注
    FOR user_rec IN SELECT id FROM users WHERE username LIKE 'testuser%' LOOP
        FOR j IN 1..p_annotations_per_user LOOP
            PERFORM create_test_annotation(
                user_rec.id,
                '测试标注 ' || j || ' by user ' || user_rec.id,
                beijing_lat + (random() - 0.5) * 0.1,
                beijing_lng + (random() - 0.5) * 0.1,
                smell_types[1 + floor(random() * array_length(smell_types, 1))::int]
            );
        END LOOP;
    END LOOP;
    
    RAISE NOTICE 'Generated % users with % annotations each', p_users_count, p_annotations_per_user;
END;
$$ LANGUAGE plpgsql;

-- 数据库性能测试函数
CREATE OR REPLACE FUNCTION test_database_performance()
RETURNS TABLE(
    test_name text,
    execution_time interval,
    rows_affected integer,
    status text
) AS $$
DECLARE
    start_time timestamp;
    end_time timestamp;
BEGIN
    -- 测试1: 用户查询性能
    start_time := clock_timestamp();
    PERFORM COUNT(*) FROM users WHERE status = 'active';
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        '用户查询测试'::text,
        (end_time - start_time)::interval,
        (SELECT COUNT(*)::integer FROM users WHERE status = 'active'),
        'PASS'::text;
    
    -- 测试2: 地理查询性能  
    start_time := clock_timestamp();
    PERFORM COUNT(*) FROM annotations 
    WHERE latitude BETWEEN 39.8 AND 40.0 
    AND longitude BETWEEN 116.3 AND 116.5;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        '地理查询测试'::text,
        (end_time - start_time)::interval,
        (SELECT COUNT(*)::integer FROM annotations 
         WHERE latitude BETWEEN 39.8 AND 40.0 
         AND longitude BETWEEN 116.3 AND 116.5),
        CASE WHEN (end_time - start_time) < interval '1 second' THEN 'PASS' ELSE 'SLOW' END;
    
    -- 测试3: 连接查询性能
    start_time := clock_timestamp();
    PERFORM COUNT(*) FROM annotations a 
    JOIN users u ON a.user_id = u.id 
    WHERE u.status = 'active';
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        '连接查询测试'::text,
        (end_time - start_time)::interval,
        (SELECT COUNT(*)::integer FROM annotations a 
         JOIN users u ON a.user_id = u.id 
         WHERE u.status = 'active'),
        CASE WHEN (end_time - start_time) < interval '2 seconds' THEN 'PASS' ELSE 'SLOW' END;
END;
$$ LANGUAGE plpgsql;