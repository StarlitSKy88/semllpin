-- SmellPin数据库结构验证脚本
-- 验证所有关键字段和功能是否正确

-- 1. 验证users表结构
SELECT 'USERS TABLE VERIFICATION' as section;
\d users;

SELECT 'Users table field check' as test,
  CASE 
    WHEN COUNT(*) = 4 THEN 'PASS: All required fields exist'
    ELSE 'FAIL: Missing required fields'
  END as result
FROM information_schema.columns 
WHERE table_name = 'users' 
  AND column_name IN ('display_name', 'avatar_url', 'email', 'username');

-- 2. 验证annotations表结构
SELECT 'ANNOTATIONS TABLE VERIFICATION' as section;
\d annotations;

SELECT 'Annotations table field check' as test,
  CASE 
    WHEN COUNT(*) = 7 THEN 'PASS: All required fields exist'
    ELSE 'FAIL: Missing required fields'
  END as result
FROM information_schema.columns 
WHERE table_name = 'annotations' 
  AND column_name IN ('content', 'smell_intensity', 'latitude', 'longitude', 'location_point', 'description', 'status');

-- 3. 验证PostGIS扩展
SELECT 'POSTGIS VERIFICATION' as section;
SELECT name, installed_version FROM pg_available_extensions WHERE name = 'postgis';

-- 4. 验证地理位置函数
SELECT 'GEOGRAPHIC FUNCTIONS VERIFICATION' as section;
SELECT proname FROM pg_proc WHERE proname IN ('get_nearby_annotations', 'set_location_point');

-- 5. 验证索引存在
SELECT 'INDEX VERIFICATION' as section;
SELECT schemaname, tablename, indexname 
FROM pg_indexes 
WHERE tablename IN ('users', 'annotations') 
  AND indexname LIKE '%display_name%' 
   OR indexname LIKE '%location_point%'
   OR indexname LIKE '%lat_lng%';

-- 6. 验证触发器存在
SELECT 'TRIGGER VERIFICATION' as section;
SELECT trigger_name, event_object_table, action_statement 
FROM information_schema.triggers 
WHERE trigger_name IN ('set_annotations_location_point', 'update_users_updated_at', 'update_annotations_updated_at');

-- 7. 测试地理位置功能
SELECT 'POSTGIS FUNCTIONALITY TEST' as section;
SELECT ST_AsText(ST_MakePoint(-122.4194, 37.7749)) as san_francisco_point;

-- 8. 验证管理员用户
SELECT 'ADMIN USER VERIFICATION' as section;
SELECT email, username, display_name, role, email_verified 
FROM users 
WHERE email = 'admin@smellpin.com';

-- 9. 数据库连接测试
SELECT 'DATABASE CONNECTION TEST' as section;
SELECT 'SUCCESS: Database connection working' as result, CURRENT_TIMESTAMP as timestamp;