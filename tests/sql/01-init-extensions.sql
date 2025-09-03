-- 测试数据库扩展初始化
-- SmellPin自动化测试方案2.0

-- 启用PostGIS扩展
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;

-- 启用性能统计扩展
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- 启用UUID生成扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 启用加密函数扩展
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 验证扩展安装
SELECT 
    extname as "Extension", 
    extversion as "Version"
FROM pg_extension 
WHERE extname IN ('postgis', 'pg_stat_statements', 'uuid-ossp', 'pgcrypto')
ORDER BY extname;