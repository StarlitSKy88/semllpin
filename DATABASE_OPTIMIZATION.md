# SmellPin Database Performance Optimization Guide

This guide provides comprehensive database performance optimizations for the SmellPin platform, focusing on achieving <100ms query response times for all LBS (Location-Based Services) operations.

## Overview

The optimization strategy includes:
- Advanced composite indexing for geographic queries
- Connection pool management with intelligent resource allocation
- Query caching and prepared statement optimization
- Real-time performance monitoring and alerting
- Automated maintenance and cleanup procedures
- PostgreSQL configuration tuning for geospatial workloads

## Implementation Files

### 1. Database Migrations
- **`migrations/019_advanced_composite_indexes.js`**: Comprehensive indexing strategy
- **`migrations/018_postgis_spatial_optimization.sql`**: PostGIS spatial optimizations

### 2. Configuration Files
- **`src/config/database-pool.ts`**: Advanced connection pool management
- **`config/postgresql-optimization.conf`**: PostgreSQL configuration optimizations

### 3. Services and Tools
- **`src/services/query-cache.ts`**: Multi-level query caching system
- **`src/services/query-analyzer.ts`**: Query performance analysis tools
- **`src/services/database-monitor.ts`**: Enhanced performance monitoring

### 4. Maintenance Scripts
- **`scripts/database-maintenance.js`**: Automated maintenance and cleanup

## Quick Start

### 1. Apply Database Migrations

```bash
# Run the advanced indexing migration
npm run migrate:up -- --name=019_advanced_composite_indexes.js

# Apply PostGIS optimizations (PostgreSQL only)
psql -d smellpin -f migrations/018_postgis_spatial_optimization.sql
```

### 2. Update Database Configuration

```javascript
// Replace existing database import with optimized version
import { initializeDatabase, getDatabase } from './src/config/database-pool';

// Initialize the optimized database connection
const db = await initializeDatabase();
```

### 3. Enable Query Caching

```javascript
// Use cached queries for better performance
import { executeQuery, cacheLocationQuery } from './src/services/query-cache';

// Cache geographic queries
const nearbyAnnotations = await cacheLocationQuery(
  db,
  'nearby_annotations',
  { north: 40.7128, south: 40.7489, east: -74.0059, west: -74.0445 },
  () => getNearbyAnnotations(lat, lng, radius),
  { ttl: 300, precision: 4 }
);
```

### 4. Apply PostgreSQL Configuration

```bash
# Backup current configuration
sudo cp /etc/postgresql/*/main/postgresql.conf /etc/postgresql/*/main/postgresql.conf.backup

# Apply optimizations (adjust paths as needed)
sudo cat config/postgresql-optimization.conf >> /etc/postgresql/*/main/postgresql.conf

# Reload configuration
sudo systemctl reload postgresql
# OR
SELECT pg_reload_conf();
```

### 5. Start Performance Monitoring

```javascript
import { startDatabaseMonitoring } from './src/services/database-monitor';

// Start monitoring with 30-second intervals
startDatabaseMonitoring(db, 30000);
```

### 6. Schedule Maintenance Tasks

```bash
# Add to crontab for automated maintenance
# Run full maintenance daily at 2 AM
0 2 * * * node /path/to/smellpin/scripts/database-maintenance.js --task=all

# Run cleanup every 6 hours
0 */6 * * * node /path/to/smellpin/scripts/database-maintenance.js --task=cleanup

# Generate performance reports weekly
0 0 * * 0 node /path/to/smellpin/scripts/database-maintenance.js --task=report
```

## Performance Targets

| Operation | Target Response Time | Optimization Strategy |
|-----------|---------------------|----------------------|
| Location queries | <50ms | Spatial indexes + caching |
| User annotations | <75ms | Composite indexes + prepared statements |
| Geofence detection | <100ms | PostGIS optimization + connection pooling |
| Analytics queries | <200ms | Materialized views + smart caching |
| Map data loading | <100ms | Geographic clustering + compression |

## Monitoring and Alerts

### Key Metrics to Monitor

1. **Query Performance**
   - Average response time: <100ms target
   - Slow query count: <5% of total queries
   - Cache hit ratio: >95%

2. **Connection Pool Health**
   - Pool utilization: <80%
   - Wait time: <50ms
   - Connection errors: <1%

3. **Database Resources**
   - Buffer hit ratio: >95%
   - Disk I/O wait: <10ms
   - Memory usage: <90%

### Performance Monitoring Queries

```sql
-- Check overall database performance
SELECT 
  schemaname,
  tablename,
  n_tup_ins + n_tup_upd + n_tup_del as total_writes,
  n_live_tup as live_rows,
  round(n_dead_tup::numeric / (n_live_tup + n_dead_tup + 1) * 100, 2) as bloat_ratio,
  last_vacuum,
  last_analyze
FROM pg_stat_user_tables
ORDER BY total_writes DESC;

-- Monitor slow queries
SELECT 
  query,
  calls,
  total_time,
  mean_time,
  max_time,
  rows
FROM pg_stat_statements 
WHERE mean_time > 100
ORDER BY mean_time DESC
LIMIT 20;

-- Check index usage
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_scan as scans,
  idx_tup_read as reads,
  idx_tup_fetch as fetches
FROM pg_stat_user_indexes
WHERE idx_scan = 0 AND schemaname = 'public'
ORDER BY pg_relation_size(indexrelid) DESC;
```

## Troubleshooting Common Issues

### High Query Response Times

1. **Check Index Usage**
   ```sql
   -- Find missing indexes
   SELECT schemaname, tablename, seq_scan, seq_tup_read
   FROM pg_stat_user_tables 
   WHERE seq_scan > seq_tup_read / 100
   ORDER BY seq_tup_read DESC;
   ```

2. **Analyze Query Plans**
   ```javascript
   import { analyzeQuery } from './src/services/query-analyzer';
   
   const analysis = await analyzeQuery(db, yourSlowQuery, params);
   console.log(analysis.recommendations);
   ```

3. **Check Connection Pool**
   ```javascript
   import { getPoolHealth } from './src/config/database-pool';
   
   const health = getPoolHealth();
   console.log(`Pool utilization: ${health.metrics.borrowed}/${health.metrics.max}`);
   ```

### Memory Issues

1. **Reduce work_mem** for individual sessions
2. **Increase shared_buffers** if you have available RAM
3. **Enable query result compression** in cache service

### High CPU Usage

1. **Check for CPU-intensive queries**
2. **Optimize PostGIS operations** with better spatial indexes
3. **Consider read replicas** for read-heavy workloads

## Advanced Optimizations

### Geographic Query Optimization

```javascript
// Use optimized location queries
import { buildOptimizedLocationQuery } from './src/config/database-pool';

const query = db('annotations')
  .select('*')
  .modify(queryBuilder => 
    buildOptimizedLocationQuery(queryBuilder, lat, lng, radius)
  );
```

### Prepared Statement Caching

```javascript
import { prepareStatement, executePreparedStatement } from './src/services/query-cache';

// Prepare frequently used queries
await prepareStatement(db, 'find_nearby_annotations', `
  SELECT * FROM annotations 
  WHERE ST_DWithin(location_point, ST_GeomFromText($1, 4326), $2)
  AND status = 'approved'
  ORDER BY location_point <-> ST_GeomFromText($1, 4326)
  LIMIT $3
`);

// Execute with parameters
const results = await executePreparedStatement(
  db, 
  'find_nearby_annotations',
  [`POINT(${lng} ${lat})`, radius, limit]
);
```

### Query Result Compression

```javascript
// Enable compression for large result sets
const compressedResults = await executeQuery(
  db,
  'large_dataset_query',
  () => db.raw(complexQuery),
  { 
    ttl: 600,
    useCache: true,
    tags: ['analytics', 'reports']
  }
);
```

## Maintenance Best Practices

### Daily Tasks
- Monitor slow query logs
- Check connection pool health
- Review cache hit ratios
- Verify backup completion

### Weekly Tasks
- Run comprehensive maintenance script
- Analyze query performance trends  
- Review and optimize new slow queries
- Update table statistics

### Monthly Tasks
- Review and update index strategies
- Analyze database growth patterns
- Plan capacity scaling needs
- Performance test new features

## Scaling Considerations

### Vertical Scaling (Single Server)
- Increase RAM for larger shared_buffers
- Use faster SSD storage
- Add CPU cores for parallel processing

### Horizontal Scaling (Multiple Servers)
- Implement read replicas for read-heavy operations
- Use connection pooling (PgBouncer) at application level
- Consider database sharding for very large datasets
- Implement Redis caching layer

### Geographic Distribution
- Use geographic database clustering
- Implement region-specific read replicas
- Consider CDN for static geographic data
- Optimize for cross-region latency

## Security Considerations

- Regular security updates for PostgreSQL
- Monitor database access logs
- Implement proper SSL/TLS encryption
- Use connection string encryption
- Regular backup testing and validation

## Support and Resources

- **PostgreSQL Documentation**: https://www.postgresql.org/docs/
- **PostGIS Documentation**: https://postgis.net/docs/
- **Performance Monitoring Tools**: pg_stat_statements, pg_stat_activity
- **Community Resources**: PostgreSQL performance mailing lists

## Contributing

When contributing performance optimizations:

1. Always test in staging environment first
2. Document performance impact measurements
3. Include rollback procedures
4. Update monitoring queries if needed
5. Follow existing code style and patterns

For questions or issues, please create a GitHub issue with:
- Database version and configuration
- Query examples and explain plans
- Performance measurements before/after
- Error logs if applicable