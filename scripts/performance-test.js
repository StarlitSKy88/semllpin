#!/usr/bin/env node

/**
 * SmellPin Database Performance Testing Script
 * 
 * Tests the effectiveness of database optimizations by running
 * representative queries and measuring response times.
 */

const knex = require('knex');
const yargs = require('yargs');

const config = {
  database: {
    client: 'postgresql',
    connection: {
      connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/smellpin',
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    },
    pool: { min: 2, max: 10 }
  },
  
  testConfig: {
    warmupRuns: 3,       // Number of warmup runs before measurement
    measurementRuns: 10, // Number of runs to measure and average
    concurrentUsers: 5,  // Simulate concurrent users
    targetResponseTime: 100 // Target response time in milliseconds
  }
};

class PerformanceTester {
  constructor() {
    this.db = knex(config.database);
    this.results = [];
  }

  /**
   * Log test results
   */
  log(message, data = {}) {
    console.log(`[${new Date().toISOString()}] ${message}`, 
                Object.keys(data).length > 0 ? JSON.stringify(data, null, 2) : '');
  }

  /**
   * Measure query execution time
   */
  async measureQuery(name, queryFn, runs = config.testConfig.measurementRuns) {
    const times = [];
    
    // Warmup runs
    for (let i = 0; i < config.testConfig.warmupRuns; i++) {
      await queryFn();
    }
    
    // Measurement runs
    for (let i = 0; i < runs; i++) {
      const startTime = process.hrtime();
      await queryFn();
      const [seconds, nanoseconds] = process.hrtime(startTime);
      const milliseconds = seconds * 1000 + nanoseconds / 1000000;
      times.push(milliseconds);
    }
    
    const result = {
      name,
      runs,
      min: Math.min(...times),
      max: Math.max(...times),
      avg: times.reduce((sum, time) => sum + time, 0) / times.length,
      median: times.sort((a, b) => a - b)[Math.floor(times.length / 2)],
      p95: times.sort((a, b) => a - b)[Math.floor(times.length * 0.95)],
      times
    };
    
    this.results.push(result);
    return result;
  }

  /**
   * Test basic connectivity and database status
   */
  async testConnectivity() {
    this.log('Testing database connectivity...');
    
    try {
      const result = await this.measureQuery('connectivity', async () => {
        return await this.db.raw('SELECT 1 as test');
      });
      
      this.log('Connectivity test completed', {
        avgTime: `${result.avg.toFixed(2)}ms`,
        status: result.avg < 10 ? 'EXCELLENT' : result.avg < 50 ? 'GOOD' : 'SLOW'
      });
      
      return result;
    } catch (error) {
      this.log('Connectivity test failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Test location-based queries (core LBS functionality)
   */
  async testLocationQueries() {
    this.log('Testing location-based queries...');
    
    // Test 1: Nearby annotations query
    const nearbyResult = await this.measureQuery('nearby_annotations', async () => {
      return await this.db.raw(`
        SELECT id, latitude, longitude, smell_intensity, created_at
        FROM annotations 
        WHERE status = 'approved'
          AND latitude BETWEEN 40.7 AND 40.8
          AND longitude BETWEEN -74.1 AND -74.0
        ORDER BY created_at DESC
        LIMIT 50
      `);
    });

    // Test 2: PostGIS spatial query (if available)
    let spatialResult = null;
    try {
      spatialResult = await this.measureQuery('postgis_spatial', async () => {
        return await this.db.raw(`
          SELECT id, latitude, longitude, smell_intensity,
                 ST_Distance(location_point, ST_GeomFromText('POINT(-74.006 40.7128)', 4326)) as distance
          FROM annotations 
          WHERE status = 'approved'
            AND ST_DWithin(location_point, ST_GeomFromText('POINT(-74.006 40.7128)', 4326), 1000)
          ORDER BY distance
          LIMIT 50
        `);
      });
    } catch (error) {
      this.log('PostGIS spatial query skipped (extension may not be available)');
    }

    // Test 3: Geographic aggregation query
    const aggregationResult = await this.measureQuery('geographic_aggregation', async () => {
      return await this.db.raw(`
        SELECT 
          ROUND(latitude, 2) as lat_group,
          ROUND(longitude, 2) as lng_group,
          COUNT(*) as annotation_count,
          AVG(smell_intensity) as avg_intensity
        FROM annotations 
        WHERE status = 'approved'
          AND created_at >= NOW() - INTERVAL '30 days'
        GROUP BY lat_group, lng_group
        HAVING COUNT(*) >= 5
        ORDER BY annotation_count DESC
        LIMIT 100
      `);
    });

    this.log('Location query tests completed', {
      nearbyQuery: `${nearbyResult.avg.toFixed(2)}ms (${this.getPerformanceRating(nearbyResult.avg)})`,
      spatialQuery: spatialResult ? `${spatialResult.avg.toFixed(2)}ms (${this.getPerformanceRating(spatialResult.avg)})` : 'N/A',
      aggregationQuery: `${aggregationResult.avg.toFixed(2)}ms (${this.getPerformanceRating(aggregationResult.avg)})`
    });

    return { nearbyResult, spatialResult, aggregationResult };
  }

  /**
   * Test user and social queries
   */
  async testUserQueries() {
    this.log('Testing user and social queries...');

    // Test 1: User profile query
    const userProfileResult = await this.measureQuery('user_profile', async () => {
      return await this.db.raw(`
        SELECT u.*, 
               COUNT(DISTINCT a.id) as annotation_count,
               COUNT(DISTINCT al.id) as total_likes_received
        FROM users u
        LEFT JOIN annotations a ON u.id = a.user_id AND a.status = 'approved'
        LEFT JOIN annotation_likes al ON a.id = al.annotation_id
        WHERE u.status = 'active'
        GROUP BY u.id
        ORDER BY annotation_count DESC
        LIMIT 50
      `);
    });

    // Test 2: User activity feed query
    const activityFeedResult = await this.measureQuery('activity_feed', async () => {
      return await this.db.raw(`
        SELECT a.*, u.username, u.display_name,
               COUNT(al.id) as like_count,
               COUNT(ac.id) as comment_count
        FROM annotations a
        JOIN users u ON a.user_id = u.id
        LEFT JOIN annotation_likes al ON a.id = al.annotation_id
        LEFT JOIN annotation_comments ac ON a.id = ac.annotation_id AND ac.status = 'active'
        WHERE a.status = 'approved'
          AND a.created_at >= NOW() - INTERVAL '7 days'
        GROUP BY a.id, u.id
        ORDER BY a.created_at DESC
        LIMIT 50
      `);
    });

    this.log('User query tests completed', {
      userProfile: `${userProfileResult.avg.toFixed(2)}ms (${this.getPerformanceRating(userProfileResult.avg)})`,
      activityFeed: `${activityFeedResult.avg.toFixed(2)}ms (${this.getPerformanceRating(activityFeedResult.avg)})`
    });

    return { userProfileResult, activityFeedResult };
  }

  /**
   * Test analytics and reporting queries
   */
  async testAnalyticsQueries() {
    this.log('Testing analytics and reporting queries...');

    // Test 1: Daily statistics
    const dailyStatsResult = await this.measureQuery('daily_statistics', async () => {
      return await this.db.raw(`
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as annotation_count,
          AVG(smell_intensity) as avg_intensity,
          COUNT(DISTINCT user_id) as active_users
        FROM annotations
        WHERE status = 'approved'
          AND created_at >= NOW() - INTERVAL '30 days'
        GROUP BY DATE(created_at)
        ORDER BY date DESC
      `);
    });

    // Test 2: Popular locations
    const popularLocationsResult = await this.measureQuery('popular_locations', async () => {
      return await this.db.raw(`
        SELECT 
          country,
          region,
          city,
          COUNT(*) as annotation_count,
          AVG(smell_intensity) as avg_intensity,
          MAX(created_at) as latest_annotation
        FROM annotations
        WHERE status = 'approved'
          AND created_at >= NOW() - INTERVAL '90 days'
          AND country IS NOT NULL
        GROUP BY country, region, city
        HAVING COUNT(*) >= 10
        ORDER BY annotation_count DESC
        LIMIT 50
      `);
    });

    this.log('Analytics query tests completed', {
      dailyStats: `${dailyStatsResult.avg.toFixed(2)}ms (${this.getPerformanceRating(dailyStatsResult.avg)})`,
      popularLocations: `${popularLocationsResult.avg.toFixed(2)}ms (${this.getPerformanceRating(popularLocationsResult.avg)})`
    });

    return { dailyStatsResult, popularLocationsResult };
  }

  /**
   * Test concurrent query performance
   */
  async testConcurrentQueries() {
    this.log(`Testing concurrent query performance (${config.testConfig.concurrentUsers} concurrent users)...`);

    const concurrentQuery = async () => {
      return await this.db.raw(`
        SELECT id, latitude, longitude, smell_intensity, description
        FROM annotations 
        WHERE status = 'approved'
          AND smell_intensity >= 5
        ORDER BY created_at DESC
        LIMIT 20
      `);
    };

    // Create multiple concurrent promises
    const promises = [];
    const startTime = process.hrtime();
    
    for (let i = 0; i < config.testConfig.concurrentUsers; i++) {
      promises.push(concurrentQuery());
    }

    await Promise.all(promises);
    
    const [seconds, nanoseconds] = process.hrtime(startTime);
    const totalTime = seconds * 1000 + nanoseconds / 1000000;
    const avgTimePerQuery = totalTime; // Since queries run concurrently

    this.log('Concurrent query test completed', {
      concurrentUsers: config.testConfig.concurrentUsers,
      totalTime: `${totalTime.toFixed(2)}ms`,
      avgTimePerQuery: `${avgTimePerQuery.toFixed(2)}ms`,
      rating: this.getPerformanceRating(avgTimePerQuery)
    });

    return {
      concurrentUsers: config.testConfig.concurrentUsers,
      totalTime,
      avgTimePerQuery
    };
  }

  /**
   * Test database health metrics
   */
  async testDatabaseHealth() {
    this.log('Checking database health metrics...');

    try {
      // Check table statistics
      const tableStatsResult = await this.db.raw(`
        SELECT 
          schemaname,
          tablename,
          n_live_tup as live_rows,
          n_dead_tup as dead_rows,
          CASE 
            WHEN n_live_tup + n_dead_tup > 0 
            THEN ROUND((n_dead_tup::float / (n_live_tup + n_dead_tup)::float) * 100, 2)
            ELSE 0 
          END as bloat_percentage,
          last_vacuum,
          last_analyze
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
        ORDER BY n_live_tup DESC
        LIMIT 10
      `);

      // Check index usage
      const indexStatsResult = await this.db.raw(`
        SELECT 
          schemaname,
          tablename,
          indexname,
          idx_scan,
          idx_tup_read,
          idx_tup_fetch
        FROM pg_stat_user_indexes
        WHERE schemaname = 'public'
        ORDER BY idx_scan DESC
        LIMIT 10
      `);

      // Check buffer hit ratio
      const bufferHitResult = await this.db.raw(`
        SELECT 
          sum(heap_blks_read) as heap_read,
          sum(heap_blks_hit) as heap_hit,
          CASE 
            WHEN sum(heap_blks_hit) + sum(heap_blks_read) > 0
            THEN round(sum(heap_blks_hit)::numeric / (sum(heap_blks_hit) + sum(heap_blks_read)) * 100, 2)
            ELSE 0
          END as hit_ratio
        FROM pg_statio_user_tables
      `);

      const bufferHitRatio = bufferHitResult.rows[0]?.hit_ratio || 0;
      
      this.log('Database health check completed', {
        tablesChecked: tableStatsResult.rows.length,
        indexesChecked: indexStatsResult.rows.length,
        bufferHitRatio: `${bufferHitRatio}%`,
        healthRating: bufferHitRatio >= 95 ? 'EXCELLENT' : bufferHitRatio >= 90 ? 'GOOD' : 'NEEDS_ATTENTION'
      });

      return {
        tableStats: tableStatsResult.rows,
        indexStats: indexStatsResult.rows,
        bufferHitRatio
      };

    } catch (error) {
      this.log('Database health check failed (may not be PostgreSQL)', { error: error.message });
      return null;
    }
  }

  /**
   * Get performance rating based on response time
   */
  getPerformanceRating(timeMs) {
    if (timeMs <= 50) return 'EXCELLENT';
    if (timeMs <= 100) return 'GOOD';
    if (timeMs <= 200) return 'ACCEPTABLE';
    if (timeMs <= 500) return 'SLOW';
    return 'CRITICAL';
  }

  /**
   * Generate performance summary
   */
  generateSummary() {
    const summary = {
      timestamp: new Date().toISOString(),
      totalTests: this.results.length,
      targetResponseTime: config.testConfig.targetResponseTime,
      results: this.results.map(result => ({
        name: result.name,
        avgTime: Math.round(result.avg * 100) / 100,
        medianTime: Math.round(result.median * 100) / 100,
        p95Time: Math.round(result.p95 * 100) / 100,
        rating: this.getPerformanceRating(result.avg),
        meetsTarget: result.avg <= config.testConfig.targetResponseTime
      })),
      overallRating: this.calculateOverallRating()
    };

    return summary;
  }

  /**
   * Calculate overall performance rating
   */
  calculateOverallRating() {
    const avgResponseTimes = this.results.map(r => r.avg);
    const overallAvg = avgResponseTimes.reduce((sum, time) => sum + time, 0) / avgResponseTimes.length;
    
    const meetingTarget = this.results.filter(r => r.avg <= config.testConfig.targetResponseTime).length;
    const targetRatio = meetingTarget / this.results.length;

    if (overallAvg <= 50 && targetRatio >= 0.9) return 'EXCELLENT';
    if (overallAvg <= 100 && targetRatio >= 0.8) return 'GOOD';
    if (overallAvg <= 200 && targetRatio >= 0.7) return 'ACCEPTABLE';
    if (overallAvg <= 500 && targetRatio >= 0.5) return 'NEEDS_IMPROVEMENT';
    return 'CRITICAL';
  }

  /**
   * Run comprehensive performance test suite
   */
  async runFullTestSuite() {
    this.log('Starting comprehensive SmellPin database performance test suite...');
    
    try {
      // Test 1: Connectivity
      await this.testConnectivity();
      
      // Test 2: Location-based queries (most important for SmellPin)
      await this.testLocationQueries();
      
      // Test 3: User and social queries
      await this.testUserQueries();
      
      // Test 4: Analytics queries
      await this.testAnalyticsQueries();
      
      // Test 5: Concurrent performance
      await this.testConcurrentQueries();
      
      // Test 6: Database health
      await this.testDatabaseHealth();
      
      // Generate and display summary
      const summary = this.generateSummary();
      
      this.log('\n' + '='.repeat(60));
      this.log('PERFORMANCE TEST SUMMARY');
      this.log('='.repeat(60));
      this.log(`Overall Rating: ${summary.overallRating}`);
      this.log(`Tests Completed: ${summary.totalTests}`);
      this.log(`Target Response Time: ${summary.targetResponseTime}ms`);
      this.log('\nDetailed Results:');
      
      summary.results.forEach(result => {
        const status = result.meetsTarget ? '✅' : '❌';
        this.log(`${status} ${result.name}: ${result.avgTime}ms (${result.rating})`);
      });
      
      this.log('\nRecommendations:');
      
      const slowQueries = summary.results.filter(r => !r.meetsTarget);
      if (slowQueries.length === 0) {
        this.log('🎉 All queries meet performance targets!');
      } else {
        this.log(`⚠️  ${slowQueries.length} queries exceed target response time:`);
        slowQueries.forEach(query => {
          this.log(`   - Optimize "${query.name}" query (${query.avgTime}ms)`);
        });
      }
      
      if (summary.overallRating === 'CRITICAL' || summary.overallRating === 'NEEDS_IMPROVEMENT') {
        this.log('\n🔧 Suggested optimizations:');
        this.log('   - Run database maintenance: node scripts/database-maintenance.js');
        this.log('   - Apply PostgreSQL configuration: config/postgresql-optimization.conf');
        this.log('   - Check index usage and add missing indexes');
        this.log('   - Consider upgrading database hardware');
      }
      
      return summary;
      
    } catch (error) {
      this.log('Performance test suite failed', { error: error.message });
      throw error;
    }
  }

  /**
   * Close database connection
   */
  async close() {
    await this.db.destroy();
  }
}

// Command line interface
async function main() {
  const argv = yargs
    .option('test', {
      alias: 't',
      type: 'string',
      choices: ['all', 'connectivity', 'location', 'user', 'analytics', 'concurrent', 'health'],
      default: 'all',
      description: 'Type of performance test to run'
    })
    .option('runs', {
      alias: 'r',
      type: 'number',
      default: 10,
      description: 'Number of measurement runs per test'
    })
    .option('concurrent', {
      alias: 'c',
      type: 'number',
      default: 5,
      description: 'Number of concurrent users to simulate'
    })
    .help()
    .argv;

  // Update config based on command line arguments
  config.testConfig.measurementRuns = argv.runs;
  config.testConfig.concurrentUsers = argv.concurrent;

  const tester = new PerformanceTester();

  try {
    switch (argv.test) {
      case 'connectivity':
        await tester.testConnectivity();
        break;
      case 'location':
        await tester.testLocationQueries();
        break;
      case 'user':
        await tester.testUserQueries();
        break;
      case 'analytics':
        await tester.testAnalyticsQueries();
        break;
      case 'concurrent':
        await tester.testConcurrentQueries();
        break;
      case 'health':
        await tester.testDatabaseHealth();
        break;
      case 'all':
      default:
        await tester.runFullTestSuite();
        break;
    }
  } catch (error) {
    console.error('Performance test failed:', error);
    process.exit(1);
  } finally {
    await tester.close();
  }
}

// Export for programmatic use
module.exports = PerformanceTester;

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}