/**
 * Optimized Database Configuration for SmellPin
 * Target: <200ms query response times for LBS system
 * Features: Advanced connection pooling, query monitoring, performance optimization
 */

import { Knex } from 'knex';
import knex from 'knex';
import { config } from './config';
import { logger } from '../utils/logger';

// Performance monitoring interface
interface QueryMetrics {
  queryName: string;
  duration: number;
  timestamp: Date;
  success: boolean;
  errorMessage?: string;
}

// Query metrics storage (in-memory for now, could be Redis in production)
const queryMetricsHistory: QueryMetrics[] = [];
const MAX_METRICS_HISTORY = 1000;

// Connection pool configuration optimized for LBS workload
const getOptimizedPoolConfig = (isProduction: boolean) => ({
  min: isProduction ? 5 : 2,           // Minimum connections
  max: isProduction ? 25 : 10,         // Maximum connections  
  createTimeoutMillis: 3000,           // Timeout for creating new connections
  acquireTimeoutMillis: 10000,         // Timeout for acquiring connection from pool
  idleTimeoutMillis: 30000,            // Close idle connections after 30s
  reapIntervalMillis: 1000,            // Check for idle connections every 1s
  createRetryIntervalMillis: 100,      // Retry interval for failed connections
  propagateCreateError: false,         // Don't propagate connection creation errors immediately
  
  // Advanced pool settings for high-concurrency LBS workload
  evictionRunIntervalMillis: 10000,    // Check for connections to evict every 10s
  numTestsPerEvictionRun: 3,           // Number of connections to test per eviction run
  softIdleTimeoutMillis: 5000,         // Soft idle timeout
  testOnBorrow: true,                  // Test connections before use
  
  // Connection validation
  validateConnection: async (connection: any) => {
    try {
      await connection.raw('SELECT 1');
      return true;
    } catch (error) {
      logger.warn('Connection validation failed:', error);
      return false;
    }
  },

  // Connection lifecycle hooks
  afterCreate: (connection: any, done: Function) => {
    // Optimize connection for geographic queries
    connection.raw(`
      SET work_mem = '32MB';
      SET random_page_cost = 1.0;
      SET effective_io_concurrency = 4;
      SET enable_seqscan = off;
      SET enable_bitmapscan = on;
      SET enable_hashjoin = on;
      SET join_collapse_limit = 12;
      SET from_collapse_limit = 12;
    `).then(() => {
      done(null, connection);
    }).catch(done);
  }
});

// Database configuration with environment-specific optimizations
const createDatabaseConfig = (): Knex.Config => {
  const isProduction = config.NODE_ENV === 'production';
  const isDevelopment = config.NODE_ENV === 'development';
  const isTest = config.NODE_ENV === 'test';

  // SQLite for development/testing (when not using PostgreSQL)
  if ((isDevelopment || isTest) && process.env['DB_TYPE'] !== 'postgresql') {
    return {
      client: 'sqlite3',
      connection: {
        filename: isTest ? ':memory:' : './smellpin.sqlite',
      },
      useNullAsDefault: true,
      pool: getOptimizedPoolConfig(false),
      migrations: {
        directory: './migrations',
        tableName: 'knex_migrations',
      },
      seeds: {
        directory: './seeds',
      },
      debug: isDevelopment,
      acquireConnectionTimeout: 10000,
    };
  }

  // PostgreSQL configuration (production and development with PostgreSQL)
  return {
    client: 'postgresql',
    connection: {
      connectionString: config.DATABASE_URL,
      host: config.database.host,
      port: config.database.port,
      user: config.database.username,
      password: config.database.password,
      database: config.database.database,
      ssl: config.database.ssl ? { 
        rejectUnauthorized: false,
        // Enable SSL session reuse for better performance
        secureProtocol: 'TLSv1_2_method',
        ciphers: 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!SHA1:!AEAD'
      } : false,
      
      // PostgreSQL-specific optimizations
      statement_timeout: 30000,         // 30-second query timeout
      query_timeout: 25000,             // 25-second query timeout  
      application_name: 'SmellPin-LBS', // For monitoring
      
      // Connection options for performance
      options: isProduction ? 
        '-c default_transaction_isolation=read_committed -c timezone=UTC' : 
        undefined,
    },
    
    pool: getOptimizedPoolConfig(isProduction),
    
    // Query optimization settings
    searchPath: ['public', 'postgis'],
    
    migrations: {
      directory: './migrations',
      tableName: 'knex_migrations',
      schemaName: 'public',
    },
    
    seeds: {
      directory: './seeds',
    },
    
    // Enable query debugging in development
    debug: isDevelopment,
    
    // Advanced connection settings
    acquireConnectionTimeout: 10000,
    asyncStackTraces: isDevelopment,
    
    // Custom query processing
    postProcessResponse: (result: any, queryContext: any) => {
      // Log slow queries in production
      if (queryContext && queryContext.__knexQueryUid && isProduction) {
        const duration = Date.now() - (queryContext.startTime || Date.now());
        if (duration > 200) { // Log queries > 200ms
          logger.warn(`Slow query detected: ${duration}ms`, {
            queryUid: queryContext.__knexQueryUid,
            sql: queryContext.sql?.slice(0, 200)
          });
        }
      }
      return result;
    },
    
    // Custom error handling  
    wrapIdentifier: (value: string, origImpl: Function) => origImpl(value),
    
    // Performance monitoring hook
    log: {
      warn(message: string) {
        logger.warn('Knex warning:', message);
      },
      error(message: string) {
        logger.error('Knex error:', message);
      },
      deprecate(message: string) {
        logger.warn('Knex deprecation:', message);
      },
      debug(message: string) {
        if (isDevelopment) {
          logger.debug('Knex debug:', message);
        }
      }
    }
  };
};

// Create optimized database instance
export const db = knex(createDatabaseConfig());

// Enhanced connection management
export const connectDatabase = async (): Promise<void> => {
  try {
    logger.info('Initializing database connection...');
    
    // Test basic connectivity
    await db.raw('SELECT 1+1 as result');
    logger.info('✅ Database connection established');

    // Verify PostGIS extension in production
    if (config.NODE_ENV === 'production') {
      try {
        await db.raw('SELECT PostGIS_Version()');
        logger.info('✅ PostGIS extension verified');
      } catch (error) {
        logger.error('❌ PostGIS extension not available:', error);
        throw new Error('PostGIS extension required for LBS functionality');
      }

      // Run migrations
      await db.migrate.latest();
      logger.info('✅ Database migrations completed');
    }

    // Optimize database settings for LBS workload
    if (process.env['DB_TYPE'] === 'postgresql') {
      await optimizeDatabaseSettings();
    }
    
    // Start performance monitoring
    startPerformanceMonitoring();
    
  } catch (error) {
    logger.error('❌ Database connection failed:', error);
    throw error;
  }
};

// Optimize database settings for geographic queries
const optimizeDatabaseSettings = async (): Promise<void> => {
  try {
    // Set session-level optimizations for geographic queries
    await db.raw(`
      SET work_mem = '64MB';
      SET shared_buffers = '256MB';
      SET effective_cache_size = '1GB';
      SET random_page_cost = 1.1;
      SET seq_page_cost = 1.0;
      SET cpu_tuple_cost = 0.01;
      SET cpu_index_tuple_cost = 0.005;
      SET cpu_operator_cost = 0.0025;
      SET enable_seqscan = on;
      SET enable_indexscan = on;
      SET enable_bitmapscan = on;
      SET enable_tidscan = on;
      SET enable_sort = on;
      SET enable_hashagg = on;
      SET enable_nestloop = on;
      SET enable_mergejoin = on;
      SET enable_hashjoin = on;
      SET constraint_exclusion = partition;
      SET default_statistics_target = 100;
    `);
    
    logger.info('✅ Database settings optimized for LBS workload');
  } catch (error) {
    logger.warn('⚠️ Could not optimize database settings:', error);
  }
};

// Performance monitoring system
const startPerformanceMonitoring = (): void => {
  // Monitor connection pool health every 30 seconds
  setInterval(async () => {
    try {
      const pool = (db as any).client?.pool;
      if (pool) {
        const metrics = {
          size: pool.size,
          available: pool.available,
          borrowed: pool.borrowed,
          invalid: pool.invalid,
          pending: pool.pending,
          min: pool.min,
          max: pool.max
        };
        
        // Log warnings for pool exhaustion
        if (metrics.available === 0 && metrics.pending > 0) {
          logger.warn('⚠️ Connection pool exhausted', metrics);
        }
        
        // Log debug info in development
        if (config.NODE_ENV === 'development') {
          logger.debug('Connection pool metrics:', metrics);
        }
      }
    } catch (error) {
      logger.error('Error monitoring connection pool:', error);
    }
  }, 30000);
  
  // Clean up old query metrics
  setInterval(() => {
    if (queryMetricsHistory.length > MAX_METRICS_HISTORY) {
      queryMetricsHistory.splice(0, queryMetricsHistory.length - MAX_METRICS_HISTORY);
    }
  }, 60000);
};

// Enhanced query monitoring wrapper
export const monitorQuery = async <T>(
  queryName: string,
  queryFn: () => Promise<T>,
  options: { 
    slowQueryThreshold?: number;
    logParams?: boolean;
    timeout?: number;
  } = {}
): Promise<T> => {
  const startTime = Date.now();
  const slowThreshold = options.slowQueryThreshold || 200; // 200ms default
  
  let result: T;
  let error: Error | null = null;
  
  try {
    // Add query timeout if specified
    if (options.timeout) {
      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`Query timeout after ${options.timeout}ms`)), options.timeout);
      });
      
      result = await Promise.race([queryFn(), timeoutPromise]);
    } else {
      result = await queryFn();
    }
    
  } catch (e) {
    error = e as Error;
    throw e;
  } finally {
    const duration = Date.now() - startTime;
    
    // Record metrics
    const metrics: QueryMetrics = {
      queryName,
      duration,
      timestamp: new Date(),
      success: !error,
      errorMessage: error?.message
    };
    queryMetricsHistory.push(metrics);
    
    // Log slow queries
    if (duration > slowThreshold) {
      logger.warn(`🐌 Slow query: ${queryName}`, {
        duration: `${duration}ms`,
        success: !error,
        error: error?.message
      });
    }
    
    // Log all queries in development
    if (config.NODE_ENV === 'development') {
      logger.debug(`Query: ${queryName}`, {
        duration: `${duration}ms`,
        success: !error
      });
    }
  }
  
  return result!;
};

// Geographic query optimization helpers
export const buildOptimizedLocationQuery = (
  query: Knex.QueryBuilder,
  latitude: number,
  longitude: number,
  radiusInMeters: number = 1000,
  tableName: string = 'annotations',
  locationColumn: string = 'location'
): Knex.QueryBuilder => {
  // Use ST_DWithin for better performance with spatial indexes
  return query.whereRaw(
    `ST_DWithin(${tableName}.${locationColumn}, ST_GeogFromText(?), ?)`,
    [`POINT(${longitude} ${latitude})`, radiusInMeters]
  );
};

export const buildBoundingBoxQuery = (
  query: Knex.QueryBuilder,
  bounds: {
    north: number;
    south: number;
    east: number;
    west: number;
  },
  tableName: string = 'annotations',
  locationColumn: string = 'location'
): Knex.QueryBuilder => {
  // Use bounding box for initial filtering, then precise distance if needed
  return query.whereRaw(
    `${tableName}.${locationColumn} && ST_MakeEnvelope(?, ?, ?, ?, 4326)`,
    [bounds.west, bounds.south, bounds.east, bounds.north]
  );
};

// Connection pool health check
export const checkConnectionPoolHealth = (): {
  healthy: boolean;
  metrics: any;
  warnings: string[];
} => {
  const pool = (db as any).client?.pool;
  const warnings: string[] = [];
  
  if (!pool) {
    return { healthy: false, metrics: null, warnings: ['Connection pool not available'] };
  }
  
  const metrics = {
    size: pool.size || 0,
    available: pool.available || 0,
    borrowed: pool.borrowed || 0,
    invalid: pool.invalid || 0,
    pending: pool.pending || 0,
    min: pool.min || 0,
    max: pool.max || 0
  };
  
  // Check for potential issues
  if (metrics.available === 0 && metrics.pending > 0) {
    warnings.push('Connection pool exhausted - requests are waiting');
  }
  
  if (metrics.borrowed > metrics.max * 0.8) {
    warnings.push('Connection pool usage is high (>80%)');
  }
  
  if (metrics.invalid > 0) {
    warnings.push(`${metrics.invalid} invalid connections in pool`);
  }
  
  const healthy = warnings.length === 0;
  
  return { healthy, metrics, warnings };
};

// Get query performance statistics
export const getQueryPerformanceStats = (limit: number = 10): {
  slowQueries: QueryMetrics[];
  averageResponseTime: number;
  totalQueries: number;
  errorRate: number;
} => {
  const recentMetrics = queryMetricsHistory.slice(-1000); // Last 1000 queries
  
  const slowQueries = recentMetrics
    .filter(m => m.duration > 200)
    .sort((a, b) => b.duration - a.duration)
    .slice(0, limit);
  
  const totalQueries = recentMetrics.length;
  const totalDuration = recentMetrics.reduce((sum, m) => sum + m.duration, 0);
  const errorCount = recentMetrics.filter(m => !m.success).length;
  
  return {
    slowQueries,
    averageResponseTime: totalQueries > 0 ? totalDuration / totalQueries : 0,
    totalQueries,
    errorRate: totalQueries > 0 ? errorCount / totalQueries : 0
  };
};

// Graceful shutdown
export const disconnectDatabase = async (): Promise<void> => {
  try {
    await db.destroy();
    logger.info('✅ Database connection closed gracefully');
  } catch (error) {
    logger.error('❌ Error closing database connection:', error);
    throw error;
  }
};

// Health check for monitoring
export const checkDatabaseHealth = async (): Promise<{
  healthy: boolean;
  responseTime: number;
  details: any;
}> => {
  const startTime = Date.now();
  
  try {
    // Basic connectivity test
    await db.raw('SELECT 1');
    const responseTime = Date.now() - startTime;
    
    // Check PostGIS availability
    let postgisVersion = null;
    try {
      const result = await db.raw('SELECT PostGIS_Version() as version');
      postgisVersion = result.rows?.[0]?.version || 'Available';
    } catch (e) {
      // PostGIS not available
    }
    
    const poolHealth = checkConnectionPoolHealth();
    
    return {
      healthy: responseTime < 1000 && poolHealth.healthy,
      responseTime,
      details: {
        postgis: postgisVersion,
        connectionPool: poolHealth,
        timestamp: new Date().toISOString()
      }
    };
  } catch (error) {
    return {
      healthy: false,
      responseTime: Date.now() - startTime,
      details: {
        error: (error as Error).message,
        timestamp: new Date().toISOString()
      }
    };
  }
};

// Transaction helper with performance monitoring
export const withTransaction = async <T>(
  callback: (trx: Knex.Transaction) => Promise<T>,
  options: { timeout?: number; isolationLevel?: string } = {}
): Promise<T> => {
  const startTime = Date.now();
  
  return monitorQuery('transaction', async () => {
    const trx = await db.transaction();
    
    try {
      // Set isolation level if specified
      if (options.isolationLevel) {
        await trx.raw(`SET TRANSACTION ISOLATION LEVEL ${options.isolationLevel}`);
      }
      
      // Set timeout if specified
      if (options.timeout) {
        await trx.raw(`SET LOCAL statement_timeout = ${options.timeout}`);
      }
      
      const result = await callback(trx);
      await trx.commit();
      
      return result;
    } catch (error) {
      await trx.rollback();
      throw error;
    }
  }, { slowQueryThreshold: 500 }); // Transactions should be faster
};

export default db;