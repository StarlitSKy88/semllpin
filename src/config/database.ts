import { Knex } from 'knex';
import knex from 'knex';
import { config } from './config';
import { logger } from '../utils/logger';

// Database configuration - prioritize PostgreSQL
const dbConfig: Knex.Config = process.env['DB_TYPE'] === 'sqlite' || (!process.env['DATABASE_URL'] && process.env['NODE_ENV'] === 'test') ? {
  // SQLite configuration for test environment only
  client: 'sqlite3',
  connection: {
    filename: process.env['NODE_ENV'] === 'test' ? './test.sqlite' : './smellpin.sqlite',
  },
  useNullAsDefault: true,
  pool: {
    min: 1,
    max: 1,
  },
  migrations: {
    directory: './migrations',
    tableName: 'knex_migrations',
  },
  seeds: {
    directory: './seeds',
  },
  debug: config.NODE_ENV === 'development',
} : {
  // PostgreSQL configuration for development and production
  client: 'postgresql',
  connection: config.DATABASE_URL ? {
    connectionString: config.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  } : {
    host: config.database.host,
    port: config.database.port,
    user: config.database.username,
    password: config.database.password,
    database: config.database.database,
    ssl: config.database.ssl ? { rejectUnauthorized: false } : false,
  },
  pool: {
    min: config.NODE_ENV === 'production' ? 8 : 3,        // Minimum idle connections
    max: config.NODE_ENV === 'production' ? 50 : 15,      // Maximum total connections
    createTimeoutMillis: 8000,                            // 8s to create new connection
    acquireTimeoutMillis: 10000,                          // 10s to acquire from pool
    idleTimeoutMillis: config.NODE_ENV === 'production' ? 300000 : 180000,  // Close idle connections
    destroyTimeoutMillis: 3000,                           // 3s to destroy connection
    propagateCreateError: false,                          // Don't fail immediately on create error
    
    // Connection lifecycle hooks
    afterCreate: async (conn: any, done: (err: Error | null, conn?: any) => void) => {
      try {
        logger.debug('🔗 New database connection created');
        // Set connection encoding and timezone for PostgreSQL with timeout protection
        if (conn.raw) {
          await conn.raw("SET statement_timeout = '8s'");
          await conn.raw("SET lock_timeout = '5s'");
          await conn.raw("SET client_encoding TO 'UTF8'");
          await conn.raw("SET timezone TO 'UTC'");
        }
        done(null, conn);
      } catch (error) {
        logger.error('❌ Failed to configure new connection:', error);
        done(error instanceof Error ? error : new Error(String(error)));
      }
    }
  },
  migrations: {
    directory: './migrations',
    tableName: 'knex_migrations',
  },
  seeds: {
    directory: './seeds',
  },
  debug: config.NODE_ENV === 'development',
};

// Create database instance
export const db = knex(dbConfig);

// Enhanced Database connection function with retry logic
export const connectDatabase = async (): Promise<void> => {
  const maxRetries = 3;
  const retryDelay = 2000; // 2 seconds
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      logger.info(`🔄 Attempting database connection (attempt ${attempt}/${maxRetries})...`);
      
      // Test the connection with timeout
      const result = await Promise.race([
        db.raw('SELECT 1+1 as result'),
        new Promise<never>((_, reject) => 
          setTimeout(() => reject(new Error('Database connection timeout after 10 seconds')), 10000)
        )
      ]);
      
      logger.info('✅ 数据库连接成功', { 
        result: result.rows?.[0] || result,
        attempt,
        connectionPool: {
          min: dbConfig.pool?.min || 0,
          max: dbConfig.pool?.max || 0
        }
      });

      // Verify PostGIS extension in production
      if (config.NODE_ENV === 'production') {
        try {
          await db.raw('SELECT PostGIS_Version()');
          logger.info('✅ PostGIS extension verified');
        } catch (error) {
          logger.warn('⚠️ PostGIS extension not available, spatial queries will be limited');
        }

        // Run migrations in production
        await db.migrate.latest();
        logger.info('✅ 数据库迁移完成');
      }
      
      // Connection successful, exit retry loop
      return;
      
    } catch (error) {
      logger.error(`❌ 数据库连接失败 (attempt ${attempt}/${maxRetries}):`, {
        error: error instanceof Error ? error.message : error,
        stack: error instanceof Error ? error.stack : undefined
      });
      
      if (attempt === maxRetries) {
        const errorMessage = `Database connection failed after ${maxRetries} attempts. Server will not start.`;
        logger.error(`🚨 ${errorMessage}`);
        throw new Error(errorMessage);
      }
      
      // Wait before retry with exponential backoff
      const delay = retryDelay * attempt;
      logger.info(`⏳ Waiting ${delay}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
};

// Database disconnection function
export const disconnectDatabase = async (): Promise<void> => {
  try {
    await db.destroy();
    logger.info('数据库连接已关闭');
  } catch (error) {
    logger.error('关闭数据库连接时发生错误:', error);
    throw error;
  }
};

// Enhanced Health check function with detailed metrics
export const checkDatabaseHealth = async (): Promise<{
  healthy: boolean;
  details: {
    connectionTest: boolean;
    poolStatus: any;
    responseTime: number;
    error?: string;
  };
}> => {
  const startTime = Date.now();
  let connectionTest = false;
  let poolStatus = {};
  let error: string | undefined;
  
  try {
    // Test basic connectivity
    await db.raw('SELECT 1');
    connectionTest = true;
    
    // Get pool status
    const pool = (db as any).client?.pool;
    if (pool) {
      poolStatus = {
        size: pool.size || 0,
        available: pool.available || 0,
        borrowed: pool.borrowed || 0,
        pending: pool.pending || 0,
        max: pool.max || 0,
        min: pool.min || 0
      };
    }
    
    const responseTime = Date.now() - startTime;
    const healthy = connectionTest && responseTime < 1000; // Consider healthy if < 1s
    
    if (!healthy && responseTime >= 1000) {
      logger.warn('⚠️ Database response time is high:', { responseTime });
    }
    
    return {
      healthy,
      details: {
        connectionTest,
        poolStatus,
        responseTime
      }
    };
    
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
    logger.error('❌ 数据库健康检查失败:', error);
    
    return {
      healthy: false,
      details: {
        connectionTest: false,
        poolStatus,
        responseTime: Date.now() - startTime,
        error
      }
    };
  }
};

// Transaction helper
export const withTransaction = async <T>(
  callback: (trx: Knex.Transaction) => Promise<T>,
): Promise<T> => {
  const trx = await db.transaction();
  try {
    const result = await callback(trx);
    await trx.commit();
    return result;
  } catch (error) {
    await trx.rollback();
    throw error;
  }
};

// Query builder helpers
export const buildPaginationQuery = (
  query: Knex.QueryBuilder,
  page: number = 1,
  limit: number = 20,
): Knex.QueryBuilder => {
  const offset = (page - 1) * limit;
  return query.limit(limit).offset(offset);
};

export const buildSearchQuery = (
  query: Knex.QueryBuilder,
  searchTerm: string,
  searchColumns: string[],
): Knex.QueryBuilder => {
  if (!searchTerm || searchColumns.length === 0) {
    return query;
  }

  return query.where((builder) => {
    searchColumns.forEach((column, index) => {
      const method = index === 0 ? 'where' : 'orWhere';
      builder[method](column, 'ILIKE', `%${searchTerm}%`);
    });
  });
};

export const buildSortQuery = (
  query: Knex.QueryBuilder,
  sortBy: string = 'created_at',
  sortOrder: 'asc' | 'desc' = 'desc',
): Knex.QueryBuilder => {
  return query.orderBy(sortBy, sortOrder);
};

// Geographic query helpers for PostGIS
export const buildLocationQuery = (
  query: Knex.QueryBuilder,
  latitude: number,
  longitude: number,
  radiusInMeters: number = 1000,
): Knex.QueryBuilder => {
  return query.whereRaw(
    'ST_DWithin(location_point, ST_GeomFromText(?, 4326), ?)',
    [`POINT(${longitude} ${latitude})`, radiusInMeters],
  );
};

export const buildBoundsQuery = (
  query: Knex.QueryBuilder,
  bounds: {
    north: number;
    south: number;
    east: number;
    west: number;
  },
): Knex.QueryBuilder => {
  return query.whereRaw(
    'ST_Within(location_point, ST_GeomFromText(?, 4326))',
    [
      `POLYGON((${bounds.west} ${bounds.south}, ${bounds.east} ${bounds.south}, ${bounds.east} ${bounds.north}, ${bounds.west} ${bounds.north}, ${bounds.west} ${bounds.south}))`,
    ],
  );
};

// Database performance monitoring
export const monitorQuery = <T>(
  queryName: string,
  queryFn: () => Promise<T>,
): Promise<T> => {
  const startTime = Date.now();

  return queryFn()
    .then((result) => {
      const duration = Date.now() - startTime;
      if (duration > 1000) { // Log slow queries (> 1 second)
        logger.warn(`慢查询检测: ${queryName} 耗时 ${duration}ms`);
      }
      return result;
    })
    .catch((error) => {
      const duration = Date.now() - startTime;
      logger.error(`查询失败: ${queryName} 耗时 ${duration}ms`, error);
      throw error;
    });
};

export default db;