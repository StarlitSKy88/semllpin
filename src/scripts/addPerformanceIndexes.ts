import { db } from '../config/database';
import { logger } from '../utils/logger';

// 手动添加重要的性能索引
async function addPerformanceIndexes() {
  logger.info('🚀 Starting to add performance indexes...');
  
  const indexQueries = [
    // Users表索引
    {
      name: 'idx_users_email_unique',
      sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email)`,
      description: '用户邮箱唯一索引'
    },
    {
      name: 'idx_users_username',
      sql: `CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
      description: '用户名索引'
    },
    {
      name: 'idx_users_status_created',
      sql: `CREATE INDEX IF NOT EXISTS idx_users_status_created ON users(status, created_at)`,
      description: '用户状态和创建时间索引'
    },

    // Annotations表索引 (如果存在)
    {
      name: 'idx_annotations_status_created',
      sql: `CREATE INDEX IF NOT EXISTS idx_annotations_status_created ON annotations(status, created_at)`,
      description: '注释状态和创建时间索引'
    },
    {
      name: 'idx_annotations_user_status',
      sql: `CREATE INDEX IF NOT EXISTS idx_annotations_user_status ON annotations(user_id, status)`,
      description: '用户注释状态索引'
    },
    {
      name: 'idx_annotations_location',
      sql: `CREATE INDEX IF NOT EXISTS idx_annotations_location ON annotations(latitude, longitude)`,
      description: '注释地理位置索引'
    },

    // Annotation Likes表索引 (如果存在)
    {
      name: 'idx_annotation_likes_unique',
      sql: `CREATE UNIQUE INDEX IF NOT EXISTS idx_annotation_likes_unique ON annotation_likes(annotation_id, user_id)`,
      description: '注释点赞唯一索引'
    },
    {
      name: 'idx_annotation_likes_user_time',
      sql: `CREATE INDEX IF NOT EXISTS idx_annotation_likes_user_time ON annotation_likes(user_id, created_at)`,
      description: '用户点赞时间索引'
    },

    // Media Files表索引 (如果存在)
    {
      name: 'idx_media_files_annotation_active',
      sql: `CREATE INDEX IF NOT EXISTS idx_media_files_annotation_active ON media_files(annotation_id, deleted_at)`,
      description: '媒体文件注释关联索引'
    },

    // User Follows表索引 (如果存在)
    {
      name: 'idx_user_follows_follower',
      sql: `CREATE INDEX IF NOT EXISTS idx_user_follows_follower ON user_follows(follower_id, status)`,
      description: '用户关注者索引'
    },
    {
      name: 'idx_user_follows_following',
      sql: `CREATE INDEX IF NOT EXISTS idx_user_follows_following ON user_follows(following_id, status)`,
      description: '用户关注中索引'
    },
  ];

  let successCount = 0;
  let failureCount = 0;

  for (const index of indexQueries) {
    try {
      logger.info(`Adding index: ${index.name} - ${index.description}`);
      await db.raw(index.sql);
      logger.info(`✅ Successfully added index: ${index.name}`);
      successCount++;
    } catch (error) {
      const errorMessage = (error as Error).message;
      if (errorMessage.includes('already exists') || errorMessage.includes('does not exist')) {
        logger.warn(`⚠️ Skipping index ${index.name}: ${errorMessage}`);
      } else {
        logger.error(`❌ Failed to add index ${index.name}:`, errorMessage);
        failureCount++;
      }
    }
  }

  logger.info(`🎉 Index creation completed!`);
  logger.info(`✅ Success: ${successCount}`);
  logger.info(`❌ Failures: ${failureCount}`);
  logger.info(`⚠️ Skipped: ${indexQueries.length - successCount - failureCount}`);
}

// 检查并添加PostGIS空间索引 (仅PostgreSQL)
async function addPostGISIndexes() {
  try {
    const dbConfig = db.client.config;
    if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
      logger.info('🗺️ Adding PostGIS spatial indexes...');
      
      const spatialIndexes = [
        {
          name: 'idx_annotations_location_point_gist',
          sql: `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_annotations_location_point_gist 
                ON annotations USING GIST (location_point)`,
          description: 'PostGIS空间索引'
        },
        {
          name: 'idx_annotations_status_location_gist',
          sql: `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_annotations_status_location_gist 
                ON annotations USING GIST (location_point) 
                WHERE status = 'approved'`,
          description: 'PostGIS已批准注释空间索引'
        }
      ];

      for (const index of spatialIndexes) {
        try {
          logger.info(`Adding PostGIS index: ${index.name}`);
          await db.raw(index.sql);
          logger.info(`✅ Successfully added PostGIS index: ${index.name}`);
        } catch (error) {
          logger.warn(`⚠️ PostGIS index ${index.name} failed: ${(error as Error).message}`);
        }
      }
    } else {
      logger.info('📝 Skipping PostGIS indexes (not using PostgreSQL)');
    }
  } catch (error) {
    logger.error('PostGIS indexes setup failed:', error);
  }
}

// 分析表统计信息
async function analyzeTablesPostgreSQL() {
  try {
    const dbConfig = db.client.config;
    if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
      logger.info('📊 Analyzing table statistics...');
      
      const tables = ['users', 'annotations', 'annotation_likes', 'media_files', 'user_follows'];
      
      for (const table of tables) {
        try {
          await db.raw(`ANALYZE ${table}`);
          logger.info(`✅ Analyzed table: ${table}`);
        } catch (error) {
          logger.warn(`⚠️ Could not analyze table ${table}: ${(error as Error).message}`);
        }
      }
    } else {
      logger.info('📝 Skipping table analysis (not using PostgreSQL)');
    }
  } catch (error) {
    logger.error('Table analysis failed:', error);
  }
}

// 主函数
async function main() {
  try {
    logger.info('🔧 Database Performance Optimization Script Starting...');
    
    // 1. 添加基本性能索引
    await addPerformanceIndexes();
    
    // 2. 添加PostGIS空间索引 (如果适用)
    await addPostGISIndexes();
    
    // 3. 分析表统计信息
    await analyzeTablesPostgreSQL();
    
    logger.info('🎉 Database performance optimization completed!');
    process.exit(0);
  } catch (error) {
    logger.error('❌ Database performance optimization failed:', error);
    process.exit(1);
  }
}

// 如果直接运行此脚本
if (require.main === module) {
  main().catch(error => {
    console.error('Script execution failed:', error);
    process.exit(1);
  });
}

export { addPerformanceIndexes, addPostGISIndexes, analyzeTablesPostgreSQL };