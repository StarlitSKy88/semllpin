#!/usr/bin/env node

/**
 * SmellPin Database Maintenance and Cleanup Scripts
 * 
 * Automated maintenance tasks for optimal database performance:
 * - Table vacuuming and analysis
 * - Index maintenance and rebuilding
 * - Old data archiving and cleanup
 * - Performance statistics collection
 * - Space reclamation and optimization
 * 
 * Usage:
 *   node scripts/database-maintenance.js --task=all
 *   node scripts/database-maintenance.js --task=vacuum
 *   node scripts/database-maintenance.js --task=analyze
 *   node scripts/database-maintenance.js --task=cleanup
 *   node scripts/database-maintenance.js --task=reindex
 */

const knex = require('knex');
const yargs = require('yargs');
const fs = require('fs').promises;
const path = require('path');

// Configuration
const config = {
  // Database connection (can be overridden by environment variables)
  database: {
    client: 'postgresql',
    connection: {
      connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/smellpin',
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    },
    pool: { min: 1, max: 5 }
  },

  // Maintenance thresholds and settings
  cleanup: {
    // Data retention policies (in days)
    locationReportsRetention: 30,          // Keep location reports for 30 days
    sessionLogsRetention: 7,               // Keep session logs for 7 days
    queryLogsRetention: 3,                 // Keep query logs for 3 days
    notificationHistoryRetention: 90,      // Keep notifications for 90 days
    deletedRecordsRetention: 30,           // Keep soft-deleted records for 30 days
    
    // Batch sizes for cleanup operations
    batchSize: 1000,
    maxBatchesPerRun: 100
  },

  // Vacuum and analyze settings
  maintenance: {
    vacuumThreshold: 20,        // Vacuum when dead tuple percentage > 20%
    analyzeThreshold: 10,       // Analyze when row count change > 10%
    reindexThreshold: 30,       // Reindex when bloat > 30%
    
    // Tables to prioritize for maintenance
    criticalTables: [
      'annotations',
      'users', 
      'location_reports',
      'geofences',
      'reward_records'
    ]
  }
};

class DatabaseMaintenance {
  constructor() {
    this.db = knex(config.database);
    this.maintenanceLog = [];
  }

  /**
   * Log maintenance activity
   */
  log(level, message, data = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data
    };
    
    this.maintenanceLog.push(entry);
    console.log(`[${entry.timestamp}] ${level.toUpperCase()}: ${message}`, 
                Object.keys(data).length > 0 ? JSON.stringify(data, null, 2) : '');
  }

  /**
   * Check if we're connected to PostgreSQL
   */
  async checkPostgreSQL() {
    try {
      const result = await this.db.raw('SELECT version()');
      const version = result.rows[0].version;
      
      if (!version.toLowerCase().includes('postgresql')) {
        throw new Error('Not a PostgreSQL database');
      }
      
      this.log('info', `Connected to ${version}`);
      return true;
    } catch (error) {
      this.log('error', 'PostgreSQL connection check failed', { error: error.message });
      return false;
    }
  }

  /**
   * Get table statistics for maintenance planning
   */
  async getTableStatistics() {
    try {
      const stats = await this.db.raw(`
        SELECT 
          schemaname,
          tablename,
          n_tup_ins as inserts,
          n_tup_upd as updates,
          n_tup_del as deletes,
          n_live_tup as live_tuples,
          n_dead_tup as dead_tuples,
          CASE 
            WHEN n_live_tup + n_dead_tup > 0 
            THEN ROUND((n_dead_tup::float / (n_live_tup + n_dead_tup)::float) * 100, 2)
            ELSE 0 
          END as dead_tuple_percent,
          last_vacuum,
          last_autovacuum,
          last_analyze,
          last_autoanalyze,
          pg_total_relation_size(schemaname||'.'||tablename) as total_size_bytes,
          pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size
        FROM pg_stat_user_tables
        WHERE schemaname = 'public'
        ORDER BY total_size_bytes DESC
      `);

      return stats.rows;
    } catch (error) {
      this.log('error', 'Failed to get table statistics', { error: error.message });
      return [];
    }
  }

  /**
   * Get index statistics and bloat information
   */
  async getIndexStatistics() {
    try {
      const indexStats = await this.db.raw(`
        SELECT 
          schemaname,
          tablename,
          indexname,
          idx_scan as scans,
          idx_tup_read as tuples_read,
          idx_tup_fetch as tuples_fetched,
          pg_size_pretty(pg_relation_size(indexrelid)) as size,
          pg_relation_size(indexrelid) as size_bytes
        FROM pg_stat_user_indexes
        WHERE schemaname = 'public'
        ORDER BY size_bytes DESC
      `);

      // Get index bloat estimate
      const bloatStats = await this.db.raw(`
        SELECT 
          schemaname,
          tablename,
          indexname,
          ROUND(
            CASE 
              WHEN pg_relation_size(indexrelid) > 0 
              THEN (pg_relation_size(indexrelid) - (relpages * 8192))::float / pg_relation_size(indexrelid)::float * 100
              ELSE 0 
            END, 2
          ) as estimated_bloat_percent
        FROM pg_stat_user_indexes 
        JOIN pg_class ON pg_class.oid = indexrelid
        WHERE schemaname = 'public'
        ORDER BY estimated_bloat_percent DESC
      `);

      return {
        usage: indexStats.rows,
        bloat: bloatStats.rows
      };
    } catch (error) {
      this.log('error', 'Failed to get index statistics', { error: error.message });
      return { usage: [], bloat: [] };
    }
  }

  /**
   * Vacuum tables based on dead tuple percentage
   */
  async performVacuum(dryRun = false) {
    this.log('info', 'Starting vacuum analysis...');
    
    const tableStats = await this.getTableStatistics();
    const vacuumCandidates = tableStats.filter(
      table => table.dead_tuple_percent > config.maintenance.vacuumThreshold ||
               config.maintenance.criticalTables.includes(table.tablename)
    );

    this.log('info', `Found ${vacuumCandidates.length} tables needing vacuum`);

    let vacuumedTables = 0;
    for (const table of vacuumCandidates) {
      try {
        const tableName = `${table.schemaname}.${table.tablename}`;
        
        if (dryRun) {
          this.log('info', `[DRY RUN] Would vacuum ${tableName}`, {
            deadTuples: table.dead_tuples,
            deadPercent: table.dead_tuple_percent,
            size: table.total_size
          });
        } else {
          this.log('info', `Vacuuming ${tableName}...`);
          const startTime = Date.now();
          
          // Use VACUUM ANALYZE for comprehensive maintenance
          await this.db.raw(`VACUUM ANALYZE ${tableName}`);
          
          const duration = Date.now() - startTime;
          vacuumedTables++;
          
          this.log('info', `Completed vacuum of ${tableName}`, {
            duration: `${duration}ms`,
            deadTuples: table.dead_tuples,
            deadPercent: table.dead_tuple_percent
          });
        }
      } catch (error) {
        this.log('error', `Failed to vacuum ${table.tablename}`, { error: error.message });
      }
    }

    this.log('info', `Vacuum completed. Processed ${vacuumedTables} tables`);
    return vacuumedTables;
  }

  /**
   * Analyze tables for query planner statistics
   */
  async performAnalyze(dryRun = false) {
    this.log('info', 'Starting table analysis...');

    const tableStats = await this.getTableStatistics();
    const criticalTables = tableStats.filter(table =>
      config.maintenance.criticalTables.includes(table.tablename)
    );

    this.log('info', `Analyzing ${criticalTables.length} critical tables`);

    let analyzedTables = 0;
    for (const table of criticalTables) {
      try {
        const tableName = `${table.schemaname}.${table.tablename}`;
        
        if (dryRun) {
          this.log('info', `[DRY RUN] Would analyze ${tableName}`);
        } else {
          this.log('info', `Analyzing ${tableName}...`);
          const startTime = Date.now();
          
          await this.db.raw(`ANALYZE ${tableName}`);
          
          const duration = Date.now() - startTime;
          analyzedTables++;
          
          this.log('info', `Completed analysis of ${tableName}`, {
            duration: `${duration}ms`,
            liveTuples: table.live_tuples
          });
        }
      } catch (error) {
        this.log('error', `Failed to analyze ${table.tablename}`, { error: error.message });
      }
    }

    this.log('info', `Analysis completed. Processed ${analyzedTables} tables`);
    return analyzedTables;
  }

  /**
   * Reindex bloated indexes
   */
  async performReindex(dryRun = false) {
    this.log('info', 'Starting index maintenance...');

    const indexStats = await this.getIndexStatistics();
    const bloatedIndexes = indexStats.bloat.filter(
      index => index.estimated_bloat_percent > config.maintenance.reindexThreshold
    );

    this.log('info', `Found ${bloatedIndexes.length} indexes needing reindex`);

    let reindexedCount = 0;
    for (const index of bloatedIndexes) {
      try {
        const indexName = `${index.schemaname}.${index.indexname}`;
        
        if (dryRun) {
          this.log('info', `[DRY RUN] Would reindex ${indexName}`, {
            bloatPercent: index.estimated_bloat_percent
          });
        } else {
          this.log('info', `Reindexing ${indexName}...`);
          const startTime = Date.now();
          
          await this.db.raw(`REINDEX INDEX CONCURRENTLY ${indexName}`);
          
          const duration = Date.now() - startTime;
          reindexedCount++;
          
          this.log('info', `Completed reindex of ${indexName}`, {
            duration: `${duration}ms`,
            bloatPercent: index.estimated_bloat_percent
          });
        }
      } catch (error) {
        this.log('error', `Failed to reindex ${index.indexname}`, { error: error.message });
      }
    }

    this.log('info', `Reindex completed. Processed ${reindexedCount} indexes`);
    return reindexedCount;
  }

  /**
   * Clean up old data based on retention policies
   */
  async performCleanup(dryRun = false) {
    this.log('info', 'Starting data cleanup...');

    const cleanupTasks = [
      {
        name: 'location_reports',
        table: 'location_reports',
        timeColumn: 'reported_at',
        retentionDays: config.cleanup.locationReportsRetention
      },
      {
        name: 'session_logs',
        table: 'user_sessions',
        timeColumn: 'expires_at',
        retentionDays: config.cleanup.sessionLogsRetention,
        condition: "expires_at < NOW() - INTERVAL '1 day'" // Already expired sessions
      },
      {
        name: 'old_notifications',
        table: 'notifications',
        timeColumn: 'created_at',
        retentionDays: config.cleanup.notificationHistoryRetention,
        condition: "is_read = true" // Only read notifications
      },
      {
        name: 'soft_deleted_annotations',
        table: 'annotations',
        timeColumn: 'updated_at',
        retentionDays: config.cleanup.deletedRecordsRetention,
        condition: "status = 'deleted'"
      }
    ];

    let totalDeleted = 0;
    for (const task of cleanupTasks) {
      try {
        const { name, table, timeColumn, retentionDays, condition } = task;
        
        // Check if table exists
        const tableExists = await this.db.schema.hasTable(table);
        if (!tableExists) {
          this.log('info', `Skipping cleanup for ${name} - table ${table} does not exist`);
          continue;
        }

        // Build cleanup query
        let query = `
          DELETE FROM ${table} 
          WHERE ${timeColumn} < NOW() - INTERVAL '${retentionDays} days'
        `;
        
        if (condition) {
          query += ` AND (${condition})`;
        }

        if (dryRun) {
          // Get count of records that would be deleted
          const countQuery = query.replace('DELETE FROM', 'SELECT COUNT(*) as count FROM');
          const result = await this.db.raw(countQuery);
          const count = result.rows[0].count;
          
          this.log('info', `[DRY RUN] Would delete ${count} records from ${name}`, {
            retentionDays,
            condition
          });
        } else {
          this.log('info', `Cleaning up ${name}...`);
          const startTime = Date.now();
          
          // Delete in batches to avoid locking
          let totalBatchDeleted = 0;
          let batchCount = 0;
          
          while (batchCount < config.cleanup.maxBatchesPerRun) {
            const batchQuery = `${query} LIMIT ${config.cleanup.batchSize}`;
            const result = await this.db.raw(batchQuery);
            const deleted = result.rowCount || 0;
            
            if (deleted === 0) break;
            
            totalBatchDeleted += deleted;
            batchCount++;
            
            this.log('info', `Deleted batch ${batchCount} from ${name}`, {
              deleted,
              totalDeleted: totalBatchDeleted
            });
            
            // Small delay between batches
            await new Promise(resolve => setTimeout(resolve, 100));
          }
          
          const duration = Date.now() - startTime;
          totalDeleted += totalBatchDeleted;
          
          this.log('info', `Completed cleanup of ${name}`, {
            deleted: totalBatchDeleted,
            batches: batchCount,
            duration: `${duration}ms`
          });
        }
      } catch (error) {
        this.log('error', `Failed to cleanup ${task.name}`, { error: error.message });
      }
    }

    this.log('info', `Cleanup completed. Deleted ${totalDeleted} total records`);
    return totalDeleted;
  }

  /**
   * Update database statistics
   */
  async updateStatistics() {
    this.log('info', 'Updating database statistics...');

    try {
      // Update all table statistics
      await this.db.raw('ANALYZE');
      
      // Refresh materialized views if they exist
      const materializedViews = await this.db.raw(`
        SELECT schemaname, matviewname 
        FROM pg_matviews 
        WHERE schemaname = 'public'
      `);

      for (const view of materializedViews.rows) {
        try {
          const viewName = `${view.schemaname}.${view.matviewname}`;
          this.log('info', `Refreshing materialized view ${viewName}...`);
          await this.db.raw(`REFRESH MATERIALIZED VIEW CONCURRENTLY ${viewName}`);
        } catch (error) {
          this.log('warn', `Failed to refresh materialized view ${view.matviewname}`, {
            error: error.message
          });
        }
      }

      this.log('info', 'Database statistics updated successfully');
    } catch (error) {
      this.log('error', 'Failed to update database statistics', { error: error.message });
    }
  }

  /**
   * Generate maintenance report
   */
  async generateReport() {
    this.log('info', 'Generating maintenance report...');

    try {
      const [tableStats, indexStats] = await Promise.all([
        this.getTableStatistics(),
        this.getIndexStatistics()
      ]);

      // Database size information
      const dbSizeResult = await this.db.raw(`
        SELECT 
          pg_size_pretty(pg_database_size(current_database())) as database_size,
          pg_database_size(current_database()) as database_size_bytes
      `);

      const report = {
        timestamp: new Date().toISOString(),
        database: {
          size: dbSizeResult.rows[0].database_size,
          sizeBytes: dbSizeResult.rows[0].database_size_bytes
        },
        tables: {
          total: tableStats.length,
          needingVacuum: tableStats.filter(t => t.dead_tuple_percent > config.maintenance.vacuumThreshold).length,
          largestTables: tableStats.slice(0, 10).map(t => ({
            name: t.tablename,
            size: t.total_size,
            liveTuples: t.live_tuples,
            deadTuplePercent: t.dead_tuple_percent
          }))
        },
        indexes: {
          total: indexStats.usage.length,
          unused: indexStats.usage.filter(i => i.scans === 0).length,
          bloated: indexStats.bloat.filter(i => i.estimated_bloat_percent > config.maintenance.reindexThreshold).length,
          largestIndexes: indexStats.usage.slice(0, 10).map(i => ({
            name: i.indexname,
            table: i.tablename,
            size: i.size,
            scans: i.scans
          }))
        },
        recommendations: this.generateRecommendations(tableStats, indexStats),
        maintenanceLog: this.maintenanceLog
      };

      return report;
    } catch (error) {
      this.log('error', 'Failed to generate maintenance report', { error: error.message });
      return null;
    }
  }

  /**
   * Generate maintenance recommendations
   */
  generateRecommendations(tableStats, indexStats) {
    const recommendations = [];

    // Table recommendations
    const highDeadTupleTables = tableStats.filter(t => t.dead_tuple_percent > 25);
    if (highDeadTupleTables.length > 0) {
      recommendations.push({
        type: 'vacuum',
        priority: 'high',
        message: `${highDeadTupleTables.length} tables have >25% dead tuples and need immediate vacuuming`,
        tables: highDeadTupleTables.map(t => t.tablename)
      });
    }

    // Index recommendations
    const unusedIndexes = indexStats.usage.filter(i => i.scans === 0);
    if (unusedIndexes.length > 0) {
      recommendations.push({
        type: 'index_cleanup',
        priority: 'medium',
        message: `${unusedIndexes.length} indexes are never used and could be dropped`,
        indexes: unusedIndexes.map(i => `${i.tablename}.${i.indexname}`)
      });
    }

    const bloatedIndexes = indexStats.bloat.filter(i => i.estimated_bloat_percent > 50);
    if (bloatedIndexes.length > 0) {
      recommendations.push({
        type: 'reindex',
        priority: 'high',
        message: `${bloatedIndexes.length} indexes have >50% bloat and should be reindexed`,
        indexes: bloatedIndexes.map(i => `${i.tablename}.${i.indexname}`)
      });
    }

    // Size recommendations
    const largeTables = tableStats.filter(t => t.total_size_bytes > 1024 * 1024 * 1024); // > 1GB
    if (largeTables.length > 0) {
      recommendations.push({
        type: 'archiving',
        priority: 'medium',
        message: `${largeTables.length} tables are >1GB and may benefit from data archiving`,
        tables: largeTables.map(t => t.tablename)
      });
    }

    return recommendations;
  }

  /**
   * Save maintenance report to file
   */
  async saveReport(report, filename = null) {
    if (!report) return;

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportFilename = filename || `maintenance-report-${timestamp}.json`;
    const reportPath = path.join(process.cwd(), 'logs', reportFilename);

    try {
      // Ensure logs directory exists
      await fs.mkdir(path.dirname(reportPath), { recursive: true });
      
      await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
      this.log('info', `Maintenance report saved to ${reportPath}`);
    } catch (error) {
      this.log('error', 'Failed to save maintenance report', { error: error.message });
    }
  }

  /**
   * Run all maintenance tasks
   */
  async runAll(dryRun = false) {
    this.log('info', `Starting comprehensive maintenance${dryRun ? ' (DRY RUN)' : ''}...`);
    
    const isPostgreSQL = await this.checkPostgreSQL();
    if (!isPostgreSQL) {
      this.log('error', 'Maintenance requires PostgreSQL database');
      return;
    }

    try {
      // Generate initial report
      const initialReport = await this.generateReport();
      
      // Perform maintenance tasks
      const results = {
        vacuum: await this.performVacuum(dryRun),
        analyze: await this.performAnalyze(dryRun),
        cleanup: await this.performCleanup(dryRun),
        reindex: await this.performReindex(dryRun)
      };

      // Update statistics
      if (!dryRun) {
        await this.updateStatistics();
      }

      // Generate final report
      const finalReport = await this.generateReport();
      
      this.log('info', 'Comprehensive maintenance completed', {
        results,
        dryRun
      });

      // Save reports
      if (initialReport) {
        await this.saveReport(initialReport, `maintenance-before-${Date.now()}.json`);
      }
      if (finalReport) {
        await this.saveReport(finalReport, `maintenance-after-${Date.now()}.json`);
      }

      return { results, initialReport, finalReport };

    } catch (error) {
      this.log('error', 'Maintenance failed', { error: error.message });
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
    .option('task', {
      alias: 't',
      type: 'string',
      choices: ['all', 'vacuum', 'analyze', 'cleanup', 'reindex', 'report'],
      default: 'all',
      description: 'Maintenance task to run'
    })
    .option('dry-run', {
      alias: 'd',
      type: 'boolean',
      default: false,
      description: 'Preview changes without executing them'
    })
    .help()
    .argv;

  const maintenance = new DatabaseMaintenance();

  try {
    switch (argv.task) {
      case 'vacuum':
        await maintenance.performVacuum(argv.dryRun);
        break;
      case 'analyze':
        await maintenance.performAnalyze(argv.dryRun);
        break;
      case 'cleanup':
        await maintenance.performCleanup(argv.dryRun);
        break;
      case 'reindex':
        await maintenance.performReindex(argv.dryRun);
        break;
      case 'report':
        const report = await maintenance.generateReport();
        await maintenance.saveReport(report);
        break;
      case 'all':
      default:
        await maintenance.runAll(argv.dryRun);
        break;
    }
  } catch (error) {
    console.error('Maintenance failed:', error);
    process.exit(1);
  } finally {
    await maintenance.close();
  }
}

// Export for programmatic use
module.exports = DatabaseMaintenance;

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}