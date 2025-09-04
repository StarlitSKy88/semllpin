/**
 * Database Health Check Routes
 * 
 * Provides comprehensive database health monitoring endpoints
 * for operational monitoring and debugging.
 */

import express from 'express';
import { checkDatabaseHealth } from '../config/database';
import { databaseConnectionMonitor } from '../services/database-connection-monitor';
import { logger } from '../utils/logger';

const router = express.Router();

/**
 * GET /api/health/database
 * Basic database health check
 */
router.get('/database', async (req, res) => {
  try {
    const healthCheck = await checkDatabaseHealth();
    
    res.status(healthCheck.healthy ? 200 : 503).json({
      success: healthCheck.healthy,
      data: {
        status: healthCheck.healthy ? 'healthy' : 'unhealthy',
        timestamp: new Date().toISOString(),
        ...healthCheck.details
      },
      message: healthCheck.healthy ? 'Database is healthy' : 'Database health check failed'
    });
    
  } catch (error) {
    logger.error('❌ Database health check endpoint error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error during health check',
      message: 'Database health check failed with error'
    });
  }
});

/**
 * GET /api/health/database/detailed
 * Detailed database health and performance metrics
 */
router.get('/database/detailed', async (req, res) => {
  try {
    const [healthCheck, poolStatus, monitoringReport] = await Promise.all([
      checkDatabaseHealth(),
      Promise.resolve(databaseConnectionMonitor.getPoolStatus()),
      Promise.resolve(databaseConnectionMonitor.generateReport())
    ]);
    
    const detailed = {
      health: {
        status: healthCheck.healthy ? 'healthy' : 'unhealthy',
        ...healthCheck.details
      },
      connectionPool: {
        current: poolStatus.current,
        summary: poolStatus.summary
      },
      monitoring: {
        status: monitoringReport.status,
        recommendations: monitoringReport.recommendations
      },
      timestamp: new Date().toISOString()
    };
    
    res.status(healthCheck.healthy ? 200 : 503).json({
      success: healthCheck.healthy,
      data: detailed,
      message: `Database status: ${monitoringReport.status}`
    });
    
  } catch (error) {
    logger.error('❌ Detailed database health check error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get detailed database health information',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/health/database/metrics
 * Real-time connection pool metrics
 */
router.get('/database/metrics', (req, res) => {
  try {
    const poolStatus = databaseConnectionMonitor.getPoolStatus();
    
    res.json({
      success: true,
      data: {
        current: poolStatus.current,
        summary: poolStatus.summary,
        timestamp: new Date().toISOString()
      },
      message: 'Connection pool metrics retrieved'
    });
    
  } catch (error) {
    logger.error('❌ Database metrics endpoint error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to retrieve database metrics',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * POST /api/health/database/reconnect
 * Force database reconnection (emergency recovery)
 * Requires admin authentication in production
 */
router.post('/database/reconnect', async (req, res) => {
  try {
    // In production, add authentication middleware here
    // if (process.env['NODE_ENV'] === 'production') {
    //   // Check for admin role
    // }
    
    logger.warn('🔄 Manual database reconnection initiated');
    
    await databaseConnectionMonitor.forceReconnect();
    
    // Wait a moment then test connection
    await new Promise(resolve => setTimeout(resolve, 1000));
    const healthCheck = await checkDatabaseHealth();
    
    res.json({
      success: healthCheck.healthy,
      data: {
        reconnected: true,
        healthy: healthCheck.healthy,
        ...healthCheck.details
      },
      message: healthCheck.healthy 
        ? 'Database reconnection successful' 
        : 'Database reconnection completed but health check failed'
    });
    
  } catch (error) {
    logger.error('❌ Database reconnection failed:', error);
    res.status(500).json({
      success: false,
      error: 'Database reconnection failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

/**
 * GET /api/health/database/report
 * Comprehensive database performance report
 */
router.get('/database/report', async (req, res) => {
  try {
    const report = databaseConnectionMonitor.generateReport();
    const healthCheck = await checkDatabaseHealth();
    
    const comprehensiveReport = {
      overview: {
        status: report.status,
        healthy: healthCheck.healthy,
        timestamp: new Date().toISOString()
      },
      health: healthCheck.details,
      recommendations: report.recommendations,
      recentMetrics: report.metrics.slice(-20), // Last 20 metrics
      summary: {
        totalMetrics: report.metrics.length,
        timespan: report.metrics.length > 0 ? {
          start: report.metrics[0]?.timestamp,
          end: report.metrics[report.metrics.length - 1]?.timestamp
        } : null
      }
    };
    
    res.json({
      success: true,
      data: comprehensiveReport,
      message: `Database performance report generated - Status: ${report.status}`
    });
    
  } catch (error) {
    logger.error('❌ Database report generation failed:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate database report',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
});

export default router;