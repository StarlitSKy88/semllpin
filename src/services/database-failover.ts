/**
 * Database Failover and Recovery Service
 * 
 * Implements automatic failover strategies and connection recovery
 * mechanisms for high availability database operations.
 */

import { EventEmitter } from 'events';
import { logger } from '../utils/logger';
import { config } from '../config/config';

interface FailoverStrategy {
  name: string;
  primaryEndpoint: string;
  fallbackEndpoints?: string[];
  maxRetries: number;
  retryDelay: number;
  healthCheckInterval: number;
}

interface ConnectionAttempt {
  endpoint: string;
  attempt: number;
  timestamp: Date;
  success: boolean;
  error?: string;
  responseTime: number;
}

class DatabaseFailoverService extends EventEmitter {
  private strategy: FailoverStrategy;
  private currentEndpoint: string;
  private connectionHistory: ConnectionAttempt[] = [];
  private healthCheckInterval?: NodeJS.Timeout;
  private failoverInProgress = false;
  private consecutiveFailures = 0;
  
  constructor(strategy?: Partial<FailoverStrategy>) {
    super();
    
    this.strategy = {
      name: 'SmellPin Database Failover',
      primaryEndpoint: config.DATABASE_URL || '',
      fallbackEndpoints: [
        // Add fallback database URLs here if available
        // 'postgresql://fallback1...',
        // 'postgresql://fallback2...'
      ],
      maxRetries: 3,
      retryDelay: 2000, // 2 seconds
      healthCheckInterval: 30000, // 30 seconds
      ...strategy
    };
    
    this.currentEndpoint = this.strategy.primaryEndpoint;
  }

  /**
   * Initialize failover service
   */
  async initialize(): Promise<void> {
    logger.info('🛡️ Initializing database failover service', {
      primaryEndpoint: this.maskConnectionString(this.strategy.primaryEndpoint),
      fallbackCount: this.strategy.fallbackEndpoints?.length || 0,
      maxRetries: this.strategy.maxRetries
    });

    // Start health monitoring
    this.startHealthMonitoring();
    
    this.emit('initialized', {
      strategy: this.strategy,
      currentEndpoint: this.maskConnectionString(this.currentEndpoint)
    });
  }

  /**
   * Start periodic health monitoring
   */
  private startHealthMonitoring(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    this.healthCheckInterval = setInterval(async () => {
      if (!this.failoverInProgress) {
        await this.performHealthCheck();
      }
    }, this.strategy.healthCheckInterval);

    logger.info('📊 Database health monitoring started', {
      interval: `${this.strategy.healthCheckInterval}ms`
    });
  }

  /**
   * Perform health check on current endpoint
   */
  private async performHealthCheck(): Promise<void> {
    const startTime = Date.now();
    
    try {
      // This would be replaced with actual database connection test
      // For now, we'll simulate a health check
      await this.simulateConnectionTest(this.currentEndpoint);
      
      const responseTime = Date.now() - startTime;
      
      this.recordConnectionAttempt(this.currentEndpoint, 1, true, undefined, responseTime);
      this.consecutiveFailures = 0;
      
      this.emit('healthCheck', {
        endpoint: this.maskConnectionString(this.currentEndpoint),
        healthy: true,
        responseTime
      });
      
    } catch (error) {
      const responseTime = Date.now() - startTime;
      const errorMessage = error instanceof Error ? error.message : String(error);
      
      this.recordConnectionAttempt(this.currentEndpoint, 1, false, errorMessage, responseTime);
      this.consecutiveFailures++;
      
      logger.warn(`⚠️ Health check failed for ${this.maskConnectionString(this.currentEndpoint)}`, {
        error: errorMessage,
        consecutiveFailures: this.consecutiveFailures
      });
      
      this.emit('healthCheck', {
        endpoint: this.maskConnectionString(this.currentEndpoint),
        healthy: false,
        error: errorMessage,
        responseTime,
        consecutiveFailures: this.consecutiveFailures
      });
      
      // Trigger failover if consecutive failures exceed threshold
      if (this.consecutiveFailures >= 3 && !this.failoverInProgress) {
        await this.initiateFailover();
      }
    }
  }

  /**
   * Simulate connection test (replace with actual database test)
   */
  private async simulateConnectionTest(endpoint: string): Promise<void> {
    // This is a placeholder - replace with actual database connection test
    // For example: await db.raw('SELECT 1');
    
    // Simulate random failures for demonstration
    if (Math.random() < 0.1) { // 10% failure rate
      throw new Error('Simulated connection failure');
    }
    
    // Simulate response time
    await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
  }

  /**
   * Initiate failover to next available endpoint
   */
  async initiateFailover(): Promise<void> {
    if (this.failoverInProgress) {
      logger.warn('⚠️ Failover already in progress, skipping');
      return;
    }

    this.failoverInProgress = true;
    logger.warn('🔄 Initiating database failover due to consecutive failures');

    this.emit('failoverStarted', {
      currentEndpoint: this.maskConnectionString(this.currentEndpoint),
      consecutiveFailures: this.consecutiveFailures
    });

    try {
      const availableEndpoints = [
        this.strategy.primaryEndpoint,
        ...(this.strategy.fallbackEndpoints || [])
      ].filter(endpoint => endpoint !== this.currentEndpoint);

      for (const endpoint of availableEndpoints) {
        logger.info(`🔍 Testing failover endpoint: ${this.maskConnectionString(endpoint)}`);
        
        const success = await this.testEndpoint(endpoint);
        if (success) {
          await this.switchToEndpoint(endpoint);
          this.failoverInProgress = false;
          return;
        }
      }

      // If no fallback endpoints work, try the original primary
      logger.warn('⚠️ All fallback endpoints failed, retrying primary');
      const primarySuccess = await this.testEndpoint(this.strategy.primaryEndpoint);
      if (primarySuccess && this.currentEndpoint !== this.strategy.primaryEndpoint) {
        await this.switchToEndpoint(this.strategy.primaryEndpoint);
      } else {
        logger.error('❌ All database endpoints failed, manual intervention required');
        this.emit('failoverFailed', {
          message: 'All database endpoints failed',
          testedEndpoints: availableEndpoints.length
        });
      }

    } catch (error) {
      logger.error('❌ Failover process failed:', error);
      this.emit('failoverFailed', {
        error: error instanceof Error ? error.message : String(error)
      });
    } finally {
      this.failoverInProgress = false;
    }
  }

  /**
   * Test if an endpoint is accessible
   */
  private async testEndpoint(endpoint: string): Promise<boolean> {
    const maxAttempts = this.strategy.maxRetries;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const startTime = Date.now();
      
      try {
        await this.simulateConnectionTest(endpoint);
        const responseTime = Date.now() - startTime;
        
        this.recordConnectionAttempt(endpoint, attempt, true, undefined, responseTime);
        
        logger.info(`✅ Endpoint test successful: ${this.maskConnectionString(endpoint)} (attempt ${attempt})`);
        return true;
        
      } catch (error) {
        const responseTime = Date.now() - startTime;
        const errorMessage = error instanceof Error ? error.message : String(error);
        
        this.recordConnectionAttempt(endpoint, attempt, false, errorMessage, responseTime);
        
        logger.warn(`❌ Endpoint test failed: ${this.maskConnectionString(endpoint)} (attempt ${attempt}/${maxAttempts})`, {
          error: errorMessage
        });
        
        if (attempt < maxAttempts) {
          const delay = this.strategy.retryDelay * attempt;
          logger.info(`⏳ Waiting ${delay}ms before retry...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    return false;
  }

  /**
   * Switch to a new database endpoint
   */
  private async switchToEndpoint(endpoint: string): Promise<void> {
    const previousEndpoint = this.currentEndpoint;
    this.currentEndpoint = endpoint;
    this.consecutiveFailures = 0;

    logger.info('🔄 Switching database endpoint', {
      from: this.maskConnectionString(previousEndpoint),
      to: this.maskConnectionString(endpoint)
    });

    // Here you would implement the actual database connection switch
    // This might involve:
    // 1. Closing existing connections
    // 2. Updating connection configuration
    // 3. Reinitializing the connection pool
    // 4. Testing the new connection

    this.emit('endpointSwitched', {
      previousEndpoint: this.maskConnectionString(previousEndpoint),
      newEndpoint: this.maskConnectionString(endpoint),
      timestamp: new Date()
    });
  }

  /**
   * Record connection attempt for analytics
   */
  private recordConnectionAttempt(
    endpoint: string,
    attempt: number,
    success: boolean,
    error?: string,
    responseTime: number = 0
  ): void {
    const record: ConnectionAttempt = {
      endpoint: this.maskConnectionString(endpoint),
      attempt,
      timestamp: new Date(),
      success,
      error,
      responseTime
    };

    this.connectionHistory.push(record);
    
    // Keep only last 100 records
    if (this.connectionHistory.length > 100) {
      this.connectionHistory = this.connectionHistory.slice(-100);
    }
  }

  /**
   * Mask sensitive information in connection strings
   */
  private maskConnectionString(connectionString: string): string {
    if (!connectionString) return '';
    
    // Mask password and sensitive parts
    return connectionString.replace(
      /:([^@:]+)@/g,
      ':***@'
    ).replace(
      /^postgresql:\/\/([^:]+):/,
      'postgresql://$1:***:'
    );
  }

  /**
   * Get failover service status
   */
  getStatus(): {
    currentEndpoint: string;
    strategy: FailoverStrategy;
    consecutiveFailures: number;
    failoverInProgress: boolean;
    connectionHistory: ConnectionAttempt[];
  } {
    return {
      currentEndpoint: this.maskConnectionString(this.currentEndpoint),
      strategy: {
        ...this.strategy,
        primaryEndpoint: this.maskConnectionString(this.strategy.primaryEndpoint),
        fallbackEndpoints: this.strategy.fallbackEndpoints?.map(ep => this.maskConnectionString(ep))
      },
      consecutiveFailures: this.consecutiveFailures,
      failoverInProgress: this.failoverInProgress,
      connectionHistory: this.connectionHistory.slice(-20) // Last 20 attempts
    };
  }

  /**
   * Manual failover trigger (for operational use)
   */
  async triggerManualFailover(): Promise<void> {
    logger.warn('🔧 Manual failover triggered by operator');
    this.consecutiveFailures = 5; // Force threshold
    await this.initiateFailover();
  }

  /**
   * Stop failover service
   */
  stop(): void {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
      this.healthCheckInterval = undefined;
    }

    logger.info('🛡️ Database failover service stopped');
    this.emit('stopped');
  }
}

// Export singleton instance
export const databaseFailoverService = new DatabaseFailoverService({
  // Custom configuration can be passed here
  maxRetries: 3,
  retryDelay: 2000,
  healthCheckInterval: 30000
});

export default databaseFailoverService;