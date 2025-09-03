/**
 * SmellPin Failover Coordinator
 * Manages automatic and manual failover between primary and secondary regions
 */

const axios = require('axios');
const dns = require('dns').promises;
const EventEmitter = require('events');

class FailoverCoordinator extends EventEmitter {
    constructor(config = {}) {
        super();
        
        this.config = {
            dnsProvider: process.env.DNS_PROVIDER || 'cloudflare',
            dnsApiToken: process.env.DNS_API_TOKEN,
            domainName: process.env.DOMAIN_NAME || 'smellpin.com',
            primaryIp: process.env.PRIMARY_IP,
            secondaryIp: process.env.SECONDARY_IP,
            zoneId: process.env.CLOUDFLARE_ZONE_ID,
            
            // Health check configuration
            healthCheckEndpoints: {
                primary: [
                    'https://api.smellpin.com/health',
                    'https://smellpin.com/health'
                ],
                secondary: [
                    'https://secondary-api.smellpin.com/health',
                    'https://secondary.smellpin.com/health'
                ]
            },
            
            // Failover thresholds
            failoverThreshold: parseInt(process.env.FAILOVER_THRESHOLD) || 3,
            healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000, // 30 seconds
            failbackDelay: parseInt(process.env.FAILBACK_DELAY) || 300000, // 5 minutes
            
            // Current state
            currentRegion: 'primary',
            failedChecks: 0,
            lastFailover: null,
            
            // Feature flags
            manualFailoverEnabled: process.env.MANUAL_FAILOVER_ENABLED === 'true',
            autoFailoverEnabled: process.env.AUTO_FAILOVER_ENABLED !== 'false',
            
            ...config
        };
        
        this.state = {
            currentRegion: this.config.currentRegion,
            primaryHealthy: true,
            secondaryHealthy: true,
            failedChecks: 0,
            lastHealthCheck: null,
            failoverInProgress: false,
            lastFailover: null
        };
        
        this.alerts = [];
        this.healthHistory = [];
        
        this.startHealthChecking();
        this.setupEventHandlers();
    }

    /**
     * Start continuous health checking
     */
    startHealthChecking() {
        console.log('Starting health checking...');
        
        setInterval(async () => {
            try {
                await this.performHealthCheck();
            } catch (error) {
                console.error('Health check error:', error);
            }
        }, this.config.healthCheckInterval);
        
        // Initial health check
        setTimeout(() => this.performHealthCheck(), 5000);
    }

    /**
     * Perform health check on all regions
     */
    async performHealthCheck() {
        const timestamp = new Date();
        console.log(`Performing health check at ${timestamp.toISOString()}`);
        
        const primaryHealth = await this.checkRegionHealth('primary');
        const secondaryHealth = await this.checkRegionHealth('secondary');
        
        this.state.primaryHealthy = primaryHealth.healthy;
        this.state.secondaryHealthy = secondaryHealth.healthy;
        this.state.lastHealthCheck = timestamp;
        
        // Store health history
        this.healthHistory.push({
            timestamp,
            primary: primaryHealth,
            secondary: secondaryHealth
        });
        
        // Keep only last 100 health checks
        if (this.healthHistory.length > 100) {
            this.healthHistory.shift();
        }
        
        // Evaluate failover conditions
        await this.evaluateFailoverConditions(primaryHealth, secondaryHealth);
        
        this.emit('healthCheck', {
            primary: primaryHealth,
            secondary: secondaryHealth,
            currentRegion: this.state.currentRegion
        });
    }

    /**
     * Check health of a specific region
     */
    async checkRegionHealth(region) {
        const endpoints = this.config.healthCheckEndpoints[region];
        const results = [];
        
        for (const endpoint of endpoints) {
            const result = await this.checkEndpoint(endpoint);
            results.push(result);
        }
        
        const healthyCount = results.filter(r => r.healthy).length;
        const avgResponseTime = results.reduce((sum, r) => sum + (r.responseTime || 0), 0) / results.length;
        
        return {
            region,
            healthy: healthyCount > (endpoints.length / 2), // Majority must be healthy
            healthyEndpoints: healthyCount,
            totalEndpoints: endpoints.length,
            avgResponseTime,
            results
        };
    }

    /**
     * Check individual endpoint health
     */
    async checkEndpoint(endpoint) {
        const startTime = Date.now();
        
        try {
            const response = await axios.get(endpoint, {
                timeout: 10000,
                headers: {
                    'User-Agent': 'SmellPin-Failover-Coordinator/1.0'
                }
            });
            
            const responseTime = Date.now() - startTime;
            
            return {
                endpoint,
                healthy: response.status >= 200 && response.status < 400,
                responseTime,
                statusCode: response.status,
                error: null
            };
            
        } catch (error) {
            const responseTime = Date.now() - startTime;
            
            return {
                endpoint,
                healthy: false,
                responseTime,
                statusCode: error.response?.status || 0,
                error: error.message
            };
        }
    }

    /**
     * Evaluate if failover conditions are met
     */
    async evaluateFailoverConditions(primaryHealth, secondaryHealth) {
        if (!this.config.autoFailoverEnabled) {
            return;
        }
        
        if (this.state.failoverInProgress) {
            console.log('Failover already in progress, skipping evaluation');
            return;
        }
        
        const currentRegion = this.state.currentRegion;
        
        // Check if current region is unhealthy
        const currentRegionHealthy = currentRegion === 'primary' ? 
            primaryHealth.healthy : secondaryHealth.healthy;
        
        // Check if failover target is healthy
        const failoverTargetHealthy = currentRegion === 'primary' ? 
            secondaryHealth.healthy : primaryHealth.healthy;
        
        if (!currentRegionHealthy) {
            this.state.failedChecks++;
            console.warn(`Current region (${currentRegion}) unhealthy. Failed checks: ${this.state.failedChecks}/${this.config.failoverThreshold}`);
            
            if (this.state.failedChecks >= this.config.failoverThreshold) {
                if (failoverTargetHealthy) {
                    const targetRegion = currentRegion === 'primary' ? 'secondary' : 'primary';
                    console.error(`Initiating automatic failover from ${currentRegion} to ${targetRegion}`);
                    await this.initiateFailover(targetRegion, 'automatic');
                } else {
                    console.error('Both regions are unhealthy! Cannot failover.');
                    await this.sendAlert('critical', 'Both regions unhealthy - service degraded');
                }
            }
        } else {
            // Reset failed checks if current region is healthy
            if (this.state.failedChecks > 0) {
                console.log(`Current region (${currentRegion}) is healthy again. Resetting failed checks.`);
                this.state.failedChecks = 0;
            }
            
            // Check for failback conditions
            await this.evaluateFailbackConditions(primaryHealth, secondaryHealth);
        }
    }

    /**
     * Evaluate failback conditions (return to primary)
     */
    async evaluateFailbackConditions(primaryHealth, secondaryHealth) {
        // Only consider failback if we're currently on secondary
        if (this.state.currentRegion !== 'secondary') {
            return;
        }
        
        // Check if enough time has passed since last failover
        if (this.state.lastFailover && 
            (Date.now() - this.state.lastFailover) < this.config.failbackDelay) {
            return;
        }
        
        // Check if primary is healthy and secondary has any issues
        if (primaryHealth.healthy && 
            primaryHealth.avgResponseTime < (secondaryHealth.avgResponseTime * 1.2)) {
            
            console.log('Primary region appears healthy and performant. Considering failback...');
            
            // Wait for primary to be consistently healthy
            const recentPrimaryHealth = this.healthHistory
                .slice(-5) // Last 5 checks
                .every(h => h.primary.healthy);
            
            if (recentPrimaryHealth) {
                console.log('Initiating failback to primary region');
                await this.initiateFailover('primary', 'failback');
            }
        }
    }

    /**
     * Initiate failover to target region
     */
    async initiateFailover(targetRegion, reason = 'manual') {
        if (this.state.failoverInProgress) {
            throw new Error('Failover already in progress');
        }
        
        console.log(`Initiating failover to ${targetRegion} (reason: ${reason})`);
        
        this.state.failoverInProgress = true;
        this.state.failedChecks = 0;
        
        try {
            // Pre-failover checks
            await this.preFailoverChecks(targetRegion);
            
            // Update DNS records
            await this.updateDnsRecords(targetRegion);
            
            // Wait for DNS propagation
            await this.waitForDnsPropagation();
            
            // Verify failover success
            await this.verifyFailover(targetRegion);
            
            // Update state
            this.state.currentRegion = targetRegion;
            this.state.lastFailover = Date.now();
            this.state.failoverInProgress = false;
            
            console.log(`Failover to ${targetRegion} completed successfully`);
            
            await this.sendAlert('warning', `Failover completed: Now serving from ${targetRegion} region`);
            
            this.emit('failoverCompleted', {
                targetRegion,
                reason,
                timestamp: new Date()
            });
            
        } catch (error) {
            this.state.failoverInProgress = false;
            console.error('Failover failed:', error);
            
            await this.sendAlert('critical', `Failover to ${targetRegion} failed: ${error.message}`);
            
            this.emit('failoverFailed', {
                targetRegion,
                reason,
                error: error.message,
                timestamp: new Date()
            });
            
            throw error;
        }
    }

    /**
     * Pre-failover checks
     */
    async preFailoverChecks(targetRegion) {
        console.log(`Performing pre-failover checks for ${targetRegion}...`);
        
        // Check target region health
        const targetHealth = await this.checkRegionHealth(targetRegion);
        if (!targetHealth.healthy) {
            throw new Error(`Target region ${targetRegion} is not healthy`);
        }
        
        // Check database replication lag
        const replicationLag = await this.checkReplicationLag();
        if (replicationLag > 60) { // 60 seconds max lag
            console.warn(`High replication lag detected: ${replicationLag}s`);
            // Continue with failover but log the issue
        }
        
        // Verify backup systems
        await this.verifyBackupSystems();
        
        console.log('Pre-failover checks passed');
    }

    /**
     * Update DNS records for failover
     */
    async updateDnsRecords(targetRegion) {
        console.log(`Updating DNS records for ${targetRegion}...`);
        
        const targetIp = targetRegion === 'primary' ? 
            this.config.primaryIp : this.config.secondaryIp;
        
        switch (this.config.dnsProvider) {
            case 'cloudflare':
                await this.updateCloudflareDns(targetIp);
                break;
            case 'route53':
                await this.updateRoute53Dns(targetIp);
                break;
            default:
                throw new Error(`Unsupported DNS provider: ${this.config.dnsProvider}`);
        }
        
        console.log(`DNS records updated to point to ${targetIp}`);
    }

    /**
     * Update Cloudflare DNS records
     */
    async updateCloudflareDns(targetIp) {
        const baseUrl = 'https://api.cloudflare.com/client/v4';
        const headers = {
            'Authorization': `Bearer ${this.config.dnsApiToken}`,
            'Content-Type': 'application/json'
        };
        
        // Get DNS records
        const response = await axios.get(
            `${baseUrl}/zones/${this.config.zoneId}/dns_records?name=${this.config.domainName}&type=A`,
            { headers }
        );
        
        if (response.data.result.length === 0) {
            throw new Error(`No A record found for ${this.config.domainName}`);
        }
        
        const record = response.data.result[0];
        
        // Update the record
        await axios.put(
            `${baseUrl}/zones/${this.config.zoneId}/dns_records/${record.id}`,
            {
                type: 'A',
                name: this.config.domainName,
                content: targetIp,
                ttl: 60 // 1 minute TTL for faster failover
            },
            { headers }
        );
    }

    /**
     * Wait for DNS propagation
     */
    async waitForDnsPropagation() {
        console.log('Waiting for DNS propagation...');
        
        const maxWait = 120000; // 2 minutes
        const checkInterval = 10000; // 10 seconds
        const startTime = Date.now();
        
        while (Date.now() - startTime < maxWait) {
            try {
                const addresses = await dns.resolve4(this.config.domainName);
                const expectedIp = this.state.currentRegion === 'primary' ? 
                    this.config.primaryIp : this.config.secondaryIp;
                
                if (addresses.includes(expectedIp)) {
                    console.log('DNS propagation completed');
                    return;
                }
            } catch (error) {
                console.warn('DNS resolution failed during propagation check:', error.message);
            }
            
            await new Promise(resolve => setTimeout(resolve, checkInterval));
        }
        
        console.warn('DNS propagation timeout - continuing with failover');
    }

    /**
     * Verify failover success
     */
    async verifyFailover(targetRegion) {
        console.log(`Verifying failover to ${targetRegion}...`);
        
        // Wait a bit for services to stabilize
        await new Promise(resolve => setTimeout(resolve, 30000));
        
        // Perform health check on target region
        const targetHealth = await this.checkRegionHealth(targetRegion);
        
        if (!targetHealth.healthy) {
            throw new Error(`Failover verification failed: ${targetRegion} is not responding properly`);
        }
        
        console.log('Failover verification successful');
    }

    /**
     * Check database replication lag
     */
    async checkReplicationLag() {
        try {
            // This would connect to your database monitoring endpoint
            const response = await axios.get('http://replication-monitor:9203/lag', {
                timeout: 5000
            });
            
            return response.data.lagSeconds || 0;
        } catch (error) {
            console.warn('Could not check replication lag:', error.message);
            return 0; // Assume no lag if we can't check
        }
    }

    /**
     * Verify backup systems
     */
    async verifyBackupSystems() {
        try {
            const response = await axios.get('http://backup-manager:9204/status', {
                timeout: 5000
            });
            
            if (!response.data.healthy) {
                console.warn('Backup systems not healthy, but continuing with failover');
            }
        } catch (error) {
            console.warn('Could not verify backup systems:', error.message);
        }
    }

    /**
     * Manual failover trigger
     */
    async manualFailover(targetRegion, reason = 'manual') {
        if (!this.config.manualFailoverEnabled) {
            throw new Error('Manual failover is disabled');
        }
        
        console.log(`Manual failover requested to ${targetRegion}`);
        await this.initiateFailover(targetRegion, reason);
    }

    /**
     * Get current status
     */
    getStatus() {
        return {
            currentRegion: this.state.currentRegion,
            primaryHealthy: this.state.primaryHealthy,
            secondaryHealthy: this.state.secondaryHealthy,
            failoverInProgress: this.state.failoverInProgress,
            lastHealthCheck: this.state.lastHealthCheck,
            lastFailover: this.state.lastFailover,
            failedChecks: this.state.failedChecks,
            config: {
                autoFailoverEnabled: this.config.autoFailoverEnabled,
                manualFailoverEnabled: this.config.manualFailoverEnabled,
                failoverThreshold: this.config.failoverThreshold,
                healthCheckInterval: this.config.healthCheckInterval
            }
        };
    }

    /**
     * Get health history
     */
    getHealthHistory(limit = 50) {
        return this.healthHistory.slice(-limit);
    }

    /**
     * Send alert notification
     */
    async sendAlert(severity, message) {
        const alert = {
            timestamp: new Date().toISOString(),
            severity,
            message,
            component: 'failover-coordinator'
        };
        
        this.alerts.push(alert);
        
        // Keep only last 100 alerts
        if (this.alerts.length > 100) {
            this.alerts.shift();
        }
        
        console.log(`ALERT [${severity}]: ${message}`);
        
        // Send to external alerting systems
        try {
            if (process.env.SLACK_WEBHOOK_URL) {
                await this.sendSlackAlert(alert);
            }
            
            if (process.env.PAGERDUTY_INTEGRATION_KEY && severity === 'critical') {
                await this.sendPagerDutyAlert(alert);
            }
        } catch (error) {
            console.error('Failed to send external alert:', error);
        }
    }

    /**
     * Send Slack alert
     */
    async sendSlackAlert(alert) {
        const color = {
            'critical': '#ff0000',
            'warning': '#ffa500',
            'info': '#00ff00'
        }[alert.severity] || '#cccccc';
        
        await axios.post(process.env.SLACK_WEBHOOK_URL, {
            text: `Failover Coordinator Alert`,
            attachments: [{
                color,
                fields: [{
                    title: `${alert.severity.toUpperCase()}: ${alert.message}`,
                    value: `Component: ${alert.component}\nTime: ${alert.timestamp}`,
                    short: false
                }]
            }]
        });
    }

    /**
     * Send PagerDuty alert
     */
    async sendPagerDutyAlert(alert) {
        await axios.post('https://events.pagerduty.com/v2/enqueue', {
            routing_key: process.env.PAGERDUTY_INTEGRATION_KEY,
            event_action: 'trigger',
            payload: {
                summary: alert.message,
                source: 'smellpin-failover-coordinator',
                severity: alert.severity,
                component: alert.component,
                timestamp: alert.timestamp
            }
        });
    }

    /**
     * Setup event handlers
     */
    setupEventHandlers() {
        this.on('healthCheck', (data) => {
            // Log health check results
            if (!data.primary.healthy || !data.secondary.healthy) {
                console.warn('Health check detected issues:', {
                    primary: data.primary.healthy,
                    secondary: data.secondary.healthy
                });
            }
        });
        
        this.on('failoverCompleted', (data) => {
            console.log(`Failover completed successfully to ${data.targetRegion} at ${data.timestamp}`);
        });
        
        this.on('failoverFailed', (data) => {
            console.error(`Failover failed to ${data.targetRegion}: ${data.error}`);
        });
    }
}

module.exports = FailoverCoordinator;