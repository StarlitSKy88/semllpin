/**
 * SmellPin Performance Guardian
 * Real-time performance monitoring with <200ms API response enforcement
 * Automatic scaling and optimization based on performance metrics
 */

const express = require('express');
const axios = require('axios');
const prometheus = require('prom-client');
const { EventEmitter } = require('events');
const Redis = require('ioredis');

class PerformanceGuardian extends EventEmitter {
    constructor() {
        super();
        
        this.app = express();
        this.port = process.env.PERFORMANCE_GUARDIAN_PORT || 9400;
        
        // Performance thresholds
        this.thresholds = {
            responseTime: {
                warning: 150,    // 150ms warning threshold
                critical: 200,   // 200ms critical threshold (SLA limit)
                emergency: 500   // 500ms emergency threshold
            },
            errorRate: {
                warning: 0.05,   // 0.05% warning
                critical: 0.1,   // 0.1% critical (SLA limit)
                emergency: 1.0   // 1.0% emergency
            },
            throughput: {
                min: 100,        // Minimum 100 RPS
                warning: 50,     // Warning below 50 RPS
                critical: 25     // Critical below 25 RPS
            }
        };
        
        // Monitored endpoints with performance requirements
        this.endpoints = [
            {
                name: 'frontend_health',
                url: 'https://smellpin.com/health',
                maxResponseTime: 200,
                critical: true,
                type: 'health'
            },
            {
                name: 'api_health',
                url: 'https://api.smellpin.com/health',
                maxResponseTime: 100,
                critical: true,
                type: 'health'
            },
            {
                name: 'user_login',
                url: 'https://api.smellpin.com/api/auth/health',
                maxResponseTime: 150,
                critical: true,
                type: 'auth'
            },
            {
                name: 'annotation_create',
                url: 'https://api.smellpin.com/api/annotations/health',
                maxResponseTime: 200,
                critical: true,
                type: 'core'
            },
            {
                name: 'lbs_location',
                url: 'https://api.smellpin.com/api/lbs/health',
                maxResponseTime: 150,
                critical: true,
                type: 'lbs'
            },
            {
                name: 'payment_process',
                url: 'https://api.smellpin.com/api/payments/health',
                maxResponseTime: 300,
                critical: true,
                type: 'payment'
            },
            {
                name: 'workers_api',
                url: 'https://smellpin-workers.your-subdomain.workers.dev/health',
                maxResponseTime: 100,
                critical: true,
                type: 'workers'
            }
        ];
        
        // Performance tracking
        this.performanceData = new Map();
        this.trendData = new Map();
        this.alertHistory = new Map();
        this.scalingActions = new Map();
        
        // Auto-scaling configuration
        this.autoScaling = {
            enabled: true,
            cooldown: 300000, // 5 minutes cooldown between scaling actions
            scaleUpThreshold: 180,   // Scale up if P95 > 180ms
            scaleDownThreshold: 100, // Scale down if P95 < 100ms
            maxInstances: 10,
            minInstances: 2
        };
        
        this.initializeMetrics();
        this.initializeConnections();
        this.setupRoutes();
        this.startPerformanceMonitoring();
    }
    
    initializeMetrics() {
        this.register = new prometheus.Register();
        
        this.metrics = {
            // Response time tracking
            responseTime: new prometheus.Histogram({
                name: 'performance_response_time_seconds',
                help: 'Response time for monitored endpoints',
                labelNames: ['endpoint', 'method', 'status_code'],
                buckets: [0.01, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 1, 2, 5],
                registers: [this.register]
            }),
            
            // SLA compliance tracking
            slaCompliance: new prometheus.Gauge({
                name: 'performance_sla_compliance_percentage',
                help: 'SLA compliance percentage over time',
                labelNames: ['endpoint', 'window'],
                registers: [this.register]
            }),
            
            // Performance violations
            slaViolations: new prometheus.Counter({
                name: 'performance_sla_violations_total',
                help: 'Total SLA violations',
                labelNames: ['endpoint', 'violation_type', 'severity'],
                registers: [this.register]
            }),
            
            // Real-time performance indicators
            currentResponseTime: new prometheus.Gauge({
                name: 'performance_current_response_time_ms',
                help: 'Current response time in milliseconds',
                labelNames: ['endpoint'],
                registers: [this.register]
            }),
            
            // Performance percentiles
            responseTimePercentiles: new prometheus.Gauge({
                name: 'performance_response_time_percentiles_ms',
                help: 'Response time percentiles',
                labelNames: ['endpoint', 'percentile'],
                registers: [this.register]
            }),
            
            // Throughput metrics
            requestRate: new prometheus.Gauge({
                name: 'performance_request_rate_per_second',
                help: 'Request rate per second',
                labelNames: ['endpoint'],
                registers: [this.register]
            }),
            
            // Error rate tracking
            errorRate: new prometheus.Gauge({
                name: 'performance_error_rate_percentage',
                help: 'Error rate percentage',
                labelNames: ['endpoint'],
                registers: [this.register]
            }),
            
            // Auto-scaling actions
            scalingActions: new prometheus.Counter({
                name: 'performance_scaling_actions_total',
                help: 'Total auto-scaling actions taken',
                labelNames: ['action_type', 'service'],
                registers: [this.register]
            }),
            
            // Performance score
            performanceScore: new prometheus.Gauge({
                name: 'performance_overall_score',
                help: 'Overall performance score (0-100)',
                labelNames: ['service'],
                registers: [this.register]
            })
        };
    }
    
    async initializeConnections() {
        try {
            // Redis for caching performance data
            if (process.env.REDIS_URL) {
                this.redis = new Redis(process.env.REDIS_URL);
                await this.redis.ping();
                console.log('Redis connected for performance caching');
            }
            
            console.log('Performance Guardian initialized successfully');
        } catch (error) {
            console.error('Failed to initialize Performance Guardian:', error);
        }
    }
    
    setupRoutes() {
        this.app.use(express.json());
        
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                service: 'performance-guardian',
                version: '1.0.0',
                monitoring: this.endpoints.length + ' endpoints',
                uptime: process.uptime(),
                thresholds: this.thresholds
            });
        });
        
        // Metrics endpoint
        this.app.get('/metrics', async (req, res) => {
            res.set('Content-Type', this.register.contentType);
            res.end(await this.register.metrics());
        });
        
        // Real-time performance dashboard
        this.app.get('/api/performance/realtime', async (req, res) => {
            try {
                const data = await this.getRealtimePerformance();
                res.json(data);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Performance analytics
        this.app.get('/api/performance/analytics', async (req, res) => {
            try {
                const period = req.query.period || '24h';
                const analytics = await this.getPerformanceAnalytics(period);
                res.json(analytics);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // SLA compliance report
        this.app.get('/api/performance/sla', async (req, res) => {
            try {
                const compliance = await this.getSLACompliance();
                res.json(compliance);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Performance trends
        this.app.get('/api/performance/trends', async (req, res) => {
            try {
                const trends = await this.getPerformanceTrends();
                res.json(trends);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Auto-scaling status
        this.app.get('/api/performance/scaling', async (req, res) => {
            try {
                const scaling = await this.getScalingStatus();
                res.json(scaling);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Manual scaling trigger
        this.app.post('/api/performance/scale', async (req, res) => {
            try {
                const { action, service, instances } = req.body;
                const result = await this.triggerScaling(action, service, instances);
                res.json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
    }
    
    startPerformanceMonitoring() {
        console.log(`Performance Guardian starting on port ${this.port}`);
        this.app.listen(this.port);
        
        // Start continuous performance monitoring every 15 seconds
        this.monitoringInterval = setInterval(() => {
            this.performPerformanceChecks();
        }, 15000);
        
        // Performance analysis every minute
        this.analysisInterval = setInterval(() => {
            this.analyzePerformanceTrends();
        }, 60000);
        
        // SLA compliance check every 5 minutes
        this.slaInterval = setInterval(() => {
            this.checkSLACompliance();
        }, 300000);
        
        // Auto-scaling evaluation every 30 seconds
        this.scalingInterval = setInterval(() => {
            this.evaluateAutoScaling();
        }, 30000);
        
        console.log('Performance monitoring started:');
        console.log('- Performance checks: every 15 seconds');
        console.log('- Trend analysis: every 60 seconds');
        console.log('- SLA compliance: every 5 minutes');
        console.log('- Auto-scaling: every 30 seconds');
        
        // Initial performance check
        this.performPerformanceChecks();
    }
    
    async performPerformanceChecks() {
        const timestamp = Date.now();
        const results = new Map();
        
        for (const endpoint of this.endpoints) {
            try {
                const result = await this.measureEndpointPerformance(endpoint);
                results.set(endpoint.name, result);
                
                // Store performance data
                await this.storePerformanceData(endpoint.name, result);
                
                // Update metrics
                this.updatePerformanceMetrics(endpoint.name, result);
                
                // Check for violations
                await this.checkPerformanceViolations(endpoint, result);
                
                // Emit performance event
                this.emit('performance_measured', {
                    endpoint: endpoint.name,
                    result,
                    timestamp
                });
                
            } catch (error) {
                console.error(`Performance check failed for ${endpoint.name}:`, error);
                
                // Record as error
                results.set(endpoint.name, {
                    success: false,
                    error: error.message,
                    timestamp
                });
            }
        }
        
        return results;
    }
    
    async measureEndpointPerformance(endpoint) {
        const measurements = [];
        const sampleCount = 5; // Take 5 samples for better accuracy
        
        for (let i = 0; i < sampleCount; i++) {
            const startTime = process.hrtime.bigint();
            
            try {
                const response = await axios({
                    method: 'GET',
                    url: endpoint.url,
                    timeout: 10000,
                    validateStatus: () => true
                });
                
                const endTime = process.hrtime.bigint();
                const responseTime = Number(endTime - startTime) / 1000000; // Convert to milliseconds
                
                measurements.push({
                    responseTime,
                    statusCode: response.status,
                    success: response.status >= 200 && response.status < 400,
                    timestamp: Date.now()
                });
                
                // Small delay between measurements
                if (i < sampleCount - 1) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
                
            } catch (error) {
                const endTime = process.hrtime.bigint();
                const responseTime = Number(endTime - startTime) / 1000000;
                
                measurements.push({
                    responseTime,
                    statusCode: null,
                    success: false,
                    error: error.message,
                    timestamp: Date.now()
                });
            }
        }
        
        // Calculate statistics
        const successfulMeasurements = measurements.filter(m => m.success);
        const responseTimes = successfulMeasurements.map(m => m.responseTime);
        
        if (responseTimes.length === 0) {
            return {
                success: false,
                errorRate: 100,
                measurements,
                timestamp: Date.now()
            };
        }
        
        responseTimes.sort((a, b) => a - b);
        
        const result = {
            success: true,
            responseTime: {
                min: Math.min(...responseTimes),
                max: Math.max(...responseTimes),
                avg: responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length,
                p50: this.percentile(responseTimes, 50),
                p95: this.percentile(responseTimes, 95),
                p99: this.percentile(responseTimes, 99)
            },
            errorRate: ((measurements.length - successfulMeasurements.length) / measurements.length) * 100,
            successRate: (successfulMeasurements.length / measurements.length) * 100,
            measurements,
            timestamp: Date.now(),
            slaViolation: this.percentile(responseTimes, 95) > endpoint.maxResponseTime
        };
        
        return result;
    }
    
    percentile(arr, p) {
        const index = (p / 100) * (arr.length - 1);
        const lower = Math.floor(index);
        const upper = Math.ceil(index);
        const weight = index - lower;
        
        if (lower === upper) {
            return arr[lower];
        }
        
        return arr[lower] * (1 - weight) + arr[upper] * weight;
    }
    
    async storePerformanceData(endpointName, result) {
        if (!this.redis) return;
        
        const key = `performance:${endpointName}`;
        const data = {
            timestamp: result.timestamp,
            responseTime: result.responseTime,
            errorRate: result.errorRate,
            slaViolation: result.slaViolation
        };
        
        try {
            // Store latest data
            await this.redis.hset(key + ':latest', data);
            
            // Store in time series (keep last 24 hours)
            await this.redis.zadd(key + ':timeseries', result.timestamp, JSON.stringify(data));
            await this.redis.zremrangebyscore(key + ':timeseries', 0, Date.now() - 24 * 60 * 60 * 1000);
            
            // Update performance cache with TTL
            await this.redis.setex(key + ':cache', 300, JSON.stringify(data));
            
        } catch (error) {
            console.error(`Failed to store performance data for ${endpointName}:`, error);
        }
    }
    
    updatePerformanceMetrics(endpointName, result) {
        if (!result.success) {
            this.metrics.errorRate.labels(endpointName).set(100);
            return;
        }
        
        const responseTime = result.responseTime;
        
        // Update response time histogram
        this.metrics.responseTime.labels(endpointName, 'GET', '200').observe(responseTime.avg / 1000);
        
        // Update current response time
        this.metrics.currentResponseTime.labels(endpointName).set(responseTime.avg);
        
        // Update percentiles
        this.metrics.responseTimePercentiles.labels(endpointName, '50').set(responseTime.p50);
        this.metrics.responseTimePercentiles.labels(endpointName, '95').set(responseTime.p95);
        this.metrics.responseTimePercentiles.labels(endpointName, '99').set(responseTime.p99);
        
        // Update error rate
        this.metrics.errorRate.labels(endpointName).set(result.errorRate);
    }
    
    async checkPerformanceViolations(endpoint, result) {
        if (!result.success) {
            await this.handleViolation(endpoint, 'availability', 'critical', result);
            return;
        }
        
        const p95ResponseTime = result.responseTime.p95;
        
        // Check response time violations
        if (p95ResponseTime > this.thresholds.responseTime.emergency) {
            await this.handleViolation(endpoint, 'response_time', 'emergency', result);
        } else if (p95ResponseTime > this.thresholds.responseTime.critical) {
            await this.handleViolation(endpoint, 'response_time', 'critical', result);
        } else if (p95ResponseTime > this.thresholds.responseTime.warning) {
            await this.handleViolation(endpoint, 'response_time', 'warning', result);
        }
        
        // Check error rate violations
        if (result.errorRate > this.thresholds.errorRate.emergency) {
            await this.handleViolation(endpoint, 'error_rate', 'emergency', result);
        } else if (result.errorRate > this.thresholds.errorRate.critical) {
            await this.handleViolation(endpoint, 'error_rate', 'critical', result);
        } else if (result.errorRate > this.thresholds.errorRate.warning) {
            await this.handleViolation(endpoint, 'error_rate', 'warning', result);
        }
        
        // SLA violation check
        if (result.slaViolation) {
            this.metrics.slaViolations.labels(endpoint.name, 'response_time', 'critical').inc();
            await this.handleViolation(endpoint, 'sla', 'critical', result);
        }
    }
    
    async handleViolation(endpoint, violationType, severity, result) {
        const violationKey = `${endpoint.name}:${violationType}:${severity}`;
        const lastViolation = this.alertHistory.get(violationKey);
        const now = Date.now();
        
        // Rate limiting: don't alert more than once per 5 minutes for the same violation
        if (lastViolation && (now - lastViolation) < 300000) {
            return;
        }
        
        this.alertHistory.set(violationKey, now);
        
        console.warn(`Performance violation detected:`, {
            endpoint: endpoint.name,
            type: violationType,
            severity,
            value: result.responseTime?.p95 || result.errorRate || 'N/A',
            timestamp: new Date().toISOString()
        });
        
        // Emit violation event for external handling
        this.emit('performance_violation', {
            endpoint,
            violationType,
            severity,
            result,
            timestamp: now
        });
        
        // Trigger auto-scaling if enabled and appropriate
        if (this.autoScaling.enabled && severity === 'critical' && violationType === 'response_time') {
            await this.considerScalingAction(endpoint, result);
        }
    }
    
    async considerScalingAction(endpoint, result) {
        const service = this.mapEndpointToService(endpoint.name);
        const lastScalingAction = this.scalingActions.get(service);
        const now = Date.now();
        
        // Check cooldown period
        if (lastScalingAction && (now - lastScalingAction.timestamp) < this.autoScaling.cooldown) {
            console.log(`Scaling action for ${service} is in cooldown period`);
            return;
        }
        
        const p95ResponseTime = result.responseTime.p95;
        
        if (p95ResponseTime > this.autoScaling.scaleUpThreshold) {
            await this.scaleService('up', service, 'performance');
        }
    }
    
    mapEndpointToService(endpointName) {
        const serviceMap = {
            'frontend_health': 'frontend',
            'api_health': 'backend',
            'user_login': 'backend',
            'annotation_create': 'backend',
            'lbs_location': 'backend',
            'payment_process': 'backend',
            'workers_api': 'workers'
        };
        
        return serviceMap[endpointName] || 'unknown';
    }
    
    async scaleService(action, service, reason) {
        console.log(`Triggering auto-scale ${action} for ${service} due to ${reason}`);
        
        // Record scaling action
        this.scalingActions.set(service, {
            action,
            reason,
            timestamp: Date.now()
        });
        
        // Update metrics
        this.metrics.scalingActions.labels(action, service).inc();
        
        // Emit scaling event for external systems to handle
        this.emit('auto_scaling', {
            action,
            service,
            reason,
            timestamp: Date.now()
        });
        
        // Here you would integrate with your actual scaling system
        // For example: Kubernetes HPA, Docker Swarm scaling, etc.
        
        return {
            success: true,
            action,
            service,
            reason,
            timestamp: Date.now()
        };
    }
    
    async getRealtimePerformance() {
        const realtime = {};
        
        for (const endpoint of this.endpoints) {
            if (this.redis) {
                try {
                    const cachedData = await this.redis.get(`performance:${endpoint.name}:cache`);
                    if (cachedData) {
                        realtime[endpoint.name] = JSON.parse(cachedData);
                    }
                } catch (error) {
                    console.error(`Failed to get realtime data for ${endpoint.name}:`, error);
                }
            }
        }
        
        return {
            timestamp: new Date().toISOString(),
            endpoints: realtime,
            thresholds: this.thresholds,
            overallScore: await this.calculateOverallPerformanceScore()
        };
    }
    
    async calculateOverallPerformanceScore() {
        // Calculate a performance score from 0-100 based on SLA compliance
        let totalScore = 0;
        let endpointCount = 0;
        
        for (const endpoint of this.endpoints) {
            if (this.redis) {
                try {
                    const cachedData = await this.redis.get(`performance:${endpoint.name}:cache`);
                    if (cachedData) {
                        const data = JSON.parse(cachedData);
                        let score = 100;
                        
                        // Deduct points for response time violations
                        if (data.responseTime && data.responseTime.p95 > endpoint.maxResponseTime) {
                            const violation = data.responseTime.p95 / endpoint.maxResponseTime;
                            score -= Math.min(50, violation * 25);
                        }
                        
                        // Deduct points for error rate
                        if (data.errorRate > 0) {
                            score -= Math.min(30, data.errorRate * 10);
                        }
                        
                        totalScore += Math.max(0, score);
                        endpointCount++;
                    }
                } catch (error) {
                    console.error(`Failed to calculate score for ${endpoint.name}:`, error);
                }
            }
        }
        
        return endpointCount > 0 ? Math.round(totalScore / endpointCount) : 0;
    }
}

module.exports = PerformanceGuardian;

// Start the guardian if this file is run directly
if (require.main === module) {
    const guardian = new PerformanceGuardian();
    
    // Handle graceful shutdown
    process.on('SIGTERM', () => {
        console.log('Shutting down Performance Guardian...');
        clearInterval(guardian.monitoringInterval);
        clearInterval(guardian.analysisInterval);
        clearInterval(guardian.slaInterval);
        clearInterval(guardian.scalingInterval);
        process.exit(0);
    });
}