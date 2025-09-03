/**
 * SmellPin SLA Monitoring Service
 * Monitors service level agreements and uptime requirements
 */

const express = require('express');
const prometheus = require('prom-client');
const axios = require('axios');
const nodemailer = require('nodemailer');
const { Client } = require('pg');
const Redis = require('ioredis');

class SLAMonitor {
    constructor() {
        this.app = express();
        this.port = process.env.SLA_MONITOR_PORT || 9201;
        
        // Initialize Prometheus metrics
        this.initializeMetrics();
        
        // Initialize database connections
        this.initializeConnections();
        
        // SLA Configuration
        this.slaConfig = {
            uptime: {
                target: 99.9, // 99.9% uptime requirement
                window: '30d' // 30-day rolling window
            },
            responseTime: {
                target: 200, // <200ms API response requirement
                percentile: 95 // P95 response time
            },
            errorRate: {
                target: 0.1, // <0.1% error rate
                window: '1h' // 1-hour window
            }
        };
        
        // Monitored endpoints
        this.endpoints = [
            { name: 'api_health', url: 'https://api.smellpin.com/health', critical: true },
            { name: 'frontend', url: 'https://smellpin.com', critical: true },
            { name: 'payment_webhook', url: 'https://api.smellpin.com/payments/webhook', critical: true },
            { name: 'user_registration', url: 'https://api.smellpin.com/api/users/health', critical: false },
            { name: 'annotation_service', url: 'https://api.smellpin.com/api/annotations/health', critical: false },
            { name: 'lbs_service', url: 'https://api.smellpin.com/api/lbs/health', critical: false }
        ];
        
        this.setupMiddleware();
        this.setupRoutes();
        this.startMonitoring();
    }

    initializeMetrics() {
        // Register default metrics
        prometheus.register.setDefaultLabels({
            app: 'smellpin-sla-monitor'
        });
        prometheus.collectDefaultMetrics();

        // Custom SLA metrics
        this.metrics = {
            uptimePercentage: new prometheus.Gauge({
                name: 'smellpin_uptime_percentage',
                help: 'Current uptime percentage for the last 30 days',
                labelNames: ['service', 'endpoint']
            }),

            responseTime: new prometheus.Histogram({
                name: 'smellpin_response_time_seconds',
                help: 'HTTP request response time in seconds',
                labelNames: ['service', 'endpoint', 'method'],
                buckets: [0.05, 0.1, 0.2, 0.5, 1, 2, 5]
            }),

            availabilityStatus: new prometheus.Gauge({
                name: 'smellpin_endpoint_up',
                help: 'Whether an endpoint is up (1) or down (0)',
                labelNames: ['service', 'endpoint', 'critical']
            }),

            slaViolations: new prometheus.Counter({
                name: 'smellpin_sla_violations_total',
                help: 'Total number of SLA violations',
                labelNames: ['type', 'service', 'severity']
            }),

            meanTimeToRecovery: new prometheus.Histogram({
                name: 'smellpin_mttr_seconds',
                help: 'Mean time to recovery in seconds',
                labelNames: ['service', 'incident_type'],
                buckets: [60, 300, 900, 1800, 3600, 7200, 14400]
            }),

            errorRate: new prometheus.Gauge({
                name: 'smellpin_error_rate_percentage',
                help: 'Current error rate percentage',
                labelNames: ['service', 'endpoint']
            })
        };
    }

    async initializeConnections() {
        try {
            // PostgreSQL connection for storing SLA data
            this.pg = new Client({
                connectionString: process.env.DATABASE_URL,
                ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
            });
            await this.pg.connect();

            // Redis connection for caching and real-time data
            this.redis = new Redis(process.env.REDIS_URL);

            // Email transporter for SLA violation notifications
            this.emailTransporter = nodemailer.createTransporter({
                host: process.env.SMTP_HOST,
                port: process.env.SMTP_PORT,
                secure: false,
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });

            console.log('SLA Monitor connections initialized successfully');
        } catch (error) {
            console.error('Failed to initialize connections:', error);
            process.exit(1);
        }
    }

    setupMiddleware() {
        this.app.use(express.json());
        this.app.use(express.urlencoded({ extended: true }));
        
        // CORS middleware
        this.app.use((req, res, next) => {
            res.header('Access-Control-Allow-Origin', '*');
            res.header('Access-Control-Allow-Headers', 'Content-Type');
            next();
        });
    }

    setupRoutes() {
        // Metrics endpoint
        this.app.get('/metrics', async (req, res) => {
            try {
                res.set('Content-Type', prometheus.register.contentType);
                const metrics = await prometheus.register.metrics();
                res.send(metrics);
            } catch (error) {
                res.status(500).send('Error generating metrics');
            }
        });

        // SLA status endpoint
        this.app.get('/sla/status', async (req, res) => {
            try {
                const status = await this.getSLAStatus();
                res.json(status);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // SLA report endpoint
        this.app.get('/sla/report', async (req, res) => {
            try {
                const { period = '30d' } = req.query;
                const report = await this.generateSLAReport(period);
                res.json(report);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });

        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime()
            });
        });
    }

    async startMonitoring() {
        console.log(`Starting SLA monitoring on port ${this.port}`);
        
        // Start HTTP server
        this.app.listen(this.port, () => {
            console.log(`SLA Monitor listening on port ${this.port}`);
        });

        // Start endpoint monitoring
        this.monitorEndpoints();
        
        // Start SLA calculations
        this.calculateSLAMetrics();
        
        // Start incident tracking
        this.trackIncidents();
    }

    async monitorEndpoints() {
        const checkInterval = 30000; // 30 seconds
        
        setInterval(async () => {
            for (const endpoint of this.endpoints) {
                await this.checkEndpoint(endpoint);
            }
        }, checkInterval);

        console.log(`Endpoint monitoring started with ${checkInterval/1000}s interval`);
    }

    async checkEndpoint(endpoint) {
        const startTime = Date.now();
        const timestamp = new Date();

        try {
            const response = await axios.get(endpoint.url, {
                timeout: 10000, // 10 second timeout
                headers: {
                    'User-Agent': 'SmellPin-SLA-Monitor/1.0'
                }
            });

            const responseTime = (Date.now() - startTime) / 1000;
            const isUp = response.status >= 200 && response.status < 400;

            // Update Prometheus metrics
            this.metrics.responseTime
                .labels(endpoint.name, endpoint.url, 'GET')
                .observe(responseTime);

            this.metrics.availabilityStatus
                .labels(endpoint.name, endpoint.url, endpoint.critical.toString())
                .set(isUp ? 1 : 0);

            // Store data for SLA calculations
            await this.storeEndpointData(endpoint, {
                timestamp,
                responseTime: responseTime * 1000, // Convert to milliseconds
                statusCode: response.status,
                isUp,
                errorMessage: null
            });

            // Check for SLA violations
            await this.checkSLAViolations(endpoint, responseTime * 1000, isUp);

        } catch (error) {
            const responseTime = (Date.now() - startTime) / 1000;
            
            // Update metrics for failed request
            this.metrics.availabilityStatus
                .labels(endpoint.name, endpoint.url, endpoint.critical.toString())
                .set(0);

            // Store failure data
            await this.storeEndpointData(endpoint, {
                timestamp,
                responseTime: responseTime * 1000,
                statusCode: error.response?.status || 0,
                isUp: false,
                errorMessage: error.message
            });

            // Check for SLA violations (service down)
            await this.checkSLAViolations(endpoint, responseTime * 1000, false);

            console.error(`Endpoint check failed for ${endpoint.name}:`, error.message);
        }
    }

    async storeEndpointData(endpoint, data) {
        try {
            // Store in PostgreSQL for historical analysis
            await this.pg.query(`
                INSERT INTO endpoint_monitoring_data 
                (endpoint_name, endpoint_url, timestamp, response_time_ms, status_code, is_up, error_message)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            `, [
                endpoint.name,
                endpoint.url,
                data.timestamp,
                data.responseTime,
                data.statusCode,
                data.isUp,
                data.errorMessage
            ]);

            // Store in Redis for real-time access
            const redisKey = `endpoint:${endpoint.name}:latest`;
            await this.redis.setex(redisKey, 300, JSON.stringify(data)); // 5 minutes TTL

        } catch (error) {
            console.error('Failed to store endpoint data:', error);
        }
    }

    async checkSLAViolations(endpoint, responseTime, isUp) {
        const violations = [];

        // Check uptime SLA
        if (!isUp && endpoint.critical) {
            violations.push({
                type: 'availability',
                severity: 'critical',
                message: `Critical endpoint ${endpoint.name} is down`
            });
        }

        // Check response time SLA
        if (isUp && responseTime > this.slaConfig.responseTime.target) {
            violations.push({
                type: 'performance',
                severity: responseTime > 1000 ? 'critical' : 'warning',
                message: `Response time ${responseTime}ms exceeds SLA target of ${this.slaConfig.responseTime.target}ms`
            });
        }

        // Process violations
        for (const violation of violations) {
            await this.handleSLAViolation(endpoint, violation);
        }
    }

    async handleSLAViolation(endpoint, violation) {
        try {
            // Update Prometheus metrics
            this.metrics.slaViolations
                .labels(violation.type, endpoint.name, violation.severity)
                .inc();

            // Store violation record
            await this.pg.query(`
                INSERT INTO sla_violations 
                (endpoint_name, violation_type, severity, message, timestamp)
                VALUES ($1, $2, $3, $4, $5)
            `, [
                endpoint.name,
                violation.type,
                violation.severity,
                violation.message,
                new Date()
            ]);

            // Send alert if critical
            if (violation.severity === 'critical') {
                await this.sendSLAViolationAlert(endpoint, violation);
            }

        } catch (error) {
            console.error('Failed to handle SLA violation:', error);
        }
    }

    async sendSLAViolationAlert(endpoint, violation) {
        try {
            const subject = `🚨 SLA Violation: ${endpoint.name}`;
            const message = `
                SLA Violation Detected:
                
                Endpoint: ${endpoint.name} (${endpoint.url})
                Type: ${violation.type}
                Severity: ${violation.severity}
                Message: ${violation.message}
                Time: ${new Date().toISOString()}
                
                Please investigate immediately.
            `;

            // Send email alert
            await this.emailTransporter.sendMail({
                from: process.env.SMTP_FROM,
                to: 'devops@smellpin.com,oncall@smellpin.com',
                subject,
                text: message
            });

            // Send Slack notification if webhook is configured
            if (process.env.SLACK_WEBHOOK_URL) {
                await axios.post(process.env.SLACK_WEBHOOK_URL, {
                    text: subject,
                    attachments: [{
                        color: 'danger',
                        fields: [{
                            title: 'SLA Violation Details',
                            value: message,
                            short: false
                        }]
                    }]
                });
            }

        } catch (error) {
            console.error('Failed to send SLA violation alert:', error);
        }
    }

    async calculateSLAMetrics() {
        const calculateInterval = 60000; // 1 minute

        setInterval(async () => {
            try {
                for (const endpoint of this.endpoints) {
                    await this.calculateEndpointSLA(endpoint);
                }
            } catch (error) {
                console.error('Error calculating SLA metrics:', error);
            }
        }, calculateInterval);
    }

    async calculateEndpointSLA(endpoint) {
        try {
            const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

            // Calculate uptime percentage
            const uptimeResult = await this.pg.query(`
                SELECT 
                    COUNT(*) as total_checks,
                    COUNT(*) FILTER (WHERE is_up = true) as successful_checks
                FROM endpoint_monitoring_data 
                WHERE endpoint_name = $1 AND timestamp >= $2
            `, [endpoint.name, thirtyDaysAgo]);

            const { total_checks, successful_checks } = uptimeResult.rows[0];
            const uptimePercentage = total_checks > 0 ? (successful_checks / total_checks) * 100 : 100;

            // Calculate P95 response time
            const responseTimeResult = await this.pg.query(`
                SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_response_time
                FROM endpoint_monitoring_data 
                WHERE endpoint_name = $1 AND timestamp >= $2 AND is_up = true
            `, [endpoint.name, thirtyDaysAgo]);

            const p95ResponseTime = responseTimeResult.rows[0]?.p95_response_time || 0;

            // Calculate error rate
            const errorRateResult = await this.pg.query(`
                SELECT 
                    COUNT(*) as total_requests,
                    COUNT(*) FILTER (WHERE status_code >= 400 OR is_up = false) as error_requests
                FROM endpoint_monitoring_data 
                WHERE endpoint_name = $1 AND timestamp >= $2
            `, [endpoint.name, thirtyDaysAgo]);

            const { total_requests, error_requests } = errorRateResult.rows[0];
            const errorRate = total_requests > 0 ? (error_requests / total_requests) * 100 : 0;

            // Update Prometheus metrics
            this.metrics.uptimePercentage
                .labels(endpoint.name, endpoint.url)
                .set(uptimePercentage);

            this.metrics.errorRate
                .labels(endpoint.name, endpoint.url)
                .set(errorRate);

        } catch (error) {
            console.error(`Error calculating SLA for ${endpoint.name}:`, error);
        }
    }

    async getSLAStatus() {
        const status = {};

        for (const endpoint of this.endpoints) {
            const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

            // Get current status
            const latestData = await this.redis.get(`endpoint:${endpoint.name}:latest`);
            const latest = latestData ? JSON.parse(latestData) : null;

            // Get SLA metrics
            const slaData = await this.pg.query(`
                SELECT 
                    COUNT(*) as total_checks,
                    COUNT(*) FILTER (WHERE is_up = true) as successful_checks,
                    AVG(response_time_ms) FILTER (WHERE is_up = true) as avg_response_time,
                    percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) FILTER (WHERE is_up = true) as p95_response_time
                FROM endpoint_monitoring_data 
                WHERE endpoint_name = $1 AND timestamp >= $2
            `, [endpoint.name, thirtyDaysAgo]);

            const metrics = slaData.rows[0];
            const uptimePercentage = metrics.total_checks > 0 ? 
                (metrics.successful_checks / metrics.total_checks) * 100 : 100;

            status[endpoint.name] = {
                isUp: latest?.isUp || false,
                lastCheck: latest?.timestamp || null,
                responseTime: latest?.responseTime || null,
                uptime: {
                    percentage: parseFloat(uptimePercentage.toFixed(3)),
                    target: this.slaConfig.uptime.target,
                    compliant: uptimePercentage >= this.slaConfig.uptime.target
                },
                performance: {
                    avgResponseTime: parseFloat(metrics.avg_response_time || 0),
                    p95ResponseTime: parseFloat(metrics.p95_response_time || 0),
                    target: this.slaConfig.responseTime.target,
                    compliant: (metrics.p95_response_time || 0) <= this.slaConfig.responseTime.target
                }
            };
        }

        return status;
    }

    async generateSLAReport(period = '30d') {
        const days = parseInt(period.replace('d', ''));
        const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

        const report = {
            period,
            generatedAt: new Date().toISOString(),
            overall: {
                uptimeTarget: this.slaConfig.uptime.target,
                responseTimeTarget: this.slaConfig.responseTime.target
            },
            endpoints: {}
        };

        for (const endpoint of this.endpoints) {
            const endpointReport = await this.pg.query(`
                SELECT 
                    COUNT(*) as total_checks,
                    COUNT(*) FILTER (WHERE is_up = true) as successful_checks,
                    COUNT(*) FILTER (WHERE is_up = false) as failed_checks,
                    AVG(response_time_ms) FILTER (WHERE is_up = true) as avg_response_time,
                    percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) FILTER (WHERE is_up = true) as p95_response_time,
                    MAX(response_time_ms) FILTER (WHERE is_up = true) as max_response_time,
                    MIN(response_time_ms) FILTER (WHERE is_up = true) as min_response_time
                FROM endpoint_monitoring_data 
                WHERE endpoint_name = $1 AND timestamp >= $2
            `, [endpoint.name, startDate]);

            const violations = await this.pg.query(`
                SELECT violation_type, severity, COUNT(*) as count
                FROM sla_violations 
                WHERE endpoint_name = $1 AND timestamp >= $2
                GROUP BY violation_type, severity
            `, [endpoint.name, startDate]);

            const data = endpointReport.rows[0];
            const uptimePercentage = data.total_checks > 0 ? 
                (data.successful_checks / data.total_checks) * 100 : 100;

            report.endpoints[endpoint.name] = {
                url: endpoint.url,
                critical: endpoint.critical,
                uptime: {
                    percentage: parseFloat(uptimePercentage.toFixed(3)),
                    totalChecks: parseInt(data.total_checks),
                    successfulChecks: parseInt(data.successful_checks),
                    failedChecks: parseInt(data.failed_checks),
                    slaCompliant: uptimePercentage >= this.slaConfig.uptime.target
                },
                performance: {
                    avgResponseTime: parseFloat(data.avg_response_time || 0),
                    p95ResponseTime: parseFloat(data.p95_response_time || 0),
                    maxResponseTime: parseFloat(data.max_response_time || 0),
                    minResponseTime: parseFloat(data.min_response_time || 0),
                    slaCompliant: (data.p95_response_time || 0) <= this.slaConfig.responseTime.target
                },
                violations: violations.rows.reduce((acc, row) => {
                    const key = `${row.violation_type}_${row.severity}`;
                    acc[key] = parseInt(row.count);
                    return acc;
                }, {})
            };
        }

        return report;
    }

    async trackIncidents() {
        // This method would integrate with incident management systems
        // to track Mean Time To Recovery (MTTR) and other incident metrics
        console.log('Incident tracking initialized');
    }
}

// Initialize database schema
async function initializeDatabase() {
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    try {
        await client.connect();

        // Create tables if they don't exist
        await client.query(`
            CREATE TABLE IF NOT EXISTS endpoint_monitoring_data (
                id SERIAL PRIMARY KEY,
                endpoint_name VARCHAR(100) NOT NULL,
                endpoint_url VARCHAR(500) NOT NULL,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                response_time_ms NUMERIC(10,2),
                status_code INTEGER,
                is_up BOOLEAN NOT NULL,
                error_message TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_endpoint_monitoring_timestamp 
            ON endpoint_monitoring_data (endpoint_name, timestamp DESC);
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS sla_violations (
                id SERIAL PRIMARY KEY,
                endpoint_name VARCHAR(100) NOT NULL,
                violation_type VARCHAR(50) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                message TEXT,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                resolved_at TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_sla_violations_timestamp 
            ON sla_violations (endpoint_name, timestamp DESC);
        `);

        console.log('Database schema initialized successfully');
    } catch (error) {
        console.error('Failed to initialize database:', error);
        process.exit(1);
    } finally {
        await client.end();
    }
}

// Start the SLA monitor
async function main() {
    await initializeDatabase();
    new SLAMonitor();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = SLAMonitor;