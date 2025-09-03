/**
 * SmellPin Enterprise Monitoring System
 * Comprehensive 99.9% uptime monitoring with advanced alerting and incident management
 */

const express = require('express');
const prometheus = require('prom-client');
const axios = require('axios');
const nodemailer = require('nodemailer');
const { Client } = require('pg');
const Redis = require('ioredis');
const cron = require('node-cron');

class EnterpriseMonitor {
    constructor() {
        this.app = express();
        this.port = process.env.ENTERPRISE_MONITOR_PORT || 9300;
        
        // SLA Requirements
        this.slaTargets = {
            uptime: 99.9, // 99.9% uptime (43.2 minutes downtime per month)
            responseTime: {
                p95: 200, // <200ms P95 response time
                p99: 500  // <500ms P99 response time
            },
            errorRate: 0.1, // <0.1% error rate
            mttr: 900, // Mean Time To Recovery <15 minutes
            mtbf: 2592000 // Mean Time Between Failures >30 days
        };
        
        // Comprehensive endpoint monitoring
        this.monitoredServices = {
            frontend: {
                name: 'Frontend Application',
                endpoints: [
                    { url: 'https://smellpin.com/health', timeout: 10000, critical: true },
                    { url: 'https://smellpin.com/', timeout: 15000, critical: true },
                    { url: 'https://smellpin.com/map', timeout: 20000, critical: false }
                ]
            },
            api: {
                name: 'Backend API',
                endpoints: [
                    { url: 'https://api.smellpin.com/health', timeout: 5000, critical: true },
                    { url: 'https://api.smellpin.com/api/health', timeout: 5000, critical: true },
                    { url: 'https://api.smellpin.com/api/users/health', timeout: 8000, critical: false },
                    { url: 'https://api.smellpin.com/api/annotations/health', timeout: 8000, critical: true },
                    { url: 'https://api.smellpin.com/api/payments/health', timeout: 10000, critical: true }
                ]
            },
            workers: {
                name: 'Cloudflare Workers',
                endpoints: [
                    { url: 'https://smellpin-workers.your-subdomain.workers.dev/health', timeout: 5000, critical: true },
                    { url: 'https://smellpin-workers.your-subdomain.workers.dev/api/health', timeout: 5000, critical: true }
                ]
            },
            infrastructure: {
                name: 'Infrastructure Services',
                endpoints: [
                    { url: 'https://api.smellpin.com/health/db', timeout: 8000, critical: true },
                    { url: 'https://api.smellpin.com/health/redis', timeout: 3000, critical: false },
                    { url: 'https://api.smellpin.com/health/storage', timeout: 5000, critical: false }
                ]
            }
        };
        
        // Alert configuration
        this.alertChannels = {
            slack: {
                enabled: !!process.env.SLACK_WEBHOOK_URL,
                webhook: process.env.SLACK_WEBHOOK_URL,
                channel: '#alerts-production'
            },
            pagerduty: {
                enabled: !!process.env.PAGERDUTY_INTEGRATION_KEY,
                integrationKey: process.env.PAGERDUTY_INTEGRATION_KEY
            },
            email: {
                enabled: !!process.env.SMTP_HOST,
                recipients: ['devops@smellpin.com', 'oncall@smellpin.com']
            }
        };
        
        // State management
        this.incidents = new Map();
        this.downtimeRecords = [];
        this.performanceMetrics = new Map();
        this.lastAlerts = new Map();
        
        this.initializeMetrics();
        this.initializeConnections();
        this.setupRoutes();
        this.startMonitoring();
    }
    
    initializeMetrics() {
        // Create comprehensive Prometheus metrics
        this.register = new prometheus.Register();
        prometheus.register.setDefaultLabels({ app: 'smellpin-enterprise-monitor' });
        
        this.metrics = {
            // Uptime and availability metrics
            serviceUptime: new prometheus.Gauge({
                name: 'smellpin_service_uptime_percentage',
                help: 'Service uptime percentage over rolling windows',
                labelNames: ['service', 'window', 'region'],
                registers: [this.register]
            }),
            
            endpointAvailability: new prometheus.Gauge({
                name: 'smellpin_endpoint_availability',
                help: 'Endpoint availability (1=up, 0=down)',
                labelNames: ['service', 'endpoint', 'critical'],
                registers: [this.register]
            }),
            
            // Performance metrics
            responseTimeHistogram: new prometheus.Histogram({
                name: 'smellpin_response_time_seconds',
                help: 'Response time distribution',
                labelNames: ['service', 'endpoint', 'method', 'status_code'],
                buckets: [0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 30],
                registers: [this.register]
            }),
            
            responseTimePercentiles: new prometheus.Gauge({
                name: 'smellpin_response_time_percentiles',
                help: 'Response time percentiles',
                labelNames: ['service', 'endpoint', 'percentile'],
                registers: [this.register]
            }),
            
            // Error tracking
            errorRate: new prometheus.Gauge({
                name: 'smellpin_error_rate_percentage',
                help: 'Error rate percentage',
                labelNames: ['service', 'endpoint', 'error_type'],
                registers: [this.register]
            }),
            
            httpErrors: new prometheus.Counter({
                name: 'smellpin_http_errors_total',
                help: 'Total HTTP errors',
                labelNames: ['service', 'endpoint', 'status_code'],
                registers: [this.register]
            }),
            
            // SLA compliance
            slaCompliance: new prometheus.Gauge({
                name: 'smellpin_sla_compliance',
                help: 'SLA compliance percentage',
                labelNames: ['service', 'metric_type'],
                registers: [this.register]
            }),
            
            slaViolations: new prometheus.Counter({
                name: 'smellpin_sla_violations_total',
                help: 'Total SLA violations',
                labelNames: ['service', 'violation_type', 'severity'],
                registers: [this.register]
            }),
            
            // Incident metrics
            activeIncidents: new prometheus.Gauge({
                name: 'smellpin_active_incidents',
                help: 'Number of active incidents',
                labelNames: ['service', 'severity'],
                registers: [this.register]
            }),
            
            mttr: new prometheus.Histogram({
                name: 'smellpin_mttr_seconds',
                help: 'Mean Time To Recovery',
                labelNames: ['service', 'incident_type'],
                buckets: [60, 300, 900, 1800, 3600, 7200, 14400, 28800],
                registers: [this.register]
            }),
            
            mtbf: new prometheus.Gauge({
                name: 'smellpin_mtbf_seconds',
                help: 'Mean Time Between Failures',
                labelNames: ['service'],
                registers: [this.register]
            }),
            
            // Business metrics
            userImpact: new prometheus.Gauge({
                name: 'smellpin_users_impacted',
                help: 'Number of users impacted by incidents',
                labelNames: ['service', 'incident_id'],
                registers: [this.register]
            })
        };
    }
    
    async initializeConnections() {
        try {
            // PostgreSQL for persistent data storage
            if (process.env.DATABASE_URL) {
                this.pg = new Client({
                    connectionString: process.env.DATABASE_URL,
                    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
                });
                await this.pg.connect();
                await this.createTables();
            }
            
            // Redis for caching and real-time data
            if (process.env.REDIS_URL) {
                this.redis = new Redis(process.env.REDIS_URL);
            }
            
            // Email configuration
            if (this.alertChannels.email.enabled) {
                this.emailTransporter = nodemailer.createTransporter({
                    host: process.env.SMTP_HOST,
                    port: process.env.SMTP_PORT || 587,
                    secure: false,
                    auth: {
                        user: process.env.SMTP_USER,
                        pass: process.env.SMTP_PASS
                    }
                });
            }
            
            console.log('Enterprise Monitor initialized successfully');
        } catch (error) {
            console.error('Failed to initialize Enterprise Monitor:', error);
        }
    }
    
    async createTables() {
        const queries = [
            `CREATE TABLE IF NOT EXISTS monitoring_checks (
                id SERIAL PRIMARY KEY,
                service_name VARCHAR(100) NOT NULL,
                endpoint_url TEXT NOT NULL,
                status VARCHAR(20) NOT NULL,
                response_time INTEGER,
                status_code INTEGER,
                error_message TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                region VARCHAR(50) DEFAULT 'us-east-1'
            )`,
            
            `CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                incident_id VARCHAR(100) UNIQUE NOT NULL,
                service_name VARCHAR(100) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                status VARCHAR(20) DEFAULT 'open',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                users_impacted INTEGER DEFAULT 0,
                resolution_summary TEXT
            )`,
            
            `CREATE TABLE IF NOT EXISTS sla_reports (
                id SERIAL PRIMARY KEY,
                service_name VARCHAR(100) NOT NULL,
                period_start TIMESTAMP NOT NULL,
                period_end TIMESTAMP NOT NULL,
                uptime_percentage DECIMAL(5,3),
                avg_response_time INTEGER,
                p95_response_time INTEGER,
                p99_response_time INTEGER,
                error_rate DECIMAL(5,3),
                total_requests BIGINT,
                failed_requests BIGINT,
                incidents_count INTEGER,
                mttr_seconds INTEGER
            )`
        ];
        
        for (const query of queries) {
            await this.pg.query(query);
        }
    }
    
    setupRoutes() {
        this.app.use(express.json());
        
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                service: 'enterprise-monitor',
                version: '1.0.0',
                uptime: process.uptime(),
                timestamp: new Date().toISOString()
            });
        });
        
        // Prometheus metrics
        this.app.get('/metrics', async (req, res) => {
            res.set('Content-Type', this.register.contentType);
            res.end(await this.register.metrics());
        });
        
        // Real-time dashboard data
        this.app.get('/api/dashboard', async (req, res) => {
            try {
                const dashboard = await this.getDashboardData();
                res.json(dashboard);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // SLA compliance report
        this.app.get('/api/sla/compliance', async (req, res) => {
            try {
                const period = req.query.period || '30d';
                const compliance = await this.getSLACompliance(period);
                res.json(compliance);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Incident management
        this.app.get('/api/incidents', async (req, res) => {
            try {
                const incidents = await this.getIncidents(req.query);
                res.json(incidents);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        this.app.post('/api/incidents/:id/resolve', async (req, res) => {
            try {
                const result = await this.resolveIncident(req.params.id, req.body);
                res.json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Performance analytics
        this.app.get('/api/performance/:service', async (req, res) => {
            try {
                const performance = await this.getPerformanceMetrics(req.params.service, req.query);
                res.json(performance);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
        
        // Alert testing
        this.app.post('/api/alerts/test', async (req, res) => {
            try {
                const result = await this.testAlerts(req.body);
                res.json(result);
            } catch (error) {
                res.status(500).json({ error: error.message });
            }
        });
    }
    
    startMonitoring() {
        console.log(`Enterprise Monitor starting on port ${this.port}`);
        this.app.listen(this.port);
        
        // Start health checks every 30 seconds
        this.healthCheckInterval = setInterval(() => {
            this.performHealthChecks();
        }, 30000);
        
        // Generate SLA reports daily at midnight
        cron.schedule('0 0 * * *', () => {
            this.generateDailySLAReport();
        });
        
        // Clean up old data weekly
        cron.schedule('0 2 * * 0', () => {
            this.cleanupOldData();
        });
        
        // Initial health check
        this.performHealthChecks();
        
        console.log('Enterprise monitoring started successfully');
        console.log('Health checks running every 30 seconds');
        console.log('SLA reports generated daily at midnight');
    }
    
    async performHealthChecks() {
        const timestamp = new Date();
        const results = new Map();
        
        for (const [serviceName, service] of Object.entries(this.monitoredServices)) {
            for (const endpoint of service.endpoints) {
                try {
                    const result = await this.checkEndpoint(serviceName, endpoint);
                    results.set(`${serviceName}:${endpoint.url}`, result);
                    
                    // Store in database
                    if (this.pg) {
                        await this.storeHealthCheck(serviceName, endpoint.url, result);
                    }
                    
                    // Update metrics
                    await this.updateMetrics(serviceName, endpoint, result);
                    
                    // Check for incidents
                    await this.checkForIncidents(serviceName, endpoint, result);
                    
                } catch (error) {
                    console.error(`Health check failed for ${serviceName}:${endpoint.url}:`, error);
                }
            }
        }
        
        // Update overall service health
        await this.updateServiceHealth();
        
        return results;
    }
    
    async checkEndpoint(serviceName, endpoint) {
        const startTime = Date.now();
        const maxRetries = 3;
        
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                const response = await axios({
                    method: 'GET',
                    url: endpoint.url,
                    timeout: endpoint.timeout,
                    validateStatus: () => true // Don't throw on HTTP errors
                });
                
                const responseTime = Date.now() - startTime;
                const isHealthy = response.status >= 200 && response.status < 400;
                
                return {
                    status: isHealthy ? 'up' : 'down',
                    responseTime,
                    statusCode: response.status,
                    attempt,
                    timestamp: new Date().toISOString(),
                    error: isHealthy ? null : `HTTP ${response.status}`,
                    region: process.env.AWS_REGION || 'us-east-1'
                };
                
            } catch (error) {
                if (attempt === maxRetries) {
                    return {
                        status: 'down',
                        responseTime: Date.now() - startTime,
                        statusCode: null,
                        attempt,
                        timestamp: new Date().toISOString(),
                        error: error.message,
                        errorCode: error.code
                    };
                }
                
                // Wait before retry (exponential backoff)
                await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
            }
        }
    }
    
    async updateMetrics(serviceName, endpoint, result) {
        const labels = {
            service: serviceName,
            endpoint: endpoint.url,
            critical: endpoint.critical.toString()
        };
        
        // Update availability
        this.metrics.endpointAvailability.set(labels, result.status === 'up' ? 1 : 0);
        
        // Update response time
        if (result.responseTime) {
            this.metrics.responseTimeHistogram
                .labels(serviceName, endpoint.url, 'GET', result.statusCode || 'timeout')
                .observe(result.responseTime / 1000);
        }
        
        // Update error metrics
        if (result.status !== 'up') {
            this.metrics.httpErrors
                .labels(serviceName, endpoint.url, result.statusCode || 'timeout')
                .inc();
        }
    }
    
    async checkForIncidents(serviceName, endpoint, result) {
        const incidentKey = `${serviceName}:${endpoint.url}`;
        const existingIncident = this.incidents.get(incidentKey);
        
        if (result.status !== 'up' && endpoint.critical) {
            if (!existingIncident) {
                // Create new incident
                const incident = await this.createIncident(serviceName, endpoint, result);
                this.incidents.set(incidentKey, incident);
                
                // Send immediate alert
                await this.sendAlert('critical', incident);
            } else if (!existingIncident.escalated && 
                      (Date.now() - existingIncident.startTime) > 15 * 60 * 1000) {
                // Escalate after 15 minutes
                existingIncident.escalated = true;
                await this.escalateIncident(existingIncident);
            }
        } else if (result.status === 'up' && existingIncident) {
            // Resolve incident
            await this.resolveIncident(existingIncident.id, {
                resolvedBy: 'system',
                resolution: 'Service recovered automatically'
            });
            this.incidents.delete(incidentKey);
        }
    }
    
    async createIncident(serviceName, endpoint, result) {
        const incidentId = `INC-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const incident = {
            id: incidentId,
            service: serviceName,
            endpoint: endpoint.url,
            severity: endpoint.critical ? 'critical' : 'major',
            title: `${serviceName} service unavailable`,
            description: `Endpoint ${endpoint.url} is down. Error: ${result.error}`,
            status: 'open',
            startTime: Date.now(),
            resolvedTime: null,
            usersImpacted: this.estimateUserImpact(serviceName),
            escalated: false
        };
        
        // Store in database
        if (this.pg) {
            await this.pg.query(`
                INSERT INTO incidents (incident_id, service_name, severity, title, description, users_impacted)
                VALUES ($1, $2, $3, $4, $5, $6)
            `, [incident.id, incident.service, incident.severity, incident.title, 
                incident.description, incident.usersImpacted]);
        }
        
        // Update metrics
        this.metrics.activeIncidents.labels(serviceName, incident.severity).inc();
        this.metrics.userImpact.labels(serviceName, incident.id).set(incident.usersImpacted);
        
        console.log(`Created incident: ${incident.id} for ${serviceName}`);
        return incident;
    }
    
    async sendAlert(level, incident) {
        const alertKey = `${incident.service}:${incident.endpoint}:${level}`;
        const lastAlert = this.lastAlerts.get(alertKey);
        const now = Date.now();
        
        // Rate limiting: don't send the same alert more than once per 10 minutes
        if (lastAlert && (now - lastAlert) < 10 * 60 * 1000) {
            return;
        }
        
        this.lastAlerts.set(alertKey, now);
        
        const alertData = {
            timestamp: new Date().toISOString(),
            level,
            service: incident.service,
            incident: incident,
            dashboard: `https://monitoring.smellpin.com/incidents/${incident.id}`
        };
        
        // Send to all configured channels
        if (this.alertChannels.slack.enabled) {
            await this.sendSlackAlert(alertData);
        }
        
        if (this.alertChannels.pagerduty.enabled && level === 'critical') {
            await this.sendPagerDutyAlert(alertData);
        }
        
        if (this.alertChannels.email.enabled) {
            await this.sendEmailAlert(alertData);
        }
    }
    
    async sendSlackAlert(alertData) {
        try {
            const color = alertData.level === 'critical' ? '#FF0000' : '#FFA500';
            const payload = {
                username: 'SmellPin Monitor',
                channel: this.alertChannels.slack.channel,
                text: `🚨 ${alertData.level.toUpperCase()} Alert - ${alertData.service}`,
                attachments: [{
                    color,
                    title: alertData.incident.title,
                    text: alertData.incident.description,
                    fields: [
                        { title: 'Service', value: alertData.service, short: true },
                        { title: 'Severity', value: alertData.incident.severity, short: true },
                        { title: 'Users Impacted', value: alertData.incident.usersImpacted, short: true },
                        { title: 'Incident ID', value: alertData.incident.id, short: true }
                    ],
                    actions: [{
                        type: 'button',
                        text: 'View Dashboard',
                        url: alertData.dashboard
                    }],
                    timestamp: Math.floor(Date.now() / 1000)
                }]
            };
            
            await axios.post(this.alertChannels.slack.webhook, payload);
        } catch (error) {
            console.error('Failed to send Slack alert:', error);
        }
    }
    
    async getDashboardData() {
        const now = Date.now();
        const services = {};
        
        // Get current service status
        for (const [serviceName, service] of Object.entries(this.monitoredServices)) {
            const endpoints = [];
            
            for (const endpoint of service.endpoints) {
                const key = `${serviceName}:${endpoint.url}`;
                const lastCheck = await this.getLastHealthCheck(serviceName, endpoint.url);
                
                endpoints.push({
                    url: endpoint.url,
                    critical: endpoint.critical,
                    status: lastCheck?.status || 'unknown',
                    responseTime: lastCheck?.response_time,
                    lastCheck: lastCheck?.checked_at
                });
            }
            
            services[serviceName] = {
                name: service.name,
                endpoints,
                overallStatus: this.calculateServiceStatus(endpoints),
                uptime: await this.calculateServiceUptime(serviceName, '24h')\n            };\n        }\n        \n        return {\n            timestamp: new Date().toISOString(),\n            services,\n            overall: {\n                status: this.calculateOverallStatus(services),\n                uptime: await this.calculateOverallUptime('24h'),\n                activeIncidents: this.incidents.size,\n                mttr: await this.calculateMTTR('30d'),\n                slaCompliance: await this.calculateSLACompliance('30d')\n            },\n            incidents: Array.from(this.incidents.values()).filter(i => i.status === 'open'),\n            metrics: {\n                totalRequests: await this.getTotalRequests('1h'),\n                errorRate: await this.getErrorRate('1h'),\n                avgResponseTime: await this.getAverageResponseTime('1h')\n            }\n        };\n    }\n    \n    estimateUserImpact(serviceName) {\n        // Estimate user impact based on service criticality\n        const impactMap = {\n            frontend: 10000,\n            api: 8000,\n            workers: 5000,\n            infrastructure: 3000\n        };\n        \n        return impactMap[serviceName] || 1000;\n    }\n    \n    // Additional utility methods would be implemented here...\n    // Including SLA calculation, reporting, cleanup, etc.\n}\n\nmodule.exports = EnterpriseMonitor;\n\n// Start the monitor if this file is run directly\nif (require.main === module) {\n    new EnterpriseMonitor();\n}