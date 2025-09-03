/**
 * SmellPin Performance Monitoring Service
 * Monitors API response times and ensures <200ms performance SLA
 */

const express = require('express');
const prometheus = require('prom-client');
const axios = require('axios');
const { Client } = require('pg');
const Redis = require('ioredis');

class PerformanceMonitor {
    constructor() {
        this.app = express();
        this.port = process.env.PERF_MONITOR_PORT || 9202;
        
        // Performance SLA targets
        this.performanceTargets = {
            apiResponseTime: 200, // ms
            databaseQueryTime: 100, // ms
            redisOperationTime: 10, // ms
            frontendLoadTime: 3000, // ms
            p95ResponseTime: 200, // ms
            p99ResponseTime: 500, // ms
        };

        // Critical endpoints to monitor
        this.criticalEndpoints = [
            { path: '/api/annotations', method: 'GET', target: 150 },
            { path: '/api/annotations', method: 'POST', target: 300 },
            { path: '/api/users/profile', method: 'GET', target: 100 },
            { path: '/api/payments/webhook', method: 'POST', target: 200 },
            { path: '/api/lbs/rewards', method: 'POST', target: 200 },
            { path: '/api/health', method: 'GET', target: 50 }
        ];

        this.initializeMetrics();
        this.initializeConnections();
        this.setupMiddleware();
        this.setupRoutes();
        this.startMonitoring();
    }

    initializeMetrics() {
        prometheus.register.setDefaultLabels({
            app: 'smellpin-performance-monitor'
        });
        prometheus.collectDefaultMetrics();

        this.metrics = {
            // API Performance Metrics
            httpRequestDuration: new prometheus.Histogram({
                name: 'smellpin_http_request_duration_seconds',
                help: 'HTTP request duration in seconds',
                labelNames: ['method', 'route', 'status_code', 'endpoint_type'],
                buckets: [0.01, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 1, 2, 5]
            }),

            httpRequestsTotal: new prometheus.Counter({
                name: 'smellpin_http_requests_total',
                help: 'Total HTTP requests',
                labelNames: ['method', 'route', 'status_code']
            }),

            slowQueriesTotal: new prometheus.Counter({
                name: 'smellpin_slow_queries_total',
                help: 'Total number of slow database queries',
                labelNames: ['query_type', 'table_name']
            }),

            // Database Performance
            databaseQueryDuration: new prometheus.Histogram({
                name: 'smellpin_database_query_duration_seconds',
                help: 'Database query execution time',
                labelNames: ['query_type', 'table_name'],
                buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.2, 0.5, 1, 2]
            }),

            databaseConnections: new prometheus.Gauge({
                name: 'smellpin_database_connections_active',
                help: 'Number of active database connections'
            }),

            // Redis Performance
            redisOperationDuration: new prometheus.Histogram({
                name: 'smellpin_redis_operation_duration_seconds',
                help: 'Redis operation execution time',
                labelNames: ['operation', 'key_pattern'],
                buckets: [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1]
            }),

            redisConnections: new prometheus.Gauge({
                name: 'smellpin_redis_connections_active',
                help: 'Number of active Redis connections'
            }),

            // Application Performance
            memoryUsage: new prometheus.Gauge({
                name: 'smellpin_memory_usage_bytes',
                help: 'Application memory usage in bytes',
                labelNames: ['type']
            }),

            cpuUsage: new prometheus.Gauge({
                name: 'smellpin_cpu_usage_percent',
                help: 'CPU usage percentage'
            }),

            // SLA Compliance
            slaCompliance: new prometheus.Gauge({
                name: 'smellpin_sla_compliance_percent',
                help: 'SLA compliance percentage',
                labelNames: ['metric_type', 'endpoint']
            }),

            performanceViolations: new prometheus.Counter({
                name: 'smellpin_performance_violations_total',
                help: 'Total performance SLA violations',
                labelNames: ['violation_type', 'severity', 'endpoint']
            }),

            // Business Metrics affecting Performance
            concurrentUsers: new prometheus.Gauge({
                name: 'smellpin_concurrent_users',
                help: 'Number of concurrent active users'
            }),

            requestRate: new prometheus.Gauge({
                name: 'smellpin_request_rate_per_second',
                help: 'Current request rate per second'
            })
        };
    }

    async initializeConnections() {
        try {
            this.pg = new Client({
                connectionString: process.env.DATABASE_URL,
                ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
            });
            await this.pg.connect();

            this.redis = new Redis(process.env.REDIS_URL);
            
            console.log('Performance Monitor connections initialized');
        } catch (error) {
            console.error('Failed to initialize connections:', error);
            process.exit(1);
        }
    }

    setupMiddleware() {
        this.app.use(express.json());
        this.app.use(this.performanceMiddleware.bind(this));
    }

    performanceMiddleware(req, res, next) {
        const start = Date.now();
        const startUsage = process.cpuUsage();

        res.on('finish', () => {
            const duration = (Date.now() - start) / 1000;
            const cpuUsage = process.cpuUsage(startUsage);
            
            // Record metrics
            this.metrics.httpRequestDuration
                .labels(req.method, req.route?.path || req.path, res.statusCode, 'api')
                .observe(duration);

            this.metrics.httpRequestsTotal
                .labels(req.method, req.route?.path || req.path, res.statusCode)
                .inc();

            // Check for performance violations
            this.checkPerformanceViolation(req, duration * 1000);
        });

        next();
    }

    setupRoutes() {
        this.app.get('/metrics', async (req, res) => {
            res.set('Content-Type', prometheus.register.contentType);
            const metrics = await prometheus.register.metrics();
            res.send(metrics);
        });

        this.app.get('/performance/status', async (req, res) => {
            const status = await this.getPerformanceStatus();
            res.json(status);
        });

        this.app.get('/performance/report', async (req, res) => {
            const { period = '1h' } = req.query;
            const report = await this.generatePerformanceReport(period);
            res.json(report);
        });

        this.app.get('/performance/slow-queries', async (req, res) => {
            const slowQueries = await this.getSlowQueries();
            res.json(slowQueries);
        });

        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime()
            });
        });
    }

    async startMonitoring() {
        console.log(`Starting Performance Monitor on port ${this.port}`);
        
        this.app.listen(this.port, () => {
            console.log(`Performance Monitor listening on port ${this.port}`);
        });

        // Start monitoring processes
        this.monitorSystemMetrics();
        this.monitorDatabasePerformance();
        this.monitorRedisPerformance();
        this.calculateSLACompliance();
        this.proactivePerformanceCheck();
    }

    checkPerformanceViolation(req, responseTimeMs) {
        const endpoint = this.criticalEndpoints.find(e => 
            e.method === req.method && 
            (req.route?.path || req.path).includes(e.path)
        );

        if (endpoint && responseTimeMs > endpoint.target) {
            const severity = responseTimeMs > (endpoint.target * 2) ? 'critical' : 'warning';
            
            this.metrics.performanceViolations
                .labels('response_time', severity, endpoint.path)
                .inc();

            console.warn(`Performance violation: ${req.method} ${endpoint.path} took ${responseTimeMs}ms (target: ${endpoint.target}ms)`);
        }
    }

    async monitorSystemMetrics() {
        setInterval(async () => {
            try {
                const memUsage = process.memoryUsage();
                
                this.metrics.memoryUsage.labels('rss').set(memUsage.rss);
                this.metrics.memoryUsage.labels('heapUsed').set(memUsage.heapUsed);
                this.metrics.memoryUsage.labels('heapTotal').set(memUsage.heapTotal);
                this.metrics.memoryUsage.labels('external').set(memUsage.external);

                // Monitor database connections
                const dbResult = await this.pg.query('SELECT count(*) as active_connections FROM pg_stat_activity');
                this.metrics.databaseConnections.set(parseInt(dbResult.rows[0].active_connections));

                // Monitor Redis connections
                const redisInfo = await this.redis.info('clients');
                const connectedClients = redisInfo.match(/connected_clients:(\d+)/);
                if (connectedClients) {
                    this.metrics.redisConnections.set(parseInt(connectedClients[1]));
                }

            } catch (error) {
                console.error('Error monitoring system metrics:', error);
            }
        }, 30000); // Every 30 seconds
    }

    async monitorDatabasePerformance() {
        setInterval(async () => {
            try {
                // Monitor slow queries
                const slowQueries = await this.pg.query(`
                    SELECT 
                        query,
                        calls,
                        total_time,
                        mean_time,
                        rows,
                        100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
                    FROM pg_stat_statements
                    WHERE mean_time > 100
                    ORDER BY total_time DESC
                    LIMIT 10
                `);

                for (const query of slowQueries.rows) {
                    if (query.mean_time > 100) { // > 100ms
                        this.metrics.slowQueriesTotal
                            .labels('slow', 'unknown')
                            .inc();
                    }
                }

                // Monitor database performance metrics
                const dbStats = await this.pg.query(`
                    SELECT 
                        schemaname,
                        tablename,
                        seq_scan,
                        seq_tup_read,
                        idx_scan,
                        idx_tup_fetch,
                        n_tup_ins,
                        n_tup_upd,
                        n_tup_del
                    FROM pg_stat_user_tables
                    WHERE schemaname = 'public'
                `);

                // Look for tables with high sequential scans (performance issue)
                for (const table of dbStats.rows) {
                    if (table.seq_scan > table.idx_scan && table.seq_tup_read > 1000) {
                        console.warn(`Table ${table.tablename} has high sequential scan ratio`);
                    }
                }

            } catch (error) {
                console.error('Error monitoring database performance:', error);
            }
        }, 60000); // Every minute
    }

    async monitorRedisPerformance() {
        setInterval(async () => {
            try {
                const start = Date.now();
                
                // Test Redis performance with a simple operation
                await this.redis.ping();
                const redisPingTime = (Date.now() - start) / 1000;

                this.metrics.redisOperationDuration
                    .labels('ping', 'health_check')
                    .observe(redisPingTime);

                // Monitor Redis memory usage
                const redisInfo = await this.redis.info('memory');
                const usedMemory = redisInfo.match(/used_memory:(\d+)/);
                if (usedMemory) {
                    this.metrics.memoryUsage
                        .labels('redis')
                        .set(parseInt(usedMemory[1]));
                }

                // Check for performance issues
                if (redisPingTime > 0.01) { // > 10ms is slow for Redis
                    console.warn(`Redis performance issue: ping took ${redisPingTime * 1000}ms`);
                }

            } catch (error) {
                console.error('Error monitoring Redis performance:', error);
            }
        }, 30000); // Every 30 seconds
    }

    async calculateSLACompliance() {
        setInterval(async () => {
            try {
                const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);

                // Calculate API response time compliance
                for (const endpoint of this.criticalEndpoints) {
                    const compliance = await this.calculateEndpointCompliance(endpoint, oneHourAgo);
                    
                    this.metrics.slaCompliance
                        .labels('response_time', endpoint.path)
                        .set(compliance);
                }

            } catch (error) {
                console.error('Error calculating SLA compliance:', error);
            }
        }, 300000); // Every 5 minutes
    }

    async calculateEndpointCompliance(endpoint, since) {
        try {
            const result = await this.pg.query(`
                SELECT 
                    COUNT(*) as total_requests,
                    COUNT(*) FILTER (WHERE response_time_ms <= $1) as compliant_requests
                FROM api_performance_data
                WHERE endpoint = $2 AND method = $3 AND timestamp >= $4
            `, [endpoint.target, endpoint.path, endpoint.method, since]);

            const { total_requests, compliant_requests } = result.rows[0];
            return total_requests > 0 ? (compliant_requests / total_requests) * 100 : 100;
        } catch (error) {
            console.error('Error calculating endpoint compliance:', error);
            return 0;
        }
    }

    async proactivePerformanceCheck() {
        setInterval(async () => {
            try {
                // Test critical API endpoints
                for (const endpoint of this.criticalEndpoints) {
                    await this.testEndpointPerformance(endpoint);
                }

                // Check system resource usage
                await this.checkResourceUsage();

            } catch (error) {
                console.error('Error in proactive performance check:', error);
            }
        }, 120000); // Every 2 minutes
    }

    async testEndpointPerformance(endpoint) {
        const startTime = Date.now();
        
        try {
            const baseURL = process.env.API_BASE_URL || 'http://localhost:3000';
            const response = await axios({
                method: endpoint.method,
                url: `${baseURL}${endpoint.path}`,
                timeout: 5000,
                headers: {
                    'User-Agent': 'SmellPin-Performance-Monitor'
                }
            });

            const responseTime = Date.now() - startTime;
            
            // Store performance data
            await this.storePerformanceData({
                endpoint: endpoint.path,
                method: endpoint.method,
                responseTime,
                statusCode: response.status,
                timestamp: new Date()
            });

            // Check for violations
            if (responseTime > endpoint.target) {
                const severity = responseTime > (endpoint.target * 2) ? 'critical' : 'warning';
                
                this.metrics.performanceViolations
                    .labels('response_time', severity, endpoint.path)
                    .inc();

                await this.handlePerformanceViolation(endpoint, responseTime, severity);
            }

        } catch (error) {
            const responseTime = Date.now() - startTime;
            
            await this.storePerformanceData({
                endpoint: endpoint.path,
                method: endpoint.method,
                responseTime,
                statusCode: 0,
                timestamp: new Date(),
                error: error.message
            });
        }
    }

    async storePerformanceData(data) {
        try {
            await this.pg.query(`
                INSERT INTO api_performance_data 
                (endpoint, method, response_time_ms, status_code, timestamp, error_message)
                VALUES ($1, $2, $3, $4, $5, $6)
            `, [
                data.endpoint,
                data.method,
                data.responseTime,
                data.statusCode,
                data.timestamp,
                data.error || null
            ]);
        } catch (error) {
            console.error('Failed to store performance data:', error);
        }
    }

    async handlePerformanceViolation(endpoint, responseTime, severity) {
        console.warn(`Performance violation: ${endpoint.method} ${endpoint.path} - ${responseTime}ms (target: ${endpoint.target}ms, severity: ${severity})`);

        // If critical, could trigger alerts here
        if (severity === 'critical') {
            // Integration with alerting system
            // await this.sendPerformanceAlert(endpoint, responseTime);
        }
    }

    async checkResourceUsage() {
        const memUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();

        // Check if memory usage is high
        const memoryUsageMB = memUsage.heapUsed / 1024 / 1024;
        if (memoryUsageMB > 500) { // > 500MB
            console.warn(`High memory usage: ${memoryUsageMB.toFixed(2)}MB`);
        }

        // Monitor garbage collection impact
        const gcTime = process.hrtime();
        global.gc && global.gc();
        const gcDuration = process.hrtime(gcTime);
        const gcMs = gcDuration[0] * 1000 + gcDuration[1] / 1000000;
        
        if (gcMs > 10) { // > 10ms GC pause
            console.warn(`Long GC pause: ${gcMs.toFixed(2)}ms`);
        }
    }

    async getPerformanceStatus() {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        
        const status = {
            timestamp: new Date().toISOString(),
            slaTargets: this.performanceTargets,
            endpoints: {}
        };

        for (const endpoint of this.criticalEndpoints) {
            const stats = await this.pg.query(`
                SELECT 
                    COUNT(*) as total_requests,
                    AVG(response_time_ms) as avg_response_time,
                    percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_response_time,
                    percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time_ms) as p99_response_time,
                    COUNT(*) FILTER (WHERE response_time_ms <= $1) as compliant_requests
                FROM api_performance_data
                WHERE endpoint = $2 AND method = $3 AND timestamp >= $4
            `, [endpoint.target, endpoint.path, endpoint.method, oneHourAgo]);

            const data = stats.rows[0];
            const compliance = data.total_requests > 0 ? 
                (data.compliant_requests / data.total_requests) * 100 : 100;

            status.endpoints[`${endpoint.method} ${endpoint.path}`] = {
                target: endpoint.target,
                totalRequests: parseInt(data.total_requests),
                avgResponseTime: parseFloat(data.avg_response_time || 0),
                p95ResponseTime: parseFloat(data.p95_response_time || 0),
                p99ResponseTime: parseFloat(data.p99_response_time || 0),
                compliance: parseFloat(compliance.toFixed(2)),
                slaCompliant: compliance >= 95 // 95% of requests should meet target
            };
        }

        return status;
    }

    async generatePerformanceReport(period) {
        const periodMs = this.parsePeriod(period);
        const startDate = new Date(Date.now() - periodMs);

        const report = {
            period,
            generatedAt: new Date().toISOString(),
            summary: {},
            endpoints: {},
            slowQueries: await this.getSlowQueries(),
            recommendations: []
        };

        // Calculate overall metrics
        const overallStats = await this.pg.query(`
            SELECT 
                COUNT(*) as total_requests,
                AVG(response_time_ms) as avg_response_time,
                percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time_ms) as p95_response_time,
                percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time_ms) as p99_response_time,
                COUNT(*) FILTER (WHERE response_time_ms <= 200) as fast_requests
            FROM api_performance_data
            WHERE timestamp >= $1
        `, [startDate]);

        const overall = overallStats.rows[0];
        report.summary = {
            totalRequests: parseInt(overall.total_requests),
            avgResponseTime: parseFloat(overall.avg_response_time || 0),
            p95ResponseTime: parseFloat(overall.p95_response_time || 0),
            p99ResponseTime: parseFloat(overall.p99_response_time || 0),
            fastRequestsPercent: overall.total_requests > 0 ? 
                (overall.fast_requests / overall.total_requests) * 100 : 100
        };

        // Generate recommendations
        if (report.summary.p95ResponseTime > 200) {
            report.recommendations.push('P95 response time exceeds 200ms target - consider optimization');
        }
        if (report.summary.fastRequestsPercent < 95) {
            report.recommendations.push('Less than 95% of requests meet performance target');
        }

        return report;
    }

    async getSlowQueries() {
        try {
            const result = await this.pg.query(`
                SELECT 
                    query,
                    calls,
                    total_time,
                    mean_time,
                    rows,
                    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
                FROM pg_stat_statements
                WHERE mean_time > 100
                ORDER BY total_time DESC
                LIMIT 20
            `);

            return result.rows.map(row => ({
                query: row.query.substring(0, 200) + '...', // Truncate for readability
                calls: parseInt(row.calls),
                totalTime: parseFloat(row.total_time),
                meanTime: parseFloat(row.mean_time),
                rows: parseInt(row.rows),
                hitPercent: parseFloat(row.hit_percent || 0)
            }));
        } catch (error) {
            console.error('Error getting slow queries:', error);
            return [];
        }
    }

    parsePeriod(period) {
        const value = parseInt(period.slice(0, -1));
        const unit = period.slice(-1);
        
        switch (unit) {
            case 'h': return value * 60 * 60 * 1000;
            case 'd': return value * 24 * 60 * 60 * 1000;
            case 'w': return value * 7 * 24 * 60 * 60 * 1000;
            default: return 60 * 60 * 1000; // Default to 1 hour
        }
    }
}

// Initialize database schema
async function initializePerformanceDatabase() {
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    });

    try {
        await client.connect();

        await client.query(`
            CREATE TABLE IF NOT EXISTS api_performance_data (
                id SERIAL PRIMARY KEY,
                endpoint VARCHAR(200) NOT NULL,
                method VARCHAR(10) NOT NULL,
                response_time_ms NUMERIC(10,2) NOT NULL,
                status_code INTEGER NOT NULL,
                timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                error_message TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_api_performance_timestamp 
            ON api_performance_data (endpoint, method, timestamp DESC);
        `);

        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_api_performance_response_time 
            ON api_performance_data (response_time_ms, timestamp DESC);
        `);

        // Enable pg_stat_statements for query monitoring
        await client.query(`
            CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
        `);

        console.log('Performance monitoring database schema initialized');
    } catch (error) {
        console.error('Failed to initialize performance database:', error);
        process.exit(1);
    } finally {
        await client.end();
    }
}

async function main() {
    await initializePerformanceDatabase();
    new PerformanceMonitor();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = PerformanceMonitor;