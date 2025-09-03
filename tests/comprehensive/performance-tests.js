"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const supertest_1 = __importDefault(require("supertest"));
const zh_CN_1 = require("@faker-js/faker/locale/zh_CN");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const perf_hooks_1 = require("perf_hooks");
const autocannon_1 = __importDefault(require("autocannon"));
class PerformanceMetrics {
    constructor() {
        this.metrics = [];
        this.memorySnapshots = [];
    }
    recordApiResponse(endpoint, responseTime, status, payloadSize) {
        this.metrics.push({
            timestamp: Date.now(),
            endpoint,
            responseTime,
            status,
            payloadSize: payloadSize || 0
        });
    }
    recordMemorySnapshot(label) {
        const memory = process.memoryUsage();
        this.memorySnapshots.push({
            timestamp: Date.now(),
            label,
            ...memory
        });
    }
    getAverageResponseTime(endpoint) {
        const filteredMetrics = endpoint
            ? this.metrics.filter(m => m.endpoint === endpoint)
            : this.metrics;
        if (filteredMetrics.length === 0)
            return 0;
        const totalTime = filteredMetrics.reduce((sum, m) => sum + m.responseTime, 0);
        return totalTime / filteredMetrics.length;
    }
    getPercentile(percentile, endpoint) {
        const filteredMetrics = endpoint
            ? this.metrics.filter(m => m.endpoint === endpoint)
            : this.metrics;
        if (filteredMetrics.length === 0)
            return 0;
        const sortedTimes = filteredMetrics
            .map(m => m.responseTime)
            .sort((a, b) => a - b);
        const index = Math.ceil((percentile / 100) * sortedTimes.length) - 1;
        return sortedTimes[index];
    }
    getThroughput(windowMs = 1000) {
        const now = Date.now();
        const windowStart = now - windowMs;
        const requestsInWindow = this.metrics.filter(m => m.timestamp >= windowStart);
        return requestsInWindow.length / (windowMs / 1000);
    }
    getErrorRate() {
        if (this.metrics.length === 0)
            return 0;
        const errorCount = this.metrics.filter(m => m.status >= 400).length;
        return (errorCount / this.metrics.length) * 100;
    }
    getMemoryGrowth() {
        if (this.memorySnapshots.length < 2)
            return 0;
        const first = this.memorySnapshots[0];
        const last = this.memorySnapshots[this.memorySnapshots.length - 1];
        return last.heapUsed - first.heapUsed;
    }
    generateReport() {
        return {
            totalRequests: this.metrics.length,
            averageResponseTime: this.getAverageResponseTime(),
            p50: this.getPercentile(50),
            p95: this.getPercentile(95),
            p99: this.getPercentile(99),
            throughput: this.getThroughput(),
            errorRate: this.getErrorRate(),
            memoryGrowth: this.getMemoryGrowth()
        };
    }
}
describe('8. 性能和负载测试', () => {
    let testUser;
    let authToken;
    let performanceMetrics;
    beforeAll(async () => {
        performanceMetrics = new PerformanceMetrics();
        performanceMetrics.recordMemorySnapshot('test_start');
        testUser = {
            id: zh_CN_1.faker.string.uuid(),
            email: zh_CN_1.faker.internet.email(),
            username: zh_CN_1.faker.internet.username(),
            role: 'user'
        };
        authToken = jsonwebtoken_1.default.sign({ userId: testUser.id, email: testUser.email, role: testUser.role }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
    });
    afterAll(async () => {
        performanceMetrics.recordMemorySnapshot('test_end');
        const report = performanceMetrics.generateReport();
        console.log('Performance Test Report:', JSON.stringify(report, null, 2));
    });
    describe('API响应时间测试', () => {
        it('健康检查接口应该在10ms内响应', async () => {
            const iterations = 10;
            const maxResponseTime = 10;
            for (let i = 0; i < iterations; i++) {
                const startTime = perf_hooks_1.performance.now();
                const response = await (0, supertest_1.default)(app)
                    .get('/api/v1/health');
                const responseTime = perf_hooks_1.performance.now() - startTime;
                expect(response.status).toBe(200);
                expect(responseTime).toBeLessThan(maxResponseTime);
                performanceMetrics.recordApiResponse('/health', responseTime, response.status);
            }
        });
        it('用户认证接口应该在100ms内响应', async () => {
            const maxResponseTime = 100;
            const startTime = perf_hooks_1.performance.now();
            const response = await (0, supertest_1.default)(app)
                .post('/api/v1/users/login')
                .send({
                email: zh_CN_1.faker.internet.email(),
                password: 'password123'
            });
            const responseTime = perf_hooks_1.performance.now() - startTime;
            expect(responseTime).toBeLessThan(maxResponseTime);
            performanceMetrics.recordApiResponse('/users/login', responseTime, response.status);
        });
        it('标注列表接口应该在200ms内响应', async () => {
            const maxResponseTime = 200;
            const startTime = perf_hooks_1.performance.now();
            const response = await (0, supertest_1.default)(app)
                .get('/api/v1/annotations/list?limit=20');
            const responseTime = perf_hooks_1.performance.now() - startTime;
            const payloadSize = JSON.stringify(response.body).length;
            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(maxResponseTime);
            performanceMetrics.recordApiResponse('/annotations/list', responseTime, response.status, payloadSize);
        });
        it('地理空间查询应该在300ms内响应', async () => {
            const maxResponseTime = 300;
            const startTime = perf_hooks_1.performance.now();
            const response = await (0, supertest_1.default)(app)
                .get('/api/v1/annotations/nearby')
                .query({
                latitude: 31.2304,
                longitude: 121.4737,
                radius: 1000
            });
            const responseTime = perf_hooks_1.performance.now() - startTime;
            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(maxResponseTime);
            performanceMetrics.recordApiResponse('/annotations/nearby', responseTime, response.status);
        });
        it('复杂查询接口应该在500ms内响应', async () => {
            const maxResponseTime = 500;
            const startTime = perf_hooks_1.performance.now();
            const response = await (0, supertest_1.default)(app)
                .get('/api/v1/annotations/list')
                .query({
                smellType: 'industrial',
                minIntensity: 3,
                maxIntensity: 5,
                startDate: '2023-01-01',
                endDate: '2023-12-31',
                sortBy: 'created_at',
                sortOrder: 'desc',
                limit: 50
            });
            const responseTime = perf_hooks_1.performance.now() - startTime;
            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(maxResponseTime);
            performanceMetrics.recordApiResponse('/annotations/complex_query', responseTime, response.status);
        });
    });
    describe('并发请求测试', () => {
        it('应该处理100个并发的健康检查请求', async () => {
            const concurrentRequests = 100;
            const maxResponseTime = 100;
            const promises = Array.from({ length: concurrentRequests }, () => {
                const startTime = perf_hooks_1.performance.now();
                return (0, supertest_1.default)(app)
                    .get('/api/v1/health')
                    .then(response => ({
                    response,
                    responseTime: perf_hooks_1.performance.now() - startTime
                }));
            });
            const results = await Promise.all(promises);
            results.forEach(result => {
                expect(result.response.status).toBe(200);
                expect(result.responseTime).toBeLessThan(maxResponseTime);
                performanceMetrics.recordApiResponse('/health_concurrent', result.responseTime, result.response.status);
            });
            const avgResponseTime = results.reduce((sum, r) => sum + r.responseTime, 0) / results.length;
            expect(avgResponseTime).toBeLessThan(maxResponseTime / 2);
        });
        it('应该处理50个并发的认证请求', async () => {
            const concurrentRequests = 50;
            const maxResponseTime = 200;
            const promises = Array.from({ length: concurrentRequests }, (_, i) => {
                const startTime = perf_hooks_1.performance.now();
                return (0, supertest_1.default)(app)
                    .post('/api/v1/users/login')
                    .send({
                    email: `test${i}@example.com`,
                    password: 'password123'
                })
                    .then(response => ({
                    response,
                    responseTime: perf_hooks_1.performance.now() - startTime
                }));
            });
            const results = await Promise.all(promises);
            results.forEach(result => {
                expect(result.responseTime).toBeLessThan(maxResponseTime);
                performanceMetrics.recordApiResponse('/users/login_concurrent', result.responseTime, result.response.status);
            });
            const errorRate = performanceMetrics.getErrorRate();
            expect(errorRate).toBeLessThan(5);
        });
        it('应该处理并发的标注创建请求', async () => {
            const concurrentRequests = 25;
            const maxResponseTime = 300;
            const promises = Array.from({ length: concurrentRequests }, (_, i) => {
                const startTime = perf_hooks_1.performance.now();
                return (0, supertest_1.default)(app)
                    .post('/api/v1/annotations')
                    .set('Authorization', `Bearer ${authToken}`)
                    .send({
                    latitude: 31.2304 + (i * 0.001),
                    longitude: 121.4737 + (i * 0.001),
                    smellType: 'industrial',
                    intensity: Math.floor(Math.random() * 5) + 1,
                    description: `并发测试标注 ${i}`
                })
                    .then(response => ({
                    response,
                    responseTime: perf_hooks_1.performance.now() - startTime
                }));
            });
            const results = await Promise.all(promises);
            const successfulCreations = results.filter(r => r.response.status === 201);
            expect(successfulCreations.length).toBeGreaterThan(concurrentRequests * 0.8);
            results.forEach(result => {
                if (result.response.status === 201) {
                    expect(result.responseTime).toBeLessThan(maxResponseTime);
                }
                performanceMetrics.recordApiResponse('/annotations_create_concurrent', result.responseTime, result.response.status);
            });
        });
        it('应该处理混合负载的并发请求', async () => {
            const readRequests = 40;
            const writeRequests = 10;
            const readPromises = Array.from({ length: readRequests }, () => {
                const startTime = perf_hooks_1.performance.now();
                return (0, supertest_1.default)(app)
                    .get('/api/v1/annotations/list?limit=10')
                    .then(response => ({
                    response,
                    responseTime: perf_hooks_1.performance.now() - startTime,
                    type: 'read'
                }));
            });
            const writePromises = Array.from({ length: writeRequests }, (_, i) => {
                const startTime = perf_hooks_1.performance.now();
                return (0, supertest_1.default)(app)
                    .post('/api/v1/annotations')
                    .set('Authorization', `Bearer ${authToken}`)
                    .send({
                    latitude: 31.2304 + (i * 0.001),
                    longitude: 121.4737 + (i * 0.001),
                    smellType: 'industrial',
                    intensity: 3,
                    description: `混合负载测试 ${i}`
                })
                    .then(response => ({
                    response,
                    responseTime: perf_hooks_1.performance.now() - startTime,
                    type: 'write'
                }));
            });
            const results = await Promise.all([...readPromises, ...writePromises]);
            const readResults = results.filter(r => r.type === 'read');
            const writeResults = results.filter(r => r.type === 'write');
            const avgReadTime = readResults.reduce((sum, r) => sum + r.responseTime, 0) / readResults.length;
            expect(avgReadTime).toBeLessThan(100);
            const avgWriteTime = writeResults.reduce((sum, r) => sum + r.responseTime, 0) / writeResults.length;
            expect(avgWriteTime).toBeLessThan(300);
        });
    });
    describe('数据库性能测试', () => {
        it('应该高效处理大量数据插入', async () => {
            const batchSize = 100;
            const maxTotalTime = 5000;
            const startTime = perf_hooks_1.performance.now();
            const promises = Array.from({ length: batchSize }, (_, i) => (0, supertest_1.default)(app)
                .post('/api/v1/annotations')
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                latitude: 31.2304 + (Math.random() * 0.1),
                longitude: 121.4737 + (Math.random() * 0.1),
                smellType: ['industrial', 'domestic', 'natural', 'chemical'][Math.floor(Math.random() * 4)],
                intensity: Math.floor(Math.random() * 5) + 1,
                description: `批量插入测试 ${i}`
            }));
            const results = await Promise.all(promises);
            const totalTime = perf_hooks_1.performance.now() - startTime;
            expect(totalTime).toBeLessThan(maxTotalTime);
            const successCount = results.filter(r => r.status === 201).length;
            expect(successCount).toBeGreaterThan(batchSize * 0.9);
            const avgRequestTime = totalTime / batchSize;
            expect(avgRequestTime).toBeLessThan(50);
        });
        it('应该高效处理地理空间查询', async () => {
            const queryCount = 50;
            const maxAvgTime = 100;
            const queries = Array.from({ length: queryCount }, (_, i) => ({
                latitude: 31.2304 + (Math.random() * 0.1),
                longitude: 121.4737 + (Math.random() * 0.1),
                radius: 500 + (Math.random() * 2000)
            }));
            const startTime = perf_hooks_1.performance.now();
            const promises = queries.map(query => (0, supertest_1.default)(app)
                .get('/api/v1/annotations/nearby')
                .query(query));
            const results = await Promise.all(promises);
            const totalTime = perf_hooks_1.performance.now() - startTime;
            const avgTime = totalTime / queryCount;
            expect(avgTime).toBeLessThan(maxAvgTime);
            results.forEach(response => {
                expect(response.status).toBe(200);
                expect(Array.isArray(response.body.data.annotations)).toBe(true);
            });
        });
        it('应该高效处理复杂的连接查询', async () => {
            const maxResponseTime = 200;
            const startTime = perf_hooks_1.performance.now();
            const response = await (0, supertest_1.default)(app)
                .get('/api/v1/users/stats')
                .query({
                includeAnnotations: true,
                includeRewards: true,
                dateRange: '30d'
            })
                .set('Authorization', `Bearer ${authToken}`);
            const responseTime = perf_hooks_1.performance.now() - startTime;
            expect(response.status).toBe(200);
            expect(responseTime).toBeLessThan(maxResponseTime);
            performanceMetrics.recordApiResponse('/users/stats_complex', responseTime, response.status);
        });
        it('应该处理数据库连接池压力', async () => {
            const concurrentConnections = 20;
            const queriesPerConnection = 5;
            const promises = Array.from({ length: concurrentConnections }, async () => {
                const queries = Array.from({ length: queriesPerConnection }, () => (0, supertest_1.default)(app)
                    .get('/api/v1/annotations/list?limit=5'));
                return Promise.all(queries);
            });
            const results = await Promise.all(promises);
            results.forEach(connectionResults => {
                connectionResults.forEach(response => {
                    expect(response.status).toBe(200);
                });
            });
        });
    });
    describe('内存和资源使用测试', () => {
        it('应该不产生内存泄漏', async () => {
            const initialMemory = process.memoryUsage();
            performanceMetrics.recordMemorySnapshot('memory_leak_test_start');
            const requestCount = 500;
            const promises = Array.from({ length: requestCount }, () => (0, supertest_1.default)(app)
                .get('/api/v1/annotations/list?limit=10'));
            await Promise.all(promises);
            if (global.gc) {
                global.gc();
            }
            await new Promise(resolve => setTimeout(resolve, 1000));
            const finalMemory = process.memoryUsage();
            performanceMetrics.recordMemorySnapshot('memory_leak_test_end');
            const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
            const memoryIncreasePerRequest = memoryIncrease / requestCount;
            expect(memoryIncreasePerRequest).toBeLessThan(1024);
            expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
        }, 30000);
        it('应该高效管理CPU使用', async () => {
            const cpuIntensiveOperations = 100;
            const startTime = process.hrtime.bigint();
            const startCpuUsage = process.cpuUsage();
            const promises = Array.from({ length: cpuIntensiveOperations }, () => (0, supertest_1.default)(app)
                .get('/api/v1/annotations/nearby')
                .query({
                latitude: 31.2304,
                longitude: 121.4737,
                radius: 2000
            }));
            await Promise.all(promises);
            const endTime = process.hrtime.bigint();
            const endCpuUsage = process.cpuUsage(startCpuUsage);
            const executionTime = Number(endTime - startTime) / 1000000;
            const cpuTime = (endCpuUsage.user + endCpuUsage.system) / 1000;
            const cpuEfficiency = cpuTime / executionTime;
            expect(cpuEfficiency).toBeLessThan(0.8);
        });
        it('应该合理使用文件描述符', async () => {
            const connections = 50;
            const promises = Array.from({ length: connections }, () => (0, supertest_1.default)(app)
                .get('/api/v1/annotations/list')
                .timeout(30000));
            const results = await Promise.all(promises);
            results.forEach(response => {
                expect(response.status).toBe(200);
            });
            await new Promise(resolve => setTimeout(resolve, 1000));
        });
    });
    describe('负载测试', () => {
        it('应该承受持续的中等负载', async () => {
            const duration = 30000;
            const requestsPerSecond = 10;
            const totalRequests = (duration / 1000) * requestsPerSecond;
            const startTime = Date.now();
            let completedRequests = 0;
            let errors = 0;
            const sendRequest = async () => {
                try {
                    const response = await (0, supertest_1.default)(app)
                        .get('/api/v1/annotations/list?limit=10');
                    if (response.status === 200) {
                        completedRequests++;
                    }
                    else {
                        errors++;
                    }
                }
                catch (error) {
                    errors++;
                }
            };
            const interval = setInterval(() => {
                if (Date.now() - startTime < duration) {
                    for (let i = 0; i < requestsPerSecond; i++) {
                        sendRequest();
                    }
                }
                else {
                    clearInterval(interval);
                }
            }, 1000);
            await new Promise(resolve => {
                setTimeout(resolve, duration + 5000);
            });
            const successRate = completedRequests / (completedRequests + errors);
            expect(successRate).toBeGreaterThan(0.95);
            expect(completedRequests).toBeGreaterThan(totalRequests * 0.8);
        }, 40000);
        it('应该处理突发流量', async () => {
            const burstSize = 100;
            const maxResponseTime = 1000;
            const promises = Array.from({ length: burstSize }, (_, i) => {
                const startTime = perf_hooks_1.performance.now();
                return (0, supertest_1.default)(app)
                    .get('/api/v1/annotations/list?limit=5')
                    .then(response => ({
                    response,
                    responseTime: perf_hooks_1.performance.now() - startTime,
                    requestId: i
                }));
            });
            const results = await Promise.all(promises);
            const responseTimes = results.map(r => r.responseTime);
            const avgResponseTime = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;
            const maxActualResponseTime = Math.max(...responseTimes);
            const successCount = results.filter(r => r.response.status === 200).length;
            expect(avgResponseTime).toBeLessThan(maxResponseTime / 2);
            expect(maxActualResponseTime).toBeLessThan(maxResponseTime);
            expect(successCount).toBeGreaterThan(burstSize * 0.9);
        });
        it('应该正确处理资源耗尽情况', async () => {
            const overloadRequests = 200;
            const promises = Array.from({ length: overloadRequests }, () => (0, supertest_1.default)(app)
                .post('/api/v1/annotations')
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                latitude: 31.2304,
                longitude: 121.4737,
                smellType: 'industrial',
                intensity: 3,
                description: '资源耗尽测试'
            }));
            const results = await Promise.all(promises);
            const successCount = results.filter(r => r.status === 201).length;
            const rateLimitCount = results.filter(r => r.status === 429).length;
            const serverErrorCount = results.filter(r => r.status >= 500).length;
            expect(serverErrorCount).toBeLessThan(overloadRequests * 0.1);
            expect(successCount + rateLimitCount).toBeGreaterThan(overloadRequests * 0.8);
        });
    });
    describe('缓存性能测试', () => {
        it('应该有效利用缓存提升性能', async () => {
            const endpoint = '/api/v1/annotations/list?limit=20&smellType=industrial';
            const startTime1 = perf_hooks_1.performance.now();
            const response1 = await (0, supertest_1.default)(app).get(endpoint);
            const responseTime1 = perf_hooks_1.performance.now() - startTime1;
            expect(response1.status).toBe(200);
            const startTime2 = perf_hooks_1.performance.now();
            const response2 = await (0, supertest_1.default)(app).get(endpoint);
            const responseTime2 = perf_hooks_1.performance.now() - startTime2;
            expect(response2.status).toBe(200);
            expect(responseTime2).toBeLessThan(responseTime1 * 0.8);
            expect(response2.body).toEqual(response1.body);
        });
        it('应该正确处理缓存失效', async () => {
            const endpoint = '/api/v1/annotations/list?limit=10';
            const response1 = await (0, supertest_1.default)(app).get(endpoint);
            expect(response1.status).toBe(200);
            const createResponse = await (0, supertest_1.default)(app)
                .post('/api/v1/annotations')
                .set('Authorization', `Bearer ${authToken}`)
                .send({
                latitude: 31.2304,
                longitude: 121.4737,
                smellType: 'industrial',
                intensity: 3,
                description: '缓存失效测试'
            });
            expect(createResponse.status).toBe(201);
            const response2 = await (0, supertest_1.default)(app).get(endpoint);
            expect(response2.status).toBe(200);
            const annotationCount1 = response1.body.data.annotations.length;
            const annotationCount2 = response2.body.data.annotations.length;
            expect(response2.body.data.totalCount).toBeGreaterThanOrEqual(response1.body.data.totalCount);
        });
    });
    describe('AutoCannon负载测试', () => {
        it('应该通过AutoCannon基准测试', async () => {
            const port = process.env.PORT || 3000;
            const result = await (0, autocannon_1.default)({
                url: `http://localhost:${port}`,
                connections: 10,
                duration: 10,
                requests: [
                    {
                        method: 'GET',
                        path: '/api/v1/health'
                    }
                ]
            });
            expect(result.errors).toBe(0);
            expect(result['2xx']).toBeGreaterThan(0);
            expect(result.latency.average).toBeLessThan(100);
            expect(result.requests.average).toBeGreaterThan(50);
        }, 15000);
        it('应该在混合负载下保持性能', async () => {
            const port = process.env.PORT || 3000;
            const result = await (0, autocannon_1.default)({
                url: `http://localhost:${port}`,
                connections: 20,
                duration: 15,
                requests: [
                    {
                        method: 'GET',
                        path: '/api/v1/health',
                        weight: 30
                    },
                    {
                        method: 'GET',
                        path: '/api/v1/annotations/list?limit=10',
                        weight: 50
                    },
                    {
                        method: 'GET',
                        path: '/api/v1/annotations/nearby?latitude=31.2304&longitude=121.4737&radius=1000',
                        weight: 20
                    }
                ]
            });
            expect(result.errors).toBeLessThan(result.requests.total * 0.01);
            expect(result['2xx']).toBeGreaterThan(result.requests.total * 0.95);
            expect(result.latency.p99).toBeLessThan(1000);
        }, 20000);
    });
});
//# sourceMappingURL=performance-tests.js.map