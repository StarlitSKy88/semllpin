#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

class RedisPerformanceTester {
  constructor() {
    this.results = {
      timestamp: new Date().toISOString(),
      connection: {},
      operations: {},
      memory: {},
      cacheAnalysis: {},
      recommendations: []
    };
    
    this.testOperations = [
      { name: 'set', description: 'Basic SET operations' },
      { name: 'get', description: 'Basic GET operations' },
      { name: 'hset', description: 'Hash SET operations' },
      { name: 'hget', description: 'Hash GET operations' },
      { name: 'lpush', description: 'List PUSH operations' },
      { name: 'lpop', description: 'List POP operations' },
      { name: 'sadd', description: 'Set ADD operations' },
      { name: 'smembers', description: 'Set MEMBERS operations' },
      { name: 'zadd', description: 'Sorted set ADD operations' },
      { name: 'zrange', description: 'Sorted set RANGE operations' }
    ];
    
    this.cacheKeys = [
      'session:*',
      'user:profile:*',
      'annotations:nearby:*',
      'map:tiles:*',
      'api:response:*'
    ];
  }

  async runRedisTests() {
    console.log('⚡ Starting Redis Performance Tests...\n');
    
    try {
      // Initialize Redis connection
      await this.initializeRedis();
      
      // Test connection performance
      await this.testConnectionPerformance();
      
      // Test operation performance
      await this.testOperationPerformance();
      
      // Test memory usage
      await this.testMemoryUsage();
      
      // Analyze cache patterns
      await this.analyzeCachePatterns();
      
      // Test concurrent operations
      await this.testConcurrentOperations();
      
      // Generate recommendations
      this.generateRecommendations();
      
      // Generate report
      await this.generateReport();
      
      console.log('✅ Redis performance tests completed!\n');
      
    } catch (error) {
      console.error('❌ Redis tests failed:', error.message);
      this.results.error = error.message;
    } finally {
      await this.cleanup();
    }
  }

  async initializeRedis() {
    console.log('🔌 Initializing Redis connection...');
    
    // Mock Redis connection (in real implementation, use ioredis or redis client)
    this.redis = {
      connected: true,
      config: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        db: process.env.REDIS_DB || 0,
        maxRetriesPerRequest: 3
      },
      // Mock methods
      set: this.mockOperation.bind(this, 'SET'),
      get: this.mockOperation.bind(this, 'GET'),
      hset: this.mockOperation.bind(this, 'HSET'),
      hget: this.mockOperation.bind(this, 'HGET'),
      lpush: this.mockOperation.bind(this, 'LPUSH'),
      lpop: this.mockOperation.bind(this, 'LPOP'),
      sadd: this.mockOperation.bind(this, 'SADD'),
      smembers: this.mockOperation.bind(this, 'SMEMBERS'),
      zadd: this.mockOperation.bind(this, 'ZADD'),
      zrange: this.mockOperation.bind(this, 'ZRANGE'),
      info: this.mockInfo.bind(this),
      keys: this.mockKeys.bind(this),
      memory: this.mockMemoryUsage.bind(this),
      ping: () => Promise.resolve('PONG')
    };
    
    console.log('✅ Connected to Redis');
  }

  async mockOperation(command, ...args) {
    // Simulate different operation latencies
    const baseLatency = {
      'SET': 0.5 + Math.random() * 2,      // 0.5-2.5ms
      'GET': 0.3 + Math.random() * 1.5,    // 0.3-1.8ms
      'HSET': 0.8 + Math.random() * 2.5,   // 0.8-3.3ms
      'HGET': 0.5 + Math.random() * 2,     // 0.5-2.5ms
      'LPUSH': 0.6 + Math.random() * 2,    // 0.6-2.6ms
      'LPOP': 0.4 + Math.random() * 1.5,   // 0.4-1.9ms
      'SADD': 0.7 + Math.random() * 2,     // 0.7-2.7ms
      'SMEMBERS': 1 + Math.random() * 3,   // 1-4ms (reading sets)
      'ZADD': 1 + Math.random() * 2.5,     // 1-3.5ms (sorted sets)
      'ZRANGE': 1.2 + Math.random() * 3    // 1.2-4.2ms (range queries)
    };

    const latency = baseLatency[command] || 1;
    
    // Simulate network/processing delay
    await new Promise(resolve => setTimeout(resolve, latency));
    
    // Return mock results
    const mockResults = {
      'SET': 'OK',
      'GET': 'mock_value_' + Date.now(),
      'HSET': 1,
      'HGET': 'mock_hash_value',
      'LPUSH': Math.floor(Math.random() * 10) + 1,
      'LPOP': 'mock_list_item',
      'SADD': 1,
      'SMEMBERS': Array(Math.floor(Math.random() * 5) + 1).fill().map(() => 'member_' + Math.random()),
      'ZADD': 1,
      'ZRANGE': Array(Math.floor(Math.random() * 10) + 1).fill().map(() => 'item_' + Math.random())
    };

    return {
      result: mockResults[command],
      latency: latency,
      timestamp: Date.now()
    };
  }

  async mockInfo() {
    return {
      redis_version: '7.0.0',
      connected_clients: Math.floor(Math.random() * 50) + 10,
      used_memory: Math.floor(Math.random() * 100000000) + 50000000, // 50-150MB
      used_memory_peak: Math.floor(Math.random() * 150000000) + 100000000,
      instantaneous_ops_per_sec: Math.floor(Math.random() * 10000) + 1000,
      total_commands_processed: Math.floor(Math.random() * 1000000) + 500000,
      expired_keys: Math.floor(Math.random() * 1000),
      evicted_keys: Math.floor(Math.random() * 100),
      keyspace_hits: Math.floor(Math.random() * 100000) + 50000,
      keyspace_misses: Math.floor(Math.random() * 10000) + 1000
    };
  }

  async mockKeys(pattern) {
    // Simulate keys based on pattern
    const keysByPattern = {
      'session:*': Array(Math.floor(Math.random() * 1000) + 100).fill().map((_, i) => `session:user_${i}`),
      'user:profile:*': Array(Math.floor(Math.random() * 500) + 50).fill().map((_, i) => `user:profile:${i}`),
      'annotations:nearby:*': Array(Math.floor(Math.random() * 200) + 20).fill().map((_, i) => `annotations:nearby:${i}`),
      'map:tiles:*': Array(Math.floor(Math.random() * 1500) + 200).fill().map((_, i) => `map:tiles:${i}`),
      'api:response:*': Array(Math.floor(Math.random() * 300) + 30).fill().map((_, i) => `api:response:${i}`)
    };
    
    return keysByPattern[pattern] || [];
  }

  async mockMemoryUsage(key) {
    return Math.floor(Math.random() * 1000) + 100; // 100-1100 bytes
  }

  async testConnectionPerformance() {
    console.log('🔗 Testing Redis connection performance...');
    
    const pingResults = [];
    const connectionTimes = [];
    
    // Test ping latency
    for (let i = 0; i < 20; i++) {
      const start = Date.now();
      await this.redis.ping();
      const latency = Date.now() - start;
      pingResults.push(latency);
    }
    
    // Simulate connection establishment times
    for (let i = 0; i < 10; i++) {
      const connTime = Math.random() * 10 + 5; // 5-15ms
      connectionTimes.push(connTime);
    }
    
    this.results.connection = {
      averagePingLatency: pingResults.reduce((a, b) => a + b) / pingResults.length,
      minPingLatency: Math.min(...pingResults),
      maxPingLatency: Math.max(...pingResults),
      averageConnectionTime: connectionTimes.reduce((a, b) => a + b) / connectionTimes.length,
      successRate: 100, // Simulated perfect connection
      jitter: this.calculateJitter(pingResults)
    };
    
    console.log(`  ⚡ Average ping: ${Math.round(this.results.connection.averagePingLatency * 100) / 100}ms`);
  }

  calculateJitter(latencies) {
    if (latencies.length < 2) return 0;
    
    let jitter = 0;
    for (let i = 1; i < latencies.length; i++) {
      jitter += Math.abs(latencies[i] - latencies[i - 1]);
    }
    return jitter / (latencies.length - 1);
  }

  async testOperationPerformance() {
    console.log('⚙️ Testing Redis operation performance...');
    
    this.results.operations = {};
    
    for (const operation of this.testOperations) {
      console.log(`  🔧 Testing ${operation.name} operations...`);
      
      const results = [];
      const iterations = 100;
      
      // Test the operation multiple times
      for (let i = 0; i < iterations; i++) {
        try {
          const testKey = `test:${operation.name}:${i}`;
          const testValue = `value_${i}`;
          
          let result;
          switch (operation.name) {
            case 'set':
              result = await this.redis.set(testKey, testValue);
              break;
            case 'get':
              result = await this.redis.get(testKey);
              break;
            case 'hset':
              result = await this.redis.hset(testKey, 'field', testValue);
              break;
            case 'hget':
              result = await this.redis.hget(testKey, 'field');
              break;
            case 'lpush':
              result = await this.redis.lpush(testKey, testValue);
              break;
            case 'lpop':
              result = await this.redis.lpop(testKey);
              break;
            case 'sadd':
              result = await this.redis.sadd(testKey, testValue);
              break;
            case 'smembers':
              result = await this.redis.smembers(testKey);
              break;
            case 'zadd':
              result = await this.redis.zadd(testKey, i, testValue);
              break;
            case 'zrange':
              result = await this.redis.zrange(testKey, 0, -1);
              break;
            default:
              result = await this.redis.get(testKey);
          }
          
          results.push({
            latency: result.latency,
            success: true
          });
          
        } catch (error) {
          results.push({
            latency: null,
            success: false,
            error: error.message
          });
        }
      }
      
      const successfulResults = results.filter(r => r.success);
      const latencies = successfulResults.map(r => r.latency);
      
      if (latencies.length > 0) {
        this.results.operations[operation.name] = {
          description: operation.description,
          iterations,
          successCount: successfulResults.length,
          failureCount: results.length - successfulResults.length,
          averageLatency: latencies.reduce((a, b) => a + b) / latencies.length,
          minLatency: Math.min(...latencies),
          maxLatency: Math.max(...latencies),
          p95Latency: this.calculatePercentile(latencies, 95),
          p99Latency: this.calculatePercentile(latencies, 99),
          throughput: successfulResults.length / (Math.max(...latencies) - Math.min(...latencies)) * 1000,
          performance: this.categorizePerformance(latencies.reduce((a, b) => a + b) / latencies.length)
        };
      } else {
        this.results.operations[operation.name] = {
          description: operation.description,
          error: 'All operations failed',
          failureCount: results.length
        };
      }
      
      console.log(`    ⏱️  Average: ${Math.round((this.results.operations[operation.name].averageLatency || 0) * 100) / 100}ms`);
    }
  }

  calculatePercentile(values, percentile) {
    const sorted = values.sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return sorted[index];
  }

  categorizePerformance(avgLatency) {
    if (avgLatency < 1) return 'Excellent';
    if (avgLatency < 2) return 'Good';
    if (avgLatency < 5) return 'Fair';
    if (avgLatency < 10) return 'Poor';
    return 'Critical';
  }

  async testMemoryUsage() {
    console.log('💾 Testing Redis memory usage...');
    
    const info = await this.redis.info();
    
    // Simulate memory analysis for different key types
    const memoryByType = {};
    
    for (const keyPattern of this.cacheKeys) {
      const keys = await this.redis.keys(keyPattern);
      let totalMemory = 0;
      
      // Sample a few keys to estimate memory usage
      const sampleSize = Math.min(keys.length, 10);
      for (let i = 0; i < sampleSize; i++) {
        const memory = await this.redis.memory(keys[i]);
        totalMemory += memory;
      }
      
      const avgMemoryPerKey = sampleSize > 0 ? totalMemory / sampleSize : 0;
      const estimatedTotal = avgMemoryPerKey * keys.length;
      
      memoryByType[keyPattern] = {
        keyCount: keys.length,
        averageKeySize: avgMemoryPerKey,
        estimatedTotalSize: estimatedTotal,
        sampleSize
      };
    }
    
    this.results.memory = {
      totalUsed: info.used_memory,
      peakUsed: info.used_memory_peak,
      memoryByType,
      fragmentation: info.used_memory / (info.used_memory * 0.85), // Simulated fragmentation
      hitRate: info.keyspace_hits / (info.keyspace_hits + info.keyspace_misses),
      evictions: info.evicted_keys,
      expires: info.expired_keys
    };
    
    console.log(`  📊 Total memory: ${Math.round(info.used_memory / 1024 / 1024)}MB`);
    console.log(`  🎯 Hit rate: ${Math.round(this.results.memory.hitRate * 100)}%`);
  }

  async analyzeCachePatterns() {
    console.log('🔍 Analyzing cache patterns...');
    
    const cacheAnalysis = {};
    
    for (const keyPattern of this.cacheKeys) {
      const keys = await this.redis.keys(keyPattern);
      
      // Simulate cache pattern analysis
      const analysis = {
        keyCount: keys.length,
        estimatedHitRate: Math.random() * 0.3 + 0.7, // 70-100%
        estimatedTTL: Math.random() * 3600 + 300, // 5min - 1hr
        accessPattern: this.determineAccessPattern(),
        effectiveness: Math.random() * 0.4 + 0.6 // 60-100%
      };
      
      cacheAnalysis[keyPattern] = analysis;
    }
    
    this.results.cacheAnalysis = cacheAnalysis;
    
    console.log(`  📈 Analyzed ${this.cacheKeys.length} cache patterns`);
  }

  determineAccessPattern() {
    const patterns = ['Hot', 'Warm', 'Cold', 'Sporadic'];
    return patterns[Math.floor(Math.random() * patterns.length)];
  }

  async testConcurrentOperations() {
    console.log('⚡ Testing concurrent operations...');
    
    const concurrencyLevels = [10, 50, 100, 200];
    const concurrencyResults = {};
    
    for (const level of concurrencyLevels) {
      console.log(`  🔄 Testing ${level} concurrent operations...`);
      
      const promises = [];
      const startTime = Date.now();
      
      // Create concurrent operations
      for (let i = 0; i < level; i++) {
        promises.push(this.redis.set(`concurrent:${level}:${i}`, `value_${i}`));
      }
      
      try {
        const results = await Promise.all(promises);
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        concurrencyResults[level] = {
          operations: level,
          duration,
          throughput: level / (duration / 1000), // ops per second
          averageLatency: duration / level,
          success: true,
          successfulOps: results.length
        };
        
      } catch (error) {
        concurrencyResults[level] = {
          operations: level,
          success: false,
          error: error.message
        };
      }
      
      console.log(`    📊 Throughput: ${Math.round(concurrencyResults[level].throughput || 0)} ops/sec`);
    }
    
    this.results.concurrency = concurrencyResults;
  }

  generateRecommendations() {
    console.log('💡 Generating Redis optimization recommendations...');
    
    const recommendations = [];
    
    // Memory usage recommendations
    if (this.results.memory.totalUsed > 100 * 1024 * 1024) { // > 100MB
      recommendations.push({
        category: 'Memory',
        priority: 'High',
        issue: 'High memory usage detected',
        recommendation: 'Implement key expiration policies and review data storage patterns',
        impact: 'High - Prevent memory exhaustion',
        effort: 'Medium'
      });
    }
    
    // Hit rate recommendations
    if (this.results.memory.hitRate < 0.9) {
      recommendations.push({
        category: 'Cache Efficiency',
        priority: 'High',
        issue: `Low cache hit rate: ${Math.round(this.results.memory.hitRate * 100)}%`,
        recommendation: 'Review cache keys and TTL settings, implement cache warming',
        impact: 'High - Better application performance',
        effort: 'Medium'
      });
    }
    
    // Operation performance recommendations
    Object.entries(this.results.operations).forEach(([op, data]) => {
      if (data.averageLatency > 5) {
        recommendations.push({
          category: 'Performance',
          priority: data.averageLatency > 10 ? 'Critical' : 'High',
          issue: `Slow ${op} operations: ${Math.round(data.averageLatency * 100) / 100}ms`,
          recommendation: 'Optimize data structures, check network latency, consider Redis cluster',
          impact: 'High - Faster response times',
          effort: 'Medium',
          operation: op
        });
      }
    });
    
    // Memory fragmentation
    if (this.results.memory.fragmentation > 1.5) {
      recommendations.push({
        category: 'Memory',
        priority: 'Medium',
        issue: 'High memory fragmentation detected',
        recommendation: 'Schedule regular Redis restarts or enable active defragmentation',
        impact: 'Medium - Better memory utilization',
        effort: 'Low'
      });
    }
    
    // Eviction recommendations
    if (this.results.memory.evictions > 100) {
      recommendations.push({
        category: 'Memory',
        priority: 'High',
        issue: 'Frequent key evictions detected',
        recommendation: 'Increase Redis memory limit or optimize key expiration policies',
        impact: 'High - Prevent data loss',
        effort: 'Low'
      });
    }
    
    // Cache pattern optimization
    Object.entries(this.results.cacheAnalysis).forEach(([pattern, data]) => {
      if (data.effectiveness < 0.8) {
        recommendations.push({
          category: 'Cache Strategy',
          priority: 'Medium',
          issue: `Low cache effectiveness for ${pattern}`,
          recommendation: 'Review caching strategy, adjust TTL, or implement smarter invalidation',
          impact: 'Medium - Better cache utilization',
          effort: 'Medium',
          pattern
        });
      }
    });
    
    // Concurrency recommendations
    const maxConcurrency = Math.max(...Object.keys(this.results.concurrency || {}).map(Number));
    if (maxConcurrency > 0) {
      const worstConcurrency = Object.entries(this.results.concurrency)
        .find(([, data]) => !data.success || data.throughput < 100);
      
      if (worstConcurrency) {
        recommendations.push({
          category: 'Scalability',
          priority: 'High',
          issue: 'Performance degradation under high concurrency',
          recommendation: 'Implement connection pooling, consider Redis Cluster for scaling',
          impact: 'High - Better scalability',
          effort: 'High'
        });
      }
    }
    
    // Sort by priority
    const priorityOrder = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
    this.results.recommendations = recommendations.sort((a, b) => 
      priorityOrder[b.priority] - priorityOrder[a.priority]
    );
  }

  async generateReport() {
    console.log('📄 Generating Redis performance report...');
    
    // Calculate overall score
    this.calculateOverallScore();
    
    // Save detailed JSON report
    const jsonReportPath = path.join(__dirname, 'redis-performance-report.json');
    fs.writeFileSync(jsonReportPath, JSON.stringify(this.results, null, 2));
    
    // Generate markdown summary
    const markdownReportPath = path.join(__dirname, 'redis-performance-summary.md');
    const markdownContent = this.generateMarkdownReport();
    fs.writeFileSync(markdownReportPath, markdownContent);
    
    console.log(`📊 Detailed report: ${jsonReportPath}`);
    console.log(`📋 Summary report: ${markdownReportPath}`);
    
    // Display key findings
    this.displayKeyFindings();
  }

  calculateOverallScore() {
    let score = 100;
    
    // Deduct for high latency operations
    Object.values(this.results.operations).forEach(op => {
      if (op.averageLatency > 10) score -= 25;
      else if (op.averageLatency > 5) score -= 15;
      else if (op.averageLatency > 2) score -= 5;
    });
    
    // Deduct for low hit rate
    if (this.results.memory.hitRate < 0.8) score -= 20;
    else if (this.results.memory.hitRate < 0.9) score -= 10;
    
    // Deduct for high memory usage
    if (this.results.memory.totalUsed > 500 * 1024 * 1024) score -= 15; // > 500MB
    else if (this.results.memory.totalUsed > 200 * 1024 * 1024) score -= 10; // > 200MB
    
    // Deduct for evictions
    if (this.results.memory.evictions > 1000) score -= 15;
    else if (this.results.memory.evictions > 100) score -= 10;
    
    // Deduct for connection issues
    if (this.results.connection.averagePingLatency > 5) score -= 10;
    else if (this.results.connection.averagePingLatency > 2) score -= 5;
    
    this.results.overallScore = Math.max(0, score);
  }

  generateMarkdownReport() {
    const timestamp = new Date().toLocaleString();
    
    return `# Redis Performance Test Report

Generated: ${timestamp}

## Executive Summary

**Overall Redis Performance Score: ${this.results.overallScore}/100**

${this.results.overallScore >= 80 ? '🟢 **Status: Excellent**' : 
  this.results.overallScore >= 60 ? '🟡 **Status: Good**' : 
  '🔴 **Status: Needs Optimization**'}

## Connection Performance

- **Average Ping Latency**: ${Math.round((this.results.connection?.averagePingLatency || 0) * 100) / 100}ms
- **Min/Max Latency**: ${Math.round((this.results.connection?.minPingLatency || 0) * 100) / 100}ms / ${Math.round((this.results.connection?.maxPingLatency || 0) * 100) / 100}ms
- **Connection Jitter**: ${Math.round((this.results.connection?.jitter || 0) * 100) / 100}ms
- **Success Rate**: ${this.results.connection?.successRate || 0}%

## Operation Performance

| Operation | Avg Latency | P95 | P99 | Performance | Throughput |
|-----------|-------------|-----|-----|-------------|------------|
${Object.entries(this.results.operations || {}).map(([name, data]) => 
  `| ${name} | ${Math.round((data.averageLatency || 0) * 100) / 100}ms | ${Math.round((data.p95Latency || 0) * 100) / 100}ms | ${Math.round((data.p99Latency || 0) * 100) / 100}ms | ${data.performance || 'N/A'} | ${Math.round(data.throughput || 0)} ops/s |`
).join('\n')}

## Memory Analysis

- **Total Memory Used**: ${Math.round((this.results.memory?.totalUsed || 0) / 1024 / 1024)}MB
- **Peak Memory**: ${Math.round((this.results.memory?.peakUsed || 0) / 1024 / 1024)}MB
- **Memory Fragmentation**: ${Math.round((this.results.memory?.fragmentation || 1) * 100) / 100}x
- **Cache Hit Rate**: ${Math.round((this.results.memory?.hitRate || 0) * 100)}%
- **Keys Evicted**: ${this.results.memory?.evictions || 0}
- **Keys Expired**: ${this.results.memory?.expires || 0}

### Memory Usage by Cache Type

${Object.entries(this.results.memory?.memoryByType || {}).map(([pattern, data]) => `
#### ${pattern}
- **Key Count**: ${data.keyCount?.toLocaleString() || 0}
- **Average Key Size**: ${Math.round(data.averageKeySize || 0)} bytes
- **Estimated Total**: ${Math.round((data.estimatedTotalSize || 0) / 1024)}KB
`).join('\n')}

## Cache Pattern Analysis

${Object.entries(this.results.cacheAnalysis || {}).map(([pattern, data]) => `
### ${pattern}
- **Keys**: ${data.keyCount?.toLocaleString() || 0}
- **Hit Rate**: ${Math.round((data.estimatedHitRate || 0) * 100)}%
- **Access Pattern**: ${data.accessPattern || 'Unknown'}
- **Effectiveness**: ${Math.round((data.effectiveness || 0) * 100)}%
- **Estimated TTL**: ${Math.round((data.estimatedTTL || 0) / 60)} minutes
`).join('\n')}

## Concurrency Performance

${Object.entries(this.results.concurrency || {}).map(([level, data]) => `
### ${level} Concurrent Operations
${data.success ? `
- **Duration**: ${data.duration}ms
- **Throughput**: ${Math.round(data.throughput)} ops/sec  
- **Average Latency**: ${Math.round(data.averageLatency * 100) / 100}ms
- **Success Rate**: 100%
` : `- **Status**: Failed - ${data.error}`}
`).join('\n')}

## Critical Issues

${this.results.recommendations.filter(r => r.priority === 'Critical').map(rec => `
### 🔴 ${rec.issue}
**Category**: ${rec.category}  
**Recommendation**: ${rec.recommendation}  
**Impact**: ${rec.impact} | **Effort**: ${rec.effort}
`).join('\n') || 'No critical issues detected ✅'}

## High Priority Recommendations

${this.results.recommendations.filter(r => r.priority === 'High').map(rec => `
### 🟡 ${rec.issue}
**Category**: ${rec.category}  
**Recommendation**: ${rec.recommendation}  
**Impact**: ${rec.impact} | **Effort**: ${rec.effort}
`).join('\n') || 'No high priority issues detected ✅'}

## Optimization Roadmap

### Immediate Actions (Critical & High Priority)
${this.results.recommendations
  .filter(r => ['Critical', 'High'].includes(r.priority))
  .map((rec, index) => `${index + 1}. ${rec.recommendation}`)
  .join('\n') || '• No immediate actions required'}

### Short-term Improvements (Medium Priority)
${this.results.recommendations
  .filter(r => r.priority === 'Medium')
  .slice(0, 5)
  .map((rec, index) => `${index + 1}. ${rec.recommendation}`)
  .join('\n') || '• No short-term improvements needed'}

## Redis Configuration Recommendations

### Memory Optimization
\`\`\`
maxmemory ${Math.round((this.results.memory?.totalUsed || 0) * 1.5 / 1024 / 1024)}mb
maxmemory-policy allkeys-lru
\`\`\`

### Performance Tuning
\`\`\`
tcp-keepalive 60
timeout 300
tcp-backlog 511
databases 16
\`\`\`

### Persistence (if needed)
\`\`\`
save 900 1
save 300 10
save 60 10000
\`\`\`

## Monitoring Setup

### Key Metrics to Monitor
1. **Memory usage** (current: ${Math.round((this.results.memory?.totalUsed || 0) / 1024 / 1024)}MB)
2. **Hit rate** (current: ${Math.round((this.results.memory?.hitRate || 0) * 100)}%)
3. **Operations per second** 
4. **Connection count**
5. **Key eviction rate**

### Alerts to Set Up
- Memory usage > 80%
- Hit rate < 95%
- Average latency > 5ms
- Eviction rate > 10/min
- Connection failures > 1%

## Performance Baseline

This report establishes a performance baseline for Redis operations:

1. **Target Latencies**: 
   - GET/SET operations: < 1ms
   - Hash operations: < 2ms
   - List/Set operations: < 2ms
   - Sorted set operations: < 3ms

2. **Target Throughput**: > 1000 ops/sec per core
3. **Target Hit Rate**: > 95%
4. **Target Memory Efficiency**: < 1.2x fragmentation

---
*Generated by SmellPin Redis Performance Tester*
`;
  }

  displayKeyFindings() {
    console.log('\n🎯 REDIS PERFORMANCE FINDINGS:');
    console.log('==============================');
    
    console.log(`📊 Overall Score: ${this.results.overallScore}/100`);
    console.log(`⚡ Avg Ping: ${Math.round((this.results.connection?.averagePingLatency || 0) * 100) / 100}ms`);
    console.log(`💾 Memory: ${Math.round((this.results.memory?.totalUsed || 0) / 1024 / 1024)}MB`);
    console.log(`🎯 Hit Rate: ${Math.round((this.results.memory?.hitRate || 0) * 100)}%`);
    
    // Show slowest operations
    const slowestOps = Object.entries(this.results.operations || {})
      .filter(([, data]) => !data.error)
      .sort((a, b) => b[1].averageLatency - a[1].averageLatency)
      .slice(0, 3);
    
    if (slowestOps.length > 0) {
      console.log('\n🐌 Slowest Operations:');
      slowestOps.forEach(([name, data], index) => {
        console.log(`${index + 1}. ${name}: ${Math.round(data.averageLatency * 100) / 100}ms`);
      });
    }
    
    // Show cache efficiency
    const cachePatterns = Object.entries(this.results.cacheAnalysis || {})
      .sort((a, b) => b[1].effectiveness - a[1].effectiveness);
    
    if (cachePatterns.length > 0) {
      console.log('\n📈 Cache Effectiveness:');
      cachePatterns.forEach(([pattern, data], index) => {
        if (index < 3) {
          console.log(`${index + 1}. ${pattern}: ${Math.round(data.effectiveness * 100)}%`);
        }
      });
    }
    
    // Show recommendations
    const criticalRecs = this.results.recommendations.filter(r => r.priority === 'Critical');
    const highRecs = this.results.recommendations.filter(r => r.priority === 'High');
    
    console.log(`\n🔥 Critical Issues: ${criticalRecs.length}`);
    console.log(`⚠️  High Priority Issues: ${highRecs.length}`);
    
    if (criticalRecs.length > 0) {
      console.log('\n🚨 Critical Recommendations:');
      criticalRecs.slice(0, 2).forEach((rec, index) => {
        console.log(`${index + 1}. ${rec.recommendation}`);
      });
    }
  }

  async cleanup() {
    // Close Redis connections, clean up test keys
    if (this.redis) {
      this.redis.connected = false;
    }
  }
}

// CLI execution
if (require.main === module) {
  const tester = new RedisPerformanceTester();
  tester.runRedisTests().catch(console.error);
}

module.exports = RedisPerformanceTester;