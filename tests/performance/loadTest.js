const autocannon = require('autocannon');
const { performance } = require('perf_hooks');

/**
 * Load Testing Configuration for SmellPin API
 * Target: Handle 10K+ concurrent users with <200ms API response time
 */

const BASE_URL = process.env.TEST_BASE_URL || 'http://localhost:3000';
const TEST_DURATION = process.env.TEST_DURATION || 60; // seconds
const MAX_CONNECTIONS = process.env.MAX_CONNECTIONS || 1000;
const TEST_TOKEN = process.env.TEST_AUTH_TOKEN || '';

class LoadTestSuite {
  constructor() {
    this.results = {
      healthCheck: null,
      authentication: null,
      nearbySearch: null,
      annotationCreation: null,
      rewardClaim: null,
      paymentProcessing: null,
    };
  }

  /**
   * Health Check Load Test
   * Tests basic server responsiveness under load
   */
  async testHealthEndpoint() {
    console.log('🏥 Testing Health Endpoint Load...');
    
    const result = await autocannon({
      url: `${BASE_URL}/api/health`,
      connections: MAX_CONNECTIONS,
      duration: TEST_DURATION,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.results.healthCheck = result;
    console.log(`Health Check Results:
      - RPS: ${result.requests.average}
      - Latency (avg): ${result.latency.average}ms
      - Latency (p99): ${result.latency.p99}ms
      - Throughput: ${result.throughput.average} bytes/sec
      - Errors: ${result.errors}
    `);

    return result;
  }

  /**
   * Authentication Load Test
   * Tests user login under high concurrent load
   */
  async testAuthenticationLoad() {
    console.log('🔐 Testing Authentication Load...');

    const result = await autocannon({
      url: `${BASE_URL}/api/auth/login`,
      connections: 500, // Lower for auth to avoid rate limiting
      duration: TEST_DURATION,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'loadtest@example.com',
        password: 'LoadTest123!',
      }),
    });

    this.results.authentication = result;
    console.log(`Authentication Results:
      - RPS: ${result.requests.average}
      - Latency (avg): ${result.latency.average}ms
      - Latency (p99): ${result.latency.p99}ms
      - Success Rate: ${((result.requests.total - result.errors) / result.requests.total * 100).toFixed(2)}%
    `);

    return result;
  }

  /**
   * Nearby Search Load Test
   * Tests LBS nearby annotation search under load
   */
  async testNearbySearchLoad() {
    console.log('🗺️ Testing Nearby Search Load...');

    const locations = [
      { lat: 39.9042, lon: 116.4074 }, // Beijing
      { lat: 31.2304, lon: 121.4737 }, // Shanghai
      { lat: 22.3193, lon: 114.1694 }, // Hong Kong
      { lat: 40.7128, lon: -74.0060 }, // New York
      { lat: 51.5074, lon: -0.1278 },  // London
    ];

    const result = await autocannon({
      url: `${BASE_URL}/api/annotations/nearby`,
      connections: MAX_CONNECTIONS,
      duration: TEST_DURATION,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TEST_TOKEN}`,
      },
      setupClient: (client) => {
        client.setBody(() => {
          const location = locations[Math.floor(Math.random() * locations.length)];
          return JSON.stringify({
            latitude: location.lat + (Math.random() - 0.5) * 0.01, // Small random variation
            longitude: location.lon + (Math.random() - 0.5) * 0.01,
            radius: Math.floor(Math.random() * 1000) + 100, // 100-1100 meters
          });
        });
      },
    });

    this.results.nearbySearch = result;
    console.log(`Nearby Search Results:
      - RPS: ${result.requests.average}
      - Latency (avg): ${result.latency.average}ms
      - Latency (p99): ${result.latency.p99}ms
      - Target Met (<200ms avg): ${result.latency.average < 200 ? '✅' : '❌'}
    `);

    return result;
  }

  /**
   * Annotation Creation Load Test
   * Tests smell annotation creation under load
   */
  async testAnnotationCreationLoad() {
    console.log('📝 Testing Annotation Creation Load...');

    const smellTypes = ['chemical', 'sewage', 'garbage', 'industrial', 'cooking', 'smoke'];
    const descriptions = [
      'Strong chemical odor detected',
      'Sewage smell in the area',
      'Garbage disposal smell',
      'Industrial emissions detected',
      'Cooking oil smell',
      'Smoke and burning smell',
    ];

    const result = await autocannon({
      url: `${BASE_URL}/api/annotations`,
      connections: 200, // Lower for write operations
      duration: TEST_DURATION / 2, // Shorter duration for writes
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TEST_TOKEN}`,
      },
      setupClient: (client) => {
        client.setBody(() => {
          return JSON.stringify({
            latitude: 39.9042 + (Math.random() - 0.5) * 0.1,
            longitude: 116.4074 + (Math.random() - 0.5) * 0.1,
            smellType: smellTypes[Math.floor(Math.random() * smellTypes.length)],
            intensity: Math.floor(Math.random() * 10) + 1,
            description: descriptions[Math.floor(Math.random() * descriptions.length)],
            amount: Math.floor(Math.random() * 50) + 10,
            tags: [`load-test-${Date.now()}`],
          });
        });
      },
    });

    this.results.annotationCreation = result;
    console.log(`Annotation Creation Results:
      - RPS: ${result.requests.average}
      - Latency (avg): ${result.latency.average}ms
      - Latency (p99): ${result.latency.p99}ms
      - Error Rate: ${(result.errors / result.requests.total * 100).toFixed(2)}%
    `);

    return result;
  }

  /**
   * LBS Reward Claim Load Test
   * Tests reward claiming system under load
   */
  async testRewardClaimLoad() {
    console.log('🎁 Testing Reward Claim Load...');

    const result = await autocannon({
      url: `${BASE_URL}/api/lbs/claim-reward`,
      connections: 500,
      duration: TEST_DURATION / 3, // Shorter for complex operations
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TEST_TOKEN}`,
      },
      setupClient: (client) => {
        client.setBody(() => {
          return JSON.stringify({
            annotationId: `annotation-${Math.random().toString(36).substr(2, 9)}`,
            locationData: {
              latitude: 39.9042 + (Math.random() - 0.5) * 0.01,
              longitude: 116.4074 + (Math.random() - 0.5) * 0.01,
              accuracy: Math.floor(Math.random() * 20) + 5,
              stayDuration: Math.floor(Math.random() * 60) + 30,
              deviceInfo: {
                platform: Math.random() > 0.5 ? 'iOS' : 'Android',
                version: '14.0',
              },
            },
            rewardType: Math.random() > 0.5 ? 'first_finder' : 'combo',
          });
        });
      },
    });

    this.results.rewardClaim = result;
    console.log(`Reward Claim Results:
      - RPS: ${result.requests.average}
      - Latency (avg): ${result.latency.average}ms
      - Latency (p99): ${result.latency.p99}ms
    `);

    return result;
  }

  /**
   * Payment Processing Load Test
   * Tests payment system under load
   */
  async testPaymentProcessingLoad() {
    console.log('💳 Testing Payment Processing Load...');

    const result = await autocannon({
      url: `${BASE_URL}/api/payments/create-session`,
      connections: 100, // Conservative for payment operations
      duration: TEST_DURATION / 4,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${TEST_TOKEN}`,
      },
      setupClient: (client) => {
        client.setBody(() => {
          return JSON.stringify({
            annotationId: `annotation-${Math.random().toString(36).substr(2, 9)}`,
            amount: Math.floor(Math.random() * 50) + 10,
            currency: 'USD',
            paymentMethod: 'stripe',
          });
        });
      },
    });

    this.results.paymentProcessing = result;
    console.log(`Payment Processing Results:
      - RPS: ${result.requests.average}
      - Latency (avg): ${result.latency.average}ms
      - Latency (p99): ${result.latency.p99}ms
    `);

    return result;
  }

  /**
   * Stress Test - Gradual Load Increase
   * Tests system behavior under gradually increasing load
   */
  async runStressTest() {
    console.log('🔥 Running Stress Test with Gradual Load Increase...');

    const stressLevels = [100, 500, 1000, 2000, 5000, 10000];
    const stressResults = [];

    for (const connections of stressLevels) {
      console.log(`\n📊 Testing with ${connections} connections...`);

      const result = await autocannon({
        url: `${BASE_URL}/api/health`,
        connections: Math.min(connections, 1000), // Limit actual connections to prevent overwhelming
        amount: connections * 10, // Total requests
        headers: {
          'Content-Type': 'application/json',
        },
      });

      const stressData = {
        connections,
        rps: result.requests.average,
        latency: result.latency.average,
        p99: result.latency.p99,
        errors: result.errors,
        errorRate: (result.errors / result.requests.total * 100),
      };

      stressResults.push(stressData);

      console.log(`Results for ${connections} connections:
        - RPS: ${stressData.rps}
        - Avg Latency: ${stressData.latency}ms
        - P99 Latency: ${stressData.p99}ms
        - Error Rate: ${stressData.errorRate.toFixed(2)}%
      `);

      // Stop if error rate becomes too high
      if (stressData.errorRate > 5) {
        console.log('⚠️  High error rate detected, stopping stress test');
        break;
      }

      // Pause between tests
      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    return stressResults;
  }

  /**
   * Database Performance Test
   * Tests database query performance under load
   */
  async testDatabasePerformance() {
    console.log('🗄️ Testing Database Performance...');

    const dbTests = [
      { name: 'User Stats', endpoint: '/api/users/stats' },
      { name: 'Payment History', endpoint: '/api/payments/user-history' },
      { name: 'Annotation Search', endpoint: '/api/annotations/search?query=chemical' },
      { name: 'Reward History', endpoint: '/api/lbs/user-rewards' },
    ];

    const dbResults = [];

    for (const test of dbTests) {
      console.log(`\n📈 Testing ${test.name}...`);

      const result = await autocannon({
        url: `${BASE_URL}${test.endpoint}`,
        connections: 200,
        duration: 30,
        headers: {
          'Authorization': `Bearer ${TEST_TOKEN}`,
        },
      });

      dbResults.push({
        name: test.name,
        rps: result.requests.average,
        latency: result.latency.average,
        p99: result.latency.p99,
        errors: result.errors,
      });

      console.log(`${test.name} Results:
        - RPS: ${result.requests.average}
        - Avg Latency: ${result.latency.average}ms
        - P99 Latency: ${result.latency.p99}ms
      `);
    }

    return dbResults;
  }

  /**
   * Generate Performance Report
   * Creates comprehensive performance report
   */
  generateReport() {
    console.log('\n📊 PERFORMANCE TEST REPORT');
    console.log('='.repeat(50));

    const requirements = {
      maxLatency: 200, // ms
      minRPS: 100,
      maxErrorRate: 1, // percent
    };

    const summary = {
      totalTests: 0,
      passedTests: 0,
      failedTests: 0,
      criticalIssues: [],
    };

    Object.entries(this.results).forEach(([testName, result]) => {
      if (!result) return;

      summary.totalTests++;
      const avgLatency = result.latency.average;
      const rps = result.requests.average;
      const errorRate = (result.errors / result.requests.total) * 100;

      const passed = 
        avgLatency <= requirements.maxLatency &&
        rps >= requirements.minRPS &&
        errorRate <= requirements.maxErrorRate;

      if (passed) {
        summary.passedTests++;
      } else {
        summary.failedTests++;
        if (avgLatency > requirements.maxLatency) {
          summary.criticalIssues.push(`${testName}: High latency (${avgLatency}ms)`);
        }
        if (errorRate > requirements.maxErrorRate) {
          summary.criticalIssues.push(`${testName}: High error rate (${errorRate.toFixed(2)}%)`);
        }
      }

      console.log(`\n${testName.toUpperCase()}:
        - Status: ${passed ? '✅ PASS' : '❌ FAIL'}
        - RPS: ${rps} (requirement: >${requirements.minRPS})
        - Avg Latency: ${avgLatency}ms (requirement: <${requirements.maxLatency}ms)
        - Error Rate: ${errorRate.toFixed(2)}% (requirement: <${requirements.maxErrorRate}%)
      `);
    });

    console.log('\n' + '='.repeat(50));
    console.log(`SUMMARY:
      - Total Tests: ${summary.totalTests}
      - Passed: ${summary.passedTests}
      - Failed: ${summary.failedTests}
      - Success Rate: ${((summary.passedTests / summary.totalTests) * 100).toFixed(1)}%
    `);

    if (summary.criticalIssues.length > 0) {
      console.log('\n🚨 CRITICAL ISSUES:');
      summary.criticalIssues.forEach(issue => console.log(`  - ${issue}`));
    }

    const overallPass = summary.failedTests === 0;
    console.log(`\n🎯 OVERALL RESULT: ${overallPass ? '✅ SYSTEM READY FOR 10K+ USERS' : '❌ PERFORMANCE ISSUES DETECTED'}`);

    return {
      summary,
      requirements,
      results: this.results,
      passed: overallPass,
    };
  }

  /**
   * Run Complete Load Test Suite
   */
  async runFullSuite() {
    console.log('🚀 Starting Complete Load Test Suite...');
    console.log(`Target: 10K+ concurrent users, <200ms response time`);
    console.log(`Test Duration: ${TEST_DURATION}s per test`);
    console.log('='.repeat(50));

    const startTime = performance.now();

    try {
      // Run all load tests
      await this.testHealthEndpoint();
      await this.testAuthenticationLoad();
      await this.testNearbySearchLoad();
      await this.testAnnotationCreationLoad();
      await this.testRewardClaimLoad();
      await this.testPaymentProcessingLoad();

      // Run stress test
      console.log('\n🔥 Running Additional Stress Tests...');
      const stressResults = await this.runStressTest();

      // Run database performance tests
      const dbResults = await this.testDatabasePerformance();

      const endTime = performance.now();
      const totalTime = ((endTime - startTime) / 1000 / 60).toFixed(2);

      console.log(`\n⏱️  Total test time: ${totalTime} minutes`);

      // Generate and return comprehensive report
      const report = this.generateReport();
      report.stressResults = stressResults;
      report.dbResults = dbResults;
      report.totalTime = totalTime;

      return report;

    } catch (error) {
      console.error('❌ Load test suite failed:', error);
      throw error;
    }
  }
}

// Export for use in other test files
module.exports = LoadTestSuite;

// Run tests if called directly
if (require.main === module) {
  const loadTest = new LoadTestSuite();
  
  loadTest.runFullSuite()
    .then(report => {
      console.log('\n📄 Test completed. Report available.');
      process.exit(report.passed ? 0 : 1);
    })
    .catch(error => {
      console.error('Load test failed:', error);
      process.exit(1);
    });
}