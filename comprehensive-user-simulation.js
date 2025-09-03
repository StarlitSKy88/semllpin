#!/usr/bin/env node

/**
 * SmellPin Comprehensive User Simulation Testing System
 * 
 * This system simulates realistic concurrent user behavior patterns
 * to test all critical workflows under load conditions.
 * 
 * Features:
 * - Multi-user concurrent simulation (10-50 users)
 * - Realistic GPS coordinate generation
 * - Complete workflow coverage (registration, annotation, rewards, payments)
 * - Performance monitoring and bottleneck identification
 * - Comprehensive reporting
 */

const axios = require('axios');
const { faker } = require('@faker-js/faker');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
  API_BASE_URL: process.env.API_URL || 'http://localhost:3000',
  API_VERSION: '/api/v1',
  CONCURRENT_USERS: parseInt(process.env.CONCURRENT_USERS) || 25,
  TEST_DURATION_MINUTES: parseInt(process.env.TEST_DURATION) || 5,
  MAX_ANNOTATIONS_PER_USER: 3,
  REWARD_CLAIM_PROBABILITY: 0.7,
  PAYMENT_SUCCESS_RATE: 0.9,
  GPS_BOUNDS: {
    // Global coordinates with high-density areas
    ZONES: [
      { name: 'New York', lat: 40.7128, lng: -74.0060, radius: 0.1 },
      { name: 'London', lat: 51.5074, lng: -0.1278, radius: 0.1 },
      { name: 'Tokyo', lat: 35.6762, lng: 139.6503, radius: 0.1 },
      { name: 'Sydney', lat: -33.8688, lng: 151.2093, radius: 0.1 },
      { name: 'San Francisco', lat: 37.7749, lng: -122.4194, radius: 0.1 },
      { name: 'Paris', lat: 48.8566, lng: 2.3522, radius: 0.1 },
      { name: 'Berlin', lat: 52.5200, lng: 13.4050, radius: 0.1 },
      { name: 'Singapore', lat: 1.3521, lng: 103.8198, radius: 0.05 }
    ]
  },
  SMELL_TYPES: [
    'industrial_pollution', 'sewage', 'garbage', 'chemical', 'smoke',
    'food_waste', 'oil_spill', 'gas_leak', 'compost', 'pet_waste',
    'perfume', 'cooking', 'flowers', 'ocean', 'forest'
  ],
  SMELL_INTENSITIES: ['mild', 'moderate', 'strong', 'overwhelming'],
  DEVICE_TYPES: ['ios', 'android', 'web']
};

// Global state
const SIMULATION_STATE = {
  users: new Map(),
  annotations: new Map(),
  rewards: new Map(),
  performance: {
    requests: 0,
    failures: 0,
    totalResponseTime: 0,
    minResponseTime: Infinity,
    maxResponseTime: 0,
    errorsByType: new Map(),
    requestsByEndpoint: new Map()
  },
  startTime: null,
  endTime: null,
  reportPath: null
};

/**
 * Performance metrics collection
 */
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      requests: [],
      errors: [],
      responseTimeHistogram: new Map(),
      concurrentUsers: 0,
      peakConcurrentUsers: 0
    };
  }

  recordRequest(endpoint, method, responseTime, success, error = null) {
    const timestamp = Date.now();
    
    SIMULATION_STATE.performance.requests++;
    SIMULATION_STATE.performance.totalResponseTime += responseTime;
    SIMULATION_STATE.performance.minResponseTime = Math.min(SIMULATION_STATE.performance.minResponseTime, responseTime);
    SIMULATION_STATE.performance.maxResponseTime = Math.max(SIMULATION_STATE.performance.maxResponseTime, responseTime);

    if (!success) {
      SIMULATION_STATE.performance.failures++;
      const errorType = error?.response?.status || error?.code || 'unknown';
      SIMULATION_STATE.performance.errorsByType.set(
        errorType, 
        (SIMULATION_STATE.performance.errorsByType.get(errorType) || 0) + 1
      );
    }

    const endpointKey = `${method} ${endpoint}`;
    const endpointStats = SIMULATION_STATE.performance.requestsByEndpoint.get(endpointKey) || {
      count: 0,
      totalTime: 0,
      failures: 0
    };
    
    endpointStats.count++;
    endpointStats.totalTime += responseTime;
    if (!success) endpointStats.failures++;
    
    SIMULATION_STATE.performance.requestsByEndpoint.set(endpointKey, endpointStats);

    this.metrics.requests.push({
      timestamp,
      endpoint,
      method,
      responseTime,
      success,
      error: error?.message || null
    });

    if (!success && error) {
      this.metrics.errors.push({
        timestamp,
        endpoint,
        method,
        error: error.message,
        status: error?.response?.status,
        data: error?.response?.data
      });
    }
  }

  updateConcurrentUsers(count) {
    this.metrics.concurrentUsers = count;
    this.metrics.peakConcurrentUsers = Math.max(this.metrics.peakConcurrentUsers, count);
  }

  generateReport() {
    const totalRequests = SIMULATION_STATE.performance.requests;
    const totalFailures = SIMULATION_STATE.performance.failures;
    const avgResponseTime = totalRequests > 0 ? 
      SIMULATION_STATE.performance.totalResponseTime / totalRequests : 0;
    
    const successRate = totalRequests > 0 ? 
      ((totalRequests - totalFailures) / totalRequests * 100).toFixed(2) : 100;

    return {
      summary: {
        totalRequests,
        totalFailures,
        successRate: `${successRate}%`,
        avgResponseTime: `${avgResponseTime.toFixed(2)}ms`,
        minResponseTime: `${SIMULATION_STATE.performance.minResponseTime}ms`,
        maxResponseTime: `${SIMULATION_STATE.performance.maxResponseTime}ms`,
        peakConcurrentUsers: this.metrics.peakConcurrentUsers,
        testDuration: `${((SIMULATION_STATE.endTime - SIMULATION_STATE.startTime) / 1000 / 60).toFixed(2)} minutes`
      },
      endpointStats: Array.from(SIMULATION_STATE.performance.requestsByEndpoint.entries())
        .map(([endpoint, stats]) => ({
          endpoint,
          requests: stats.count,
          avgResponseTime: `${(stats.totalTime / stats.count).toFixed(2)}ms`,
          failureRate: `${(stats.failures / stats.count * 100).toFixed(2)}%`
        }))
        .sort((a, b) => b.requests - a.requests),
      errorAnalysis: Array.from(SIMULATION_STATE.performance.errorsByType.entries())
        .map(([type, count]) => ({ errorType: type, count }))
        .sort((a, b) => b.count - a.count),
      detailedMetrics: this.metrics
    };
  }
}

const performanceMonitor = new PerformanceMonitor();

/**
 * Realistic test data generators
 */
class TestDataGenerator {
  static generateUser() {
    const zone = faker.helpers.arrayElement(CONFIG.GPS_BOUNDS.ZONES);
    return {
      username: faker.internet.userName().toLowerCase() + '_' + faker.string.numeric(4),
      email: faker.internet.email().toLowerCase(),
      password: 'TestPassword123!',
      displayName: faker.person.fullName(),
      bio: faker.lorem.sentence(),
      location: {
        lat: zone.lat + (Math.random() - 0.5) * zone.radius,
        lng: zone.lng + (Math.random() - 0.5) * zone.radius,
        zone: zone.name
      },
      deviceInfo: this.generateDeviceInfo(),
      preferences: {
        notifications: Math.random() > 0.5,
        privacy: faker.helpers.arrayElement(['public', 'friends', 'private']),
        language: faker.helpers.arrayElement(['en', 'zh', 'es', 'fr', 'de'])
      }
    };
  }

  static generateDeviceInfo() {
    const deviceType = faker.helpers.arrayElement(CONFIG.DEVICE_TYPES);
    const baseInfo = {
      deviceType,
      userAgent: faker.internet.userAgent(),
      timestamp: Date.now()
    };

    switch (deviceType) {
      case 'ios':
        return {
          ...baseInfo,
          os: 'iOS',
          osVersion: faker.helpers.arrayElement(['16.0', '17.0', '17.1', '17.2']),
          device: faker.helpers.arrayElement(['iPhone 14', 'iPhone 15', 'iPhone 15 Pro']),
          appVersion: '1.0.0'
        };
      case 'android':
        return {
          ...baseInfo,
          os: 'Android',
          osVersion: faker.helpers.arrayElement(['13', '14', '15']),
          device: faker.helpers.arrayElement(['Samsung Galaxy S24', 'Pixel 8', 'OnePlus 12']),
          appVersion: '1.0.0'
        };
      default:
        return {
          ...baseInfo,
          os: 'Web',
          browser: faker.helpers.arrayElement(['Chrome', 'Safari', 'Firefox', 'Edge']),
          resolution: '1920x1080'
        };
    }
  }

  static generateSmellAnnotation(userLocation) {
    // Generate location near user with some randomness
    const annotation = {
      latitude: userLocation.lat + (Math.random() - 0.5) * 0.01,
      longitude: userLocation.lng + (Math.random() - 0.5) * 0.01,
      smellType: faker.helpers.arrayElement(CONFIG.SMELL_TYPES),
      intensity: faker.helpers.arrayElement(CONFIG.SMELL_INTENSITIES),
      description: faker.lorem.sentences(faker.number.int({ min: 1, max: 3 })),
      tags: faker.helpers.arrayElements(['outdoor', 'indoor', 'industrial', 'natural', 'temporary', 'persistent'], 
        faker.number.int({ min: 1, max: 3 })),
      isAnonymous: Math.random() > 0.7,
      mediaUrls: Math.random() > 0.6 ? [
        `https://example.com/photo/${faker.string.uuid()}.jpg`
      ] : [],
      timestamp: Date.now(),
      deviceInfo: this.generateDeviceInfo(),
      weather: {
        temperature: faker.number.int({ min: -10, max: 40 }),
        humidity: faker.number.int({ min: 30, max: 90 }),
        windSpeed: faker.number.float({ min: 0, max: 20, precision: 0.1 })
      }
    };

    // Add realistic validation errors occasionally
    if (Math.random() < 0.05) {
      // Simulate validation issues
      if (Math.random() < 0.5) {
        annotation.latitude = 200; // Invalid latitude
      } else {
        annotation.description = ''; // Empty description
      }
    }

    return annotation;
  }

  static generateGPSLocation(zone) {
    return {
      latitude: zone.lat + (Math.random() - 0.5) * zone.radius,
      longitude: zone.lng + (Math.random() - 0.5) * zone.radius,
      accuracy: faker.number.float({ min: 5, max: 50, precision: 0.1 }),
      timestamp: Date.now(),
      speed: faker.number.float({ min: 0, max: 20, precision: 0.1 }),
      bearing: faker.number.int({ min: 0, max: 360 })
    };
  }

  static generatePaymentInfo() {
    return {
      amount: faker.helpers.arrayElement([0.99, 1.99, 2.99, 4.99]),
      currency: 'USD',
      paymentMethod: faker.helpers.arrayElement(['stripe', 'paypal']),
      cardNumber: '4242424242424242', // Test card
      expiryMonth: faker.number.int({ min: 1, max: 12 }),
      expiryYear: faker.number.int({ min: 2025, max: 2030 }),
      cvv: faker.string.numeric(3),
      billingAddress: {
        street: faker.location.streetAddress(),
        city: faker.location.city(),
        country: faker.location.countryCode(),
        postalCode: faker.location.zipCode()
      }
    };
  }
}

/**
 * HTTP Client with performance tracking
 */
class HTTPClient {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.authToken = null;
  }

  setAuthToken(token) {
    this.authToken = token;
  }

  async makeRequest(method, endpoint, data = null, headers = {}) {
    const startTime = Date.now();
    const url = `${this.baseURL}${CONFIG.API_VERSION}${endpoint}`;
    
    const requestConfig = {
      method,
      url,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'SmellPin-UserSimulation/1.0.0',
        ...headers
      },
      timeout: 30000,
      validateStatus: () => true // Don't throw on HTTP errors
    };

    if (this.authToken) {
      requestConfig.headers.Authorization = `Bearer ${this.authToken}`;
    }

    if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
      requestConfig.data = data;
    }

    try {
      const response = await axios(requestConfig);
      const responseTime = Date.now() - startTime;
      const success = response.status >= 200 && response.status < 300;
      
      performanceMonitor.recordRequest(endpoint, method, responseTime, success, 
        success ? null : new Error(`HTTP ${response.status}: ${response.statusText}`));
      
      return {
        success,
        status: response.status,
        data: response.data,
        headers: response.headers,
        responseTime
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      performanceMonitor.recordRequest(endpoint, method, responseTime, false, error);
      
      return {
        success: false,
        error: error.message,
        responseTime,
        networkError: true
      };
    }
  }

  // Convenience methods
  async get(endpoint, headers = {}) {
    return this.makeRequest('GET', endpoint, null, headers);
  }

  async post(endpoint, data, headers = {}) {
    return this.makeRequest('POST', endpoint, data, headers);
  }

  async put(endpoint, data, headers = {}) {
    return this.makeRequest('PUT', endpoint, data, headers);
  }

  async delete(endpoint, headers = {}) {
    return this.makeRequest('DELETE', endpoint, null, headers);
  }
}

/**
 * Individual User Simulator
 */
class UserSimulator {
  constructor(userData) {
    this.userData = userData;
    this.client = new HTTPClient(CONFIG.API_BASE_URL);
    this.authToken = null;
    this.userId = null;
    this.annotations = [];
    this.discoveredRewards = [];
    this.isActive = false;
    this.activityLog = [];
    this.lastLocation = userData.location;
  }

  log(action, details = {}) {
    const logEntry = {
      timestamp: Date.now(),
      action,
      userId: this.userId,
      username: this.userData.username,
      ...details
    };
    this.activityLog.push(logEntry);
    console.log(`[${this.userData.username}] ${action}:`, details.status || details.message || 'OK');
  }

  async register() {
    this.log('REGISTER_ATTEMPT', { email: this.userData.email });
    
    const response = await this.client.post('/users/register', {
      username: this.userData.username,
      email: this.userData.email,
      password: this.userData.password,
      displayName: this.userData.displayName,
      bio: this.userData.bio,
      deviceInfo: this.userData.deviceInfo
    });

    if (response.success) {
      this.userId = response.data?.user?.id;
      this.authToken = response.data?.token;
      this.client.setAuthToken(this.authToken);
      SIMULATION_STATE.users.set(this.userId, this);
      this.log('REGISTER_SUCCESS', { userId: this.userId });
      return true;
    } else {
      this.log('REGISTER_FAILED', { 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return false;
    }
  }

  async login() {
    this.log('LOGIN_ATTEMPT', { email: this.userData.email });
    
    const response = await this.client.post('/users/login', {
      email: this.userData.email,
      password: this.userData.password,
      deviceInfo: this.userData.deviceInfo
    });

    if (response.success) {
      this.authToken = response.data?.token;
      this.userId = response.data?.user?.id;
      this.client.setAuthToken(this.authToken);
      this.log('LOGIN_SUCCESS', { userId: this.userId });
      return true;
    } else {
      this.log('LOGIN_FAILED', { 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return false;
    }
  }

  async updateLocation() {
    const zone = faker.helpers.arrayElement(CONFIG.GPS_BOUNDS.ZONES);
    this.lastLocation = TestDataGenerator.generateGPSLocation(zone);
    
    this.log('LOCATION_UPDATE', { 
      lat: this.lastLocation.latitude.toFixed(6), 
      lng: this.lastLocation.longitude.toFixed(6),
      zone: zone.name
    });

    // In a real app, this would be sent to a location tracking endpoint
    // For simulation purposes, we just update our internal state
    return true;
  }

  async createSmellAnnotation() {
    const annotation = TestDataGenerator.generateSmellAnnotation(this.lastLocation);
    
    this.log('ANNOTATION_CREATE_ATTEMPT', { 
      smellType: annotation.smellType, 
      intensity: annotation.intensity 
    });

    const response = await this.client.post('/annotations', annotation);

    if (response.success) {
      const annotationId = response.data?.annotation?.id;
      this.annotations.push(annotationId);
      SIMULATION_STATE.annotations.set(annotationId, {
        ...annotation,
        id: annotationId,
        userId: this.userId,
        createdAt: new Date()
      });
      
      this.log('ANNOTATION_CREATE_SUCCESS', { 
        annotationId, 
        smellType: annotation.smellType 
      });
      return annotationId;
    } else {
      this.log('ANNOTATION_CREATE_FAILED', { 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return null;
    }
  }

  async discoverNearbyAnnotations() {
    this.log('NEARBY_SEARCH_ATTEMPT', { 
      lat: this.lastLocation.latitude.toFixed(6), 
      lng: this.lastLocation.longitude.toFixed(6) 
    });

    const response = await this.client.get(
      `/annotations/nearby?lat=${this.lastLocation.latitude}&lng=${this.lastLocation.longitude}&radius=1000&limit=10`
    );

    if (response.success) {
      const annotations = response.data?.annotations || [];
      this.log('NEARBY_SEARCH_SUCCESS', { count: annotations.length });
      
      // Try to claim rewards from discovered annotations
      for (const annotation of annotations) {
        if (annotation.userId !== this.userId && Math.random() < CONFIG.REWARD_CLAIM_PROBABILITY) {
          await this.claimLBSReward(annotation.id);
          await this.delay(faker.number.int({ min: 500, max: 2000 }));
        }
      }
      
      return annotations;
    } else {
      this.log('NEARBY_SEARCH_FAILED', { 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return [];
    }
  }

  async claimLBSReward(annotationId) {
    this.log('REWARD_CLAIM_ATTEMPT', { annotationId });

    const response = await this.client.post('/lbs/rewards/claim', {
      annotationId,
      location: {
        latitude: this.lastLocation.latitude,
        longitude: this.lastLocation.longitude
      },
      deviceInfo: this.userData.deviceInfo
    });

    if (response.success) {
      const reward = response.data?.reward;
      this.discoveredRewards.push(reward);
      SIMULATION_STATE.rewards.set(`${this.userId}-${annotationId}`, reward);
      
      this.log('REWARD_CLAIM_SUCCESS', { 
        annotationId, 
        amount: reward?.amount || 0 
      });
      return reward;
    } else {
      this.log('REWARD_CLAIM_FAILED', { 
        annotationId, 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return null;
    }
  }

  async processPayment() {
    const paymentInfo = TestDataGenerator.generatePaymentInfo();
    
    // Simulate payment processing (would fail occasionally in real scenarios)
    if (Math.random() > CONFIG.PAYMENT_SUCCESS_RATE) {
      this.log('PAYMENT_FAILED', { 
        amount: paymentInfo.amount, 
        error: 'Simulated payment failure' 
      });
      return false;
    }

    this.log('PAYMENT_ATTEMPT', { 
      amount: paymentInfo.amount, 
      method: paymentInfo.paymentMethod 
    });

    const response = await this.client.post('/payments/process', {
      amount: paymentInfo.amount,
      currency: paymentInfo.currency,
      paymentMethod: paymentInfo.paymentMethod,
      paymentDetails: {
        cardNumber: paymentInfo.cardNumber,
        expiryMonth: paymentInfo.expiryMonth,
        expiryYear: paymentInfo.expiryYear,
        cvv: paymentInfo.cvv
      },
      billingAddress: paymentInfo.billingAddress
    });

    if (response.success) {
      this.log('PAYMENT_SUCCESS', { 
        amount: paymentInfo.amount, 
        transactionId: response.data?.transactionId 
      });
      return true;
    } else {
      this.log('PAYMENT_FAILED', { 
        amount: paymentInfo.amount, 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return false;
    }
  }

  async performSocialInteraction() {
    // Get annotations from other users to interact with
    const response = await this.client.get('/annotations/list?limit=10&sort=recent');
    
    if (response.success) {
      const annotations = response.data?.annotations || [];
      const otherUserAnnotations = annotations.filter(a => a.userId !== this.userId);
      
      if (otherUserAnnotations.length > 0) {
        const annotation = faker.helpers.arrayElement(otherUserAnnotations);
        
        // Randomly like or comment
        if (Math.random() > 0.5) {
          await this.likeAnnotation(annotation.id);
        } else {
          await this.commentOnAnnotation(annotation.id);
        }
      }
    }
  }

  async likeAnnotation(annotationId) {
    this.log('LIKE_ATTEMPT', { annotationId });

    const response = await this.client.post(`/annotations/${annotationId}/like`);

    if (response.success) {
      this.log('LIKE_SUCCESS', { annotationId });
      return true;
    } else {
      this.log('LIKE_FAILED', { 
        annotationId, 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return false;
    }
  }

  async commentOnAnnotation(annotationId) {
    const comment = faker.lorem.sentence();
    this.log('COMMENT_ATTEMPT', { annotationId, comment: comment.substring(0, 50) + '...' });

    const response = await this.client.post(`/annotations/${annotationId}/comments`, {
      content: comment,
      isAnonymous: Math.random() > 0.8
    });

    if (response.success) {
      this.log('COMMENT_SUCCESS', { annotationId });
      return true;
    } else {
      this.log('COMMENT_FAILED', { 
        annotationId, 
        status: response.status, 
        error: response.data?.message || response.error 
      });
      return false;
    }
  }

  async delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async simulateUserJourney() {
    this.isActive = true;
    
    try {
      // Step 1: Register or Login
      const registrationSuccess = await this.register();
      if (!registrationSuccess) {
        // Try login instead
        const loginSuccess = await this.login();
        if (!loginSuccess) {
          this.log('USER_JOURNEY_FAILED', { reason: 'Authentication failed' });
          return;
        }
      }

      // Step 2: Update location
      await this.updateLocation();
      await this.delay(faker.number.int({ min: 1000, max: 3000 }));

      // Step 3: Create annotations
      const annotationsToCreate = faker.number.int({ min: 1, max: CONFIG.MAX_ANNOTATIONS_PER_USER });
      for (let i = 0; i < annotationsToCreate; i++) {
        await this.createSmellAnnotation();
        await this.delay(faker.number.int({ min: 2000, max: 5000 }));
        
        // Update location occasionally
        if (Math.random() > 0.7) {
          await this.updateLocation();
          await this.delay(faker.number.int({ min: 1000, max: 2000 }));
        }
      }

      // Step 4: Discover nearby annotations and claim rewards
      await this.discoverNearbyAnnotations();
      await this.delay(faker.number.int({ min: 1000, max: 3000 }));

      // Step 5: Social interactions
      if (Math.random() > 0.4) {
        await this.performSocialInteraction();
        await this.delay(faker.number.int({ min: 1000, max: 2000 }));
      }

      // Step 6: Process payment (for premium features)
      if (Math.random() > 0.7) {
        await this.processPayment();
      }

      this.log('USER_JOURNEY_COMPLETED', { 
        annotationsCreated: this.annotations.length, 
        rewardsDiscovered: this.discoveredRewards.length 
      });

    } catch (error) {
      this.log('USER_JOURNEY_ERROR', { error: error.message });
    } finally {
      this.isActive = false;
    }
  }
}

/**
 * Main Simulation Controller
 */
class SimulationController {
  constructor() {
    this.users = [];
    this.activeSimulations = new Set();
    this.reportGenerator = new ReportGenerator();
  }

  async initialize() {
    console.log('\n🚀 Initializing SmellPin User Simulation System...\n');
    
    // Check API connectivity
    const healthCheck = await this.checkAPIHealth();
    if (!healthCheck) {
      console.error('❌ API Health check failed. Ensure the backend is running on', CONFIG.API_BASE_URL);
      process.exit(1);
    }

    console.log(`✅ API Health check passed`);
    console.log(`👥 Preparing ${CONFIG.CONCURRENT_USERS} concurrent users`);
    console.log(`⏱️  Test duration: ${CONFIG.TEST_DURATION_MINUTES} minutes`);
    console.log(`🌍 Geographic zones: ${CONFIG.GPS_BOUNDS.ZONES.map(z => z.name).join(', ')}\n`);

    // Generate users
    for (let i = 0; i < CONFIG.CONCURRENT_USERS; i++) {
      const userData = TestDataGenerator.generateUser();
      const userSimulator = new UserSimulator(userData);
      this.users.push(userSimulator);
    }

    SIMULATION_STATE.startTime = Date.now();
  }

  async checkAPIHealth() {
    try {
      const client = new HTTPClient(CONFIG.API_BASE_URL);
      const response = await client.get('/health');
      return response.success;
    } catch (error) {
      console.error('Health check error:', error.message);
      return false;
    }
  }

  async runSimulation() {
    console.log('🎬 Starting concurrent user simulation...\n');

    const promises = this.users.map((user, index) => {
      return this.runUserSimulation(user, index);
    });

    // Monitor progress
    const progressInterval = setInterval(() => {
      const activeCount = Array.from(this.activeSimulations).length;
      performanceMonitor.updateConcurrentUsers(activeCount);
      
      console.log(`📊 Active users: ${activeCount}/${CONFIG.CONCURRENT_USERS} | ` +
                  `Requests: ${SIMULATION_STATE.performance.requests} | ` +
                  `Failures: ${SIMULATION_STATE.performance.failures}`);
    }, 10000);

    // Wait for all simulations to complete or timeout
    const timeoutPromise = new Promise(resolve => {
      setTimeout(resolve, CONFIG.TEST_DURATION_MINUTES * 60 * 1000);
    });

    await Promise.race([
      Promise.allSettled(promises),
      timeoutPromise
    ]);

    clearInterval(progressInterval);
    SIMULATION_STATE.endTime = Date.now();

    console.log('\n✅ User simulation completed\n');
  }

  async runUserSimulation(user, index) {
    // Stagger user starts to simulate realistic traffic patterns
    const startDelay = faker.number.int({ min: 0, max: 30000 });
    await new Promise(resolve => setTimeout(resolve, startDelay));

    this.activeSimulations.add(user.userId || `user-${index}`);
    
    try {
      await user.simulateUserJourney();
    } catch (error) {
      console.error(`User simulation error for ${user.userData.username}:`, error);
    } finally {
      this.activeSimulations.delete(user.userId || `user-${index}`);
    }
  }

  async generateReport() {
    console.log('📊 Generating comprehensive test report...\n');

    const report = this.reportGenerator.generateFullReport(
      performanceMonitor.generateReport(),
      this.users,
      SIMULATION_STATE
    );

    // Save report to file
    const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
    const reportFileName = `smellpin-simulation-report-${timestamp}.json`;
    const reportPath = path.join(__dirname, 'test-reports', reportFileName);

    // Ensure reports directory exists
    const reportsDir = path.join(__dirname, 'test-reports');
    if (!fs.existsSync(reportsDir)) {
      fs.mkdirSync(reportsDir, { recursive: true });
    }

    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
    SIMULATION_STATE.reportPath = reportPath;

    // Generate HTML report
    const htmlReport = this.reportGenerator.generateHTMLReport(report);
    const htmlReportPath = path.join(__dirname, 'test-reports', 
      reportFileName.replace('.json', '.html'));
    fs.writeFileSync(htmlReportPath, htmlReport);

    console.log(`💾 Detailed JSON report saved: ${reportPath}`);
    console.log(`📄 HTML report saved: ${htmlReportPath}`);
    
    // Print summary to console
    this.printSummary(report);

    return report;
  }

  printSummary(report) {
    const { performance, userJourneyStats, businessMetrics } = report;

    console.log('📈 SIMULATION RESULTS SUMMARY');
    console.log('=' .repeat(50));
    console.log(`🎯 Test Duration: ${performance.summary.testDuration}`);
    console.log(`👥 Concurrent Users: ${performance.summary.peakConcurrentUsers}`);
    console.log(`📨 Total Requests: ${performance.summary.totalRequests}`);
    console.log(`✅ Success Rate: ${performance.summary.successRate}`);
    console.log(`⚡ Avg Response Time: ${performance.summary.avgResponseTime}`);
    console.log(`📍 Annotations Created: ${businessMetrics.totalAnnotations}`);
    console.log(`🎁 Rewards Claimed: ${businessMetrics.totalRewards}`);
    console.log(`💳 Payments Processed: ${businessMetrics.totalPayments}`);
    console.log(`👍 Social Interactions: ${businessMetrics.totalLikes + businessMetrics.totalComments}`);

    if (performance.errorAnalysis.length > 0) {
      console.log('\n❌ TOP ERRORS:');
      performance.errorAnalysis.slice(0, 5).forEach(error => {
        console.log(`   ${error.errorType}: ${error.count} occurrences`);
      });
    }

    console.log('\n🏆 TOP PERFORMING ENDPOINTS:');
    performance.endpointStats.slice(0, 5).forEach(endpoint => {
      console.log(`   ${endpoint.endpoint}: ${endpoint.requests} requests, ` +
                  `${endpoint.avgResponseTime} avg, ${endpoint.failureRate} failures`);
    });

    console.log('=' .repeat(50));

    // Performance recommendations
    this.printRecommendations(report);
  }

  printRecommendations(report) {
    console.log('\n💡 PERFORMANCE RECOMMENDATIONS:');
    console.log('-' .repeat(40));

    const { performance } = report;
    const avgResponseTime = parseFloat(performance.summary.avgResponseTime);
    const successRate = parseFloat(performance.summary.successRate);

    if (avgResponseTime > 1000) {
      console.log('⚠️  High response times detected. Consider:');
      console.log('   • Database query optimization');
      console.log('   • Adding database indexes');
      console.log('   • Implementing caching layers');
      console.log('   • Database connection pooling optimization');
    }

    if (successRate < 95) {
      console.log('⚠️  Low success rate detected. Consider:');
      console.log('   • Reviewing error logs for common failures');
      console.log('   • Improving input validation');
      console.log('   • Adding proper error handling');
      console.log('   • Implementing circuit breakers for external services');
    }

    const highErrorEndpoints = performance.endpointStats
      .filter(e => parseFloat(e.failureRate) > 5)
      .slice(0, 3);

    if (highErrorEndpoints.length > 0) {
      console.log('⚠️  High error rate endpoints:');
      highErrorEndpoints.forEach(endpoint => {
        console.log(`   • ${endpoint.endpoint}: ${endpoint.failureRate} failure rate`);
      });
    }

    console.log('-' .repeat(40));
  }
}

/**
 * Report Generator
 */
class ReportGenerator {
  generateFullReport(performanceReport, users, simulationState) {
    const userJourneyStats = this.analyzeUserJourneys(users);
    const businessMetrics = this.calculateBusinessMetrics(simulationState);
    const systemHealth = this.assessSystemHealth(performanceReport);

    return {
      metadata: {
        testName: 'SmellPin Comprehensive User Simulation',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        configuration: {
          concurrentUsers: CONFIG.CONCURRENT_USERS,
          testDurationMinutes: CONFIG.TEST_DURATION_MINUTES,
          apiBaseUrl: CONFIG.API_BASE_URL,
          maxAnnotationsPerUser: CONFIG.MAX_ANNOTATIONS_PER_USER
        }
      },
      performance: performanceReport,
      userJourneyStats,
      businessMetrics,
      systemHealth,
      recommendations: this.generateRecommendations(performanceReport, businessMetrics),
      rawData: {
        users: users.map(u => ({
          username: u.userData.username,
          annotations: u.annotations.length,
          rewards: u.discoveredRewards.length,
          activityLog: u.activityLog
        }))
      }
    };
  }

  analyzeUserJourneys(users) {
    const stats = {
      totalUsers: users.length,
      successfulRegistrations: 0,
      successfulLogins: 0,
      averageAnnotationsPerUser: 0,
      averageRewardsPerUser: 0,
      completedJourneys: 0,
      failedJourneys: 0,
      journeyCompletionRate: 0
    };

    users.forEach(user => {
      const log = user.activityLog;
      const hasSuccessfulReg = log.some(entry => entry.action === 'REGISTER_SUCCESS');
      const hasSuccessfulLogin = log.some(entry => entry.action === 'LOGIN_SUCCESS');
      const hasCompletedJourney = log.some(entry => entry.action === 'USER_JOURNEY_COMPLETED');

      if (hasSuccessfulReg) stats.successfulRegistrations++;
      if (hasSuccessfulLogin) stats.successfulLogins++;
      if (hasCompletedJourney) stats.completedJourneys++;
      else stats.failedJourneys++;

      stats.averageAnnotationsPerUser += user.annotations.length;
      stats.averageRewardsPerUser += user.discoveredRewards.length;
    });

    stats.averageAnnotationsPerUser /= users.length;
    stats.averageRewardsPerUser /= users.length;
    stats.journeyCompletionRate = (stats.completedJourneys / users.length) * 100;

    return stats;
  }

  calculateBusinessMetrics(simulationState) {
    return {
      totalAnnotations: simulationState.annotations.size,
      totalRewards: simulationState.rewards.size,
      totalUsers: simulationState.users.size,
      totalPayments: Array.from(simulationState.users.values())
        .reduce((sum, user) => sum + user.activityLog
          .filter(entry => entry.action === 'PAYMENT_SUCCESS').length, 0),
      totalLikes: Array.from(simulationState.users.values())
        .reduce((sum, user) => sum + user.activityLog
          .filter(entry => entry.action === 'LIKE_SUCCESS').length, 0),
      totalComments: Array.from(simulationState.users.values())
        .reduce((sum, user) => sum + user.activityLog
          .filter(entry => entry.action === 'COMMENT_SUCCESS').length, 0),
      geographicDistribution: this.calculateGeographicStats(simulationState.annotations)
    };
  }

  calculateGeographicStats(annotations) {
    const zoneStats = {};
    
    Array.from(annotations.values()).forEach(annotation => {
      // Find which zone this annotation belongs to
      const zone = CONFIG.GPS_BOUNDS.ZONES.find(z => {
        const distance = Math.sqrt(
          Math.pow(annotation.latitude - z.lat, 2) + 
          Math.pow(annotation.longitude - z.lng, 2)
        );
        return distance <= z.radius;
      });

      const zoneName = zone ? zone.name : 'Other';
      zoneStats[zoneName] = (zoneStats[zoneName] || 0) + 1;
    });

    return zoneStats;
  }

  assessSystemHealth(performanceReport) {
    const avgResponseTime = parseFloat(performanceReport.summary.avgResponseTime);
    const successRate = parseFloat(performanceReport.summary.successRate);
    const totalRequests = performanceReport.summary.totalRequests;

    let healthScore = 100;
    let status = 'excellent';
    const issues = [];

    if (avgResponseTime > 2000) {
      healthScore -= 30;
      issues.push('Very high response times');
    } else if (avgResponseTime > 1000) {
      healthScore -= 15;
      issues.push('High response times');
    }

    if (successRate < 90) {
      healthScore -= 40;
      issues.push('Low success rate');
    } else if (successRate < 95) {
      healthScore -= 20;
      issues.push('Moderate success rate');
    }

    if (totalRequests < 100) {
      healthScore -= 10;
      issues.push('Low traffic volume');
    }

    if (healthScore >= 90) status = 'excellent';
    else if (healthScore >= 75) status = 'good';
    else if (healthScore >= 60) status = 'fair';
    else status = 'poor';

    return {
      healthScore,
      status,
      issues,
      recommendations: issues.length > 0 ? [
        'Review performance bottlenecks',
        'Optimize database queries',
        'Implement caching strategies',
        'Review error handling'
      ] : ['System performing well']
    };
  }

  generateRecommendations(performanceReport, businessMetrics) {
    const recommendations = [];

    // Performance recommendations
    const avgResponseTime = parseFloat(performanceReport.summary.avgResponseTime);
    if (avgResponseTime > 1000) {
      recommendations.push({
        category: 'Performance',
        priority: 'High',
        recommendation: 'Optimize slow API endpoints and database queries'
      });
    }

    // Business recommendations
    if (businessMetrics.totalAnnotations < CONFIG.CONCURRENT_USERS) {
      recommendations.push({
        category: 'Business',
        priority: 'Medium',
        recommendation: 'Improve user onboarding to increase annotation creation rates'
      });
    }

    // Error handling recommendations
    if (performanceReport.errorAnalysis.length > 0) {
      recommendations.push({
        category: 'Reliability',
        priority: 'High',
        recommendation: 'Address common error patterns to improve system stability'
      });
    }

    return recommendations;
  }

  generateHTMLReport(report) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmellPin User Simulation Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2563eb; color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .content { padding: 30px; }
        .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric-card { background: #f8fafc; border-left: 4px solid #2563eb; padding: 20px; border-radius: 4px; }
        .metric-value { font-size: 2em; font-weight: bold; color: #1e40af; }
        .metric-label { color: #64748b; margin-top: 5px; }
        .status-excellent { color: #16a34a; }
        .status-good { color: #2563eb; }
        .status-fair { color: #d97706; }
        .status-poor { color: #dc2626; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background: #f8fafc; font-weight: 600; }
        .chart-placeholder { background: #f8fafc; border: 2px dashed #cbd5e1; height: 200px; display: flex; align-items: center; justify-content: center; margin: 20px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌍 SmellPin User Simulation Report</h1>
            <p>Generated: ${report.metadata.timestamp}</p>
            <p>Test Configuration: ${report.metadata.configuration.concurrentUsers} users, ${report.metadata.configuration.testDurationMinutes} minutes</p>
        </div>
        
        <div class="content">
            <h2>📊 Performance Summary</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">${report.performance.summary.totalRequests}</div>
                    <div class="metric-label">Total Requests</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.performance.summary.successRate}</div>
                    <div class="metric-label">Success Rate</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.performance.summary.avgResponseTime}</div>
                    <div class="metric-label">Avg Response Time</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value status-${report.systemHealth.status}">${report.systemHealth.status.toUpperCase()}</div>
                    <div class="metric-label">System Health (${report.systemHealth.healthScore}/100)</div>
                </div>
            </div>

            <h2>🎯 Business Metrics</h2>
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value">${report.businessMetrics.totalAnnotations}</div>
                    <div class="metric-label">Smell Annotations</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.businessMetrics.totalRewards}</div>
                    <div class="metric-label">Rewards Claimed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.businessMetrics.totalPayments}</div>
                    <div class="metric-label">Payments Processed</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">${report.businessMetrics.totalLikes + report.businessMetrics.totalComments}</div>
                    <div class="metric-label">Social Interactions</div>
                </div>
            </div>

            <h2>🔥 Top Performing Endpoints</h2>
            <table>
                <thead>
                    <tr><th>Endpoint</th><th>Requests</th><th>Avg Response Time</th><th>Failure Rate</th></tr>
                </thead>
                <tbody>
                    ${report.performance.endpointStats.slice(0, 10).map(endpoint => 
                        `<tr><td>${endpoint.endpoint}</td><td>${endpoint.requests}</td><td>${endpoint.avgResponseTime}</td><td>${endpoint.failureRate}</td></tr>`
                    ).join('')}
                </tbody>
            </table>

            ${report.performance.errorAnalysis.length > 0 ? `
                <h2>❌ Error Analysis</h2>
                <table>
                    <thead>
                        <tr><th>Error Type</th><th>Count</th><th>Percentage</th></tr>
                    </thead>
                    <tbody>
                        ${report.performance.errorAnalysis.slice(0, 10).map(error => 
                            `<tr><td>${error.errorType}</td><td>${error.count}</td><td>${((error.count / report.performance.summary.totalRequests) * 100).toFixed(2)}%</td></tr>`
                        ).join('')}
                    </tbody>
                </table>
            ` : ''}

            <h2>💡 Recommendations</h2>
            ${report.recommendations.length > 0 ? 
                report.recommendations.map(rec => 
                    `<div class="metric-card"><strong>${rec.category} (${rec.priority} Priority):</strong> ${rec.recommendation}</div>`
                ).join('') 
                : '<p>✅ No specific recommendations - system performing well!</p>'
            }

            <h2>🌍 Geographic Distribution</h2>
            <table>
                <thead>
                    <tr><th>Location Zone</th><th>Annotations</th></tr>
                </thead>
                <tbody>
                    ${Object.entries(report.businessMetrics.geographicDistribution).map(([zone, count]) => 
                        `<tr><td>${zone}</td><td>${count}</td></tr>`
                    ).join('')}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>`;
  }
}

/**
 * Main execution function
 */
async function runComprehensiveUserSimulation() {
  try {
    console.log('🎯 SmellPin Comprehensive User Simulation System');
    console.log('================================================\n');

    const controller = new SimulationController();
    
    // Initialize simulation
    await controller.initialize();
    
    // Run simulation
    await controller.runSimulation();
    
    // Generate comprehensive report
    const report = await controller.generateReport();
    
    console.log('\n🎉 Simulation completed successfully!');
    console.log(`📊 Full report available at: ${SIMULATION_STATE.reportPath}`);

    // Exit with appropriate code based on results
    const healthScore = report.systemHealth.healthScore;
    if (healthScore >= 75) {
      console.log('✅ System health is good - tests passed');
      process.exit(0);
    } else {
      console.log('⚠️  System health concerns detected - review recommendations');
      process.exit(1);
    }

  } catch (error) {
    console.error('💥 Simulation failed:', error);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Simulation interrupted by user');
  if (SIMULATION_STATE.reportPath) {
    console.log(`📊 Partial results saved to: ${SIMULATION_STATE.reportPath}`);
  }
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled Promise Rejection:', reason);
  process.exit(1);
});

// Export for potential use as module
module.exports = {
  runComprehensiveUserSimulation,
  SimulationController,
  UserSimulator,
  TestDataGenerator,
  PerformanceMonitor,
  CONFIG
};

// Run simulation if called directly
if (require.main === module) {
  runComprehensiveUserSimulation();
}