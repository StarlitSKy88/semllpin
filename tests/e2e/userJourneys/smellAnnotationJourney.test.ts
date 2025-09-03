import request from 'supertest';
import { app } from '../../../src/server';
import { db } from '../../../src/config/database';
import { v4 as uuidv4 } from 'uuid';

describe('E2E: Smell Annotation User Journey', () => {
  let authToken: string;
  let userId: string;
  let annotationId: string;
  let testUser: any;

  beforeAll(async () => {
    // Setup test database connection
    await db.raw('SELECT 1');
    
    // Create test user
    testUser = {
      id: uuidv4(),
      email: `test-${Date.now()}@example.com`,
      username: `testuser${Date.now()}`,
      password: 'TestPassword123!',
    };
  });

  afterAll(async () => {
    // Cleanup test data
    if (userId) {
      await db('users').where('id', userId).del();
      await db('annotations').where('user_id', userId).del();
      await db('lbs_rewards').where('user_id', userId).del();
      await db('payments').where('userId', userId).del();
    }
    
    // Close database connection
    await db.destroy();
  });

  describe('User Registration and Authentication', () => {
    it('should register a new user successfully', async () => {
      const response = await request(app)
        .post('/api/auth/register')
        .send({
          email: testUser.email,
          username: testUser.username,
          password: testUser.password,
        })
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        user: {
          email: testUser.email,
          username: testUser.username,
        },
      });

      userId = response.body.user.id;
      expect(userId).toBeDefined();
    });

    it('should login user and get authentication token', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        })
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        token: expect.any(String),
        user: {
          id: userId,
          email: testUser.email,
        },
      });

      authToken = response.body.token;
      expect(authToken).toBeDefined();
    });
  });

  describe('Smell Annotation Creation Flow', () => {
    const annotationData = {
      latitude: 39.9042,
      longitude: 116.4074,
      smellType: 'chemical',
      intensity: 7,
      description: 'Strong chemical smell near factory area',
      tags: ['industrial', 'chemical', 'pollution'],
      amount: 50.00,
    };

    it('should create smell annotation successfully', async () => {
      const response = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(annotationData)
        .expect(201);

      expect(response.body).toMatchObject({
        success: true,
        annotation: {
          latitude: annotationData.latitude,
          longitude: annotationData.longitude,
          smellType: annotationData.smellType,
          intensity: annotationData.intensity,
          description: annotationData.description,
          amount: annotationData.amount,
          status: 'active',
        },
      });

      annotationId = response.body.annotation.id;
      expect(annotationId).toBeDefined();
    });

    it('should validate annotation data properly', async () => {
      const invalidData = {
        ...annotationData,
        latitude: 200, // Invalid latitude
        intensity: 15, // Invalid intensity (should be 1-10)
        amount: -10, // Invalid negative amount
      };

      const response = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(invalidData)
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        errors: expect.any(Array),
      });

      expect(response.body.errors).toEqual(
        expect.arrayContaining([
          expect.stringContaining('latitude'),
          expect.stringContaining('intensity'),
          expect.stringContaining('amount'),
        ])
      );
    });

    it('should require authentication for annotation creation', async () => {
      const response = await request(app)
        .post('/api/annotations')
        .send(annotationData)
        .expect(401);

      expect(response.body).toMatchObject({
        success: false,
        message: expect.stringContaining('authentication'),
      });
    });
  });

  describe('LBS Reward Discovery Flow', () => {
    const mockLocationData = {
      latitude: 39.9042,
      longitude: 116.4074,
      accuracy: 10,
      stayDuration: 60,
      deviceInfo: {
        platform: 'iOS',
        version: '14.0',
        deviceId: 'test-device-123',
      },
    };

    it('should check for nearby annotations', async () => {
      const response = await request(app)
        .post('/api/lbs/nearby')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          latitude: mockLocationData.latitude,
          longitude: mockLocationData.longitude,
          radius: 100, // 100 meters
        })
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        annotations: expect.any(Array),
      });

      // Should find our created annotation
      const foundAnnotation = response.body.annotations.find(
        (ann: any) => ann.id === annotationId
      );
      expect(foundAnnotation).toBeDefined();
    });

    it('should attempt to claim LBS reward', async () => {
      const response = await request(app)
        .post('/api/lbs/claim-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId,
          locationData: mockLocationData,
          rewardType: 'first_finder',
        })
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        reward: {
          annotationId,
          userId,
          rewardType: 'first_finder',
          status: expect.stringMatching(/pending|verified/),
          amount: expect.any(Number),
        },
      });

      expect(response.body.reward.amount).toBeGreaterThan(0);
    });

    it('should prevent duplicate reward claims', async () => {
      // Try to claim the same reward again
      const response = await request(app)
        .post('/api/lbs/claim-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId,
          locationData: mockLocationData,
          rewardType: 'first_finder',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        message: expect.stringContaining('已获得'),
      });
    });

    it('should reject reward claim with poor GPS accuracy', async () => {
      // Create another annotation for testing
      const newAnnotationResponse = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          latitude: 39.9050,
          longitude: 116.4080,
          smellType: 'sewage',
          intensity: 6,
          description: 'Sewage smell',
          amount: 30.00,
        })
        .expect(201);

      const newAnnotationId = newAnnotationResponse.body.annotation.id;

      const response = await request(app)
        .post('/api/lbs/claim-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: newAnnotationId,
          locationData: {
            ...mockLocationData,
            latitude: 39.9050,
            longitude: 116.4080,
            accuracy: 100, // Poor accuracy
          },
          rewardType: 'first_finder',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        message: expect.stringContaining('精度'),
      });
    });
  });

  describe('Payment Processing Flow', () => {
    let paymentId: string;

    it('should create payment session for annotation', async () => {
      const response = await request(app)
        .post('/api/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId,
          amount: 50.00,
          currency: 'USD',
          paymentMethod: 'stripe',
        })
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        session: {
          id: expect.any(String),
          url: expect.stringContaining('stripe'),
        },
        payment: {
          id: expect.any(String),
          userId,
          annotationId,
          amount: 50.00,
          status: 'pending',
        },
      });

      paymentId = response.body.payment.id;
    });

    it('should handle payment success webhook', async () => {
      const webhookData = {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_test_session_123',
            payment_intent: 'pi_test_intent_123',
            payment_status: 'paid',
            amount_total: 5000, // Stripe uses cents
            metadata: {
              paymentId,
              userId,
              annotationId,
            },
          },
        },
      };

      const response = await request(app)
        .post('/api/webhooks/stripe')
        .send(webhookData)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
      });

      // Verify payment was updated
      const paymentResponse = await request(app)
        .get(`/api/payments/${paymentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(paymentResponse.body.payment.status).toBe('completed');
    });

    it('should handle payment failure', async () => {
      // Create another payment for testing failure
      const failurePaymentResponse = await request(app)
        .post('/api/payments/create-session')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId,
          amount: 25.00,
          currency: 'USD',
          paymentMethod: 'stripe',
        })
        .expect(200);

      const failurePaymentId = failurePaymentResponse.body.payment.id;

      const failureWebhookData = {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_test_session_failed',
            payment_intent: 'pi_test_intent_failed',
            payment_status: 'failed',
            amount_total: 2500,
            metadata: {
              paymentId: failurePaymentId,
              userId,
              annotationId,
            },
          },
        },
      };

      await request(app)
        .post('/api/webhooks/stripe')
        .send(failureWebhookData)
        .expect(200);

      // Verify payment was marked as failed
      const failedPaymentResponse = await request(app)
        .get(`/api/payments/${failurePaymentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(failedPaymentResponse.body.payment.status).toBe('failed');
    });

    it('should get user payment history', async () => {
      const response = await request(app)
        .get('/api/payments/user-history')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        payments: expect.any(Array),
        total: expect.any(Number),
      });

      expect(response.body.payments.length).toBeGreaterThan(0);
      expect(response.body.payments.every((p: any) => p.userId === userId)).toBe(true);
    });
  });

  describe('Anti-Fraud Detection Flow', () => {
    it('should detect suspicious location patterns', async () => {
      const suspiciousLocation = {
        latitude: 40.7128, // NYC - very far from previous location
        longitude: -74.0060,
        accuracy: 5,
        stayDuration: 30,
        deviceInfo: {
          platform: 'iOS',
          version: '14.0',
          deviceId: 'test-device-123',
        },
      };

      // Create annotation in NYC
      const nycAnnotationResponse = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          latitude: suspiciousLocation.latitude,
          longitude: suspiciousLocation.longitude,
          smellType: 'chemical',
          intensity: 8,
          description: 'Test annotation in NYC',
          amount: 40.00,
        })
        .expect(201);

      // Try to claim reward immediately (suspicious timing)
      const response = await request(app)
        .post('/api/lbs/claim-reward')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          annotationId: nycAnnotationResponse.body.annotation.id,
          locationData: suspiciousLocation,
          rewardType: 'first_finder',
        })
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        message: expect.stringContaining('suspicious'),
      });
    });

    it('should track user behavior patterns', async () => {
      const response = await request(app)
        .get('/api/users/fraud-history')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        success: true,
        fraudHistory: expect.any(Array),
        riskScore: expect.any(Number),
      });

      expect(response.body.riskScore).toBeGreaterThanOrEqual(0);
      expect(response.body.riskScore).toBeLessThanOrEqual(1);
    });
  });

  describe('Data Consistency and Integrity', () => {
    it('should maintain data consistency across services', async () => {
      // Get user stats
      const statsResponse = await request(app)
        .get('/api/users/stats')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Get user annotations
      const annotationsResponse = await request(app)
        .get('/api/annotations/user')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Get user rewards
      const rewardsResponse = await request(app)
        .get('/api/lbs/user-rewards')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      // Verify consistency
      expect(statsResponse.body.stats.totalAnnotations).toBe(
        annotationsResponse.body.annotations.length
      );

      expect(statsResponse.body.stats.totalRewards).toBe(
        rewardsResponse.body.rewards.length
      );
    });

    it('should handle concurrent requests gracefully', async () => {
      const concurrentRequests = Array(5).fill(0).map((_, i) =>
        request(app)
          .get('/api/annotations/nearby')
          .set('Authorization', `Bearer ${authToken}`)
          .query({
            latitude: 39.9042,
            longitude: 116.4074,
            radius: 500,
          })
      );

      const responses = await Promise.all(concurrentRequests);

      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });
    });
  });

  describe('Performance and Response Times', () => {
    it('should respond to API calls within acceptable time limits', async () => {
      const endpoints = [
        { method: 'get', path: '/api/annotations/nearby', query: { latitude: 39.9042, longitude: 116.4074, radius: 100 } },
        { method: 'get', path: '/api/users/stats' },
        { method: 'get', path: '/api/payments/user-history' },
        { method: 'get', path: '/api/lbs/user-rewards' },
      ];

      for (const endpoint of endpoints) {
        const startTime = Date.now();
        
        let requestBuilder = request(app)[endpoint.method](endpoint.path)
          .set('Authorization', `Bearer ${authToken}`);

        if (endpoint.query) {
          requestBuilder = requestBuilder.query(endpoint.query);
        }

        const response = await requestBuilder.expect(200);
        
        const responseTime = Date.now() - startTime;

        expect(responseTime).toBeLessThan(2000); // Should respond within 2 seconds
        expect(response.body.success).toBe(true);
      }
    });

    it('should handle high-frequency requests without degradation', async () => {
      const startTime = Date.now();
      
      const rapidRequests = Array(20).fill(0).map(() =>
        request(app)
          .get('/api/health')
          .expect(200)
      );

      await Promise.all(rapidRequests);
      
      const totalTime = Date.now() - startTime;
      const averageTime = totalTime / 20;

      expect(averageTime).toBeLessThan(500); // Average response should be under 500ms
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed requests gracefully', async () => {
      const malformedRequests = [
        {
          endpoint: '/api/annotations',
          method: 'post',
          body: { invalid: 'data', latitude: 'not-a-number' },
        },
        {
          endpoint: '/api/lbs/claim-reward',
          method: 'post',
          body: { annotationId: 'invalid-uuid', locationData: null },
        },
        {
          endpoint: '/api/payments/create-session',
          method: 'post',
          body: { amount: 'invalid', currency: 123 },
        },
      ];

      for (const malformedRequest of malformedRequests) {
        const response = await request(app)
          [malformedRequest.method](malformedRequest.endpoint)
          .set('Authorization', `Bearer ${authToken}`)
          .send(malformedRequest.body)
          .expect(400);

        expect(response.body).toMatchObject({
          success: false,
          errors: expect.any(Array),
        });
      }
    });

    it('should handle network timeouts and retries', async () => {
      // Simulate slow network by testing with very large payload
      const largePayload = {
        latitude: 39.9042,
        longitude: 116.4074,
        smellType: 'chemical',
        intensity: 5,
        description: 'x'.repeat(10000), // Large description
        tags: Array(100).fill('tag'),
        amount: 25.00,
      };

      const response = await request(app)
        .post('/api/annotations')
        .set('Authorization', `Bearer ${authToken}`)
        .send(largePayload)
        .timeout(10000); // 10 second timeout

      expect(response.status).toBeLessThan(500); // Should handle gracefully
    });

    it('should maintain service availability during peak load', async () => {
      // Simulate peak load with multiple concurrent operations
      const peakLoadOperations = [
        ...Array(5).fill(0).map(() => 
          request(app)
            .get('/api/annotations/nearby')
            .set('Authorization', `Bearer ${authToken}`)
            .query({ latitude: 39.9042, longitude: 116.4074, radius: 100 })
        ),
        ...Array(3).fill(0).map(() =>
          request(app)
            .get('/api/users/stats')
            .set('Authorization', `Bearer ${authToken}`)
        ),
        ...Array(2).fill(0).map(() =>
          request(app)
            .get('/api/payments/user-history')
            .set('Authorization', `Bearer ${authToken}`)
        ),
      ];

      const results = await Promise.allSettled(peakLoadOperations);
      const successCount = results.filter(r => r.status === 'fulfilled').length;
      const successRate = successCount / results.length;

      expect(successRate).toBeGreaterThan(0.9); // 90% success rate during peak load
    });
  });
});