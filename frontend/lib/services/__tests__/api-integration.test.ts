import { annotationApi, lbsApi, geocodingApi } from '../api';
import { apiClient } from '../../api';

// Mock API client
jest.mock('../../api', () => ({
  apiClient: {
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn()
  }
}));

const mockApiClient = apiClient as jest.Mocked<typeof apiClient>;

describe('Map API Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Annotation API Integration', () => {
    describe('getMapAnnotations', () => {
      it('should fetch annotations within bounds', async () => {
        const mockAnnotations = [
          {
            id: '1',
            title: '臭豆腐摊位',
            latitude: 39.9042,
            longitude: 116.4074,
            rewardAmount: 15,
            description: '正宗臭豆腐'
          },
          {
            id: '2',
            title: '垃圾站',
            latitude: 39.9052,
            longitude: 116.4084,
            rewardAmount: 10,
            description: '注意异味'
          }
        ];

        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: mockAnnotations }
        });

        const bounds = {
          north: 39.91,
          south: 39.90,
          east: 116.42,
          west: 116.40
        };

        const result = await annotationApi.getMapAnnotations(bounds);

        expect(mockApiClient.get).toHaveBeenCalledWith('/annotations/map', {
          params: bounds
        });
        expect(result.data.data).toHaveLength(2);
        expect(result.data.data[0].id).toBe('1');
      });

      it('should fetch all annotations when no bounds provided', async () => {
        const mockAnnotations = [
          { id: '1', title: 'Test 1', latitude: 39.9042, longitude: 116.4074 }
        ];

        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: mockAnnotations }
        });

        const result = await annotationApi.getMapAnnotations();

        expect(mockApiClient.get).toHaveBeenCalledWith('/annotations/map', {
          params: undefined
        });
        expect(result.data.success).toBe(true);
      });

      it('should handle API errors gracefully', async () => {
        mockApiClient.get.mockRejectedValue(new Error('Network error'));

        await expect(
          annotationApi.getMapAnnotations()
        ).rejects.toThrow('Network error');
      });

      it('should handle invalid bounds gracefully', async () => {
        const invalidBounds = {
          north: -100, // Invalid
          south: 100,  // Invalid
          east: 200,   // Invalid
          west: -200   // Invalid
        };

        mockApiClient.get.mockResolvedValue({
          data: { success: false, error: 'Invalid bounds' }
        });

        const result = await annotationApi.getMapAnnotations(invalidBounds);

        expect(result.data.success).toBe(false);
      });
    });

    describe('getNearbyAnnotations', () => {
      it('should fetch nearby annotations within radius', async () => {
        const mockNearbyAnnotations = [
          {
            id: '1',
            title: '附近标注1',
            latitude: 39.9043,
            longitude: 116.4075,
            distance: 50
          }
        ];

        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: mockNearbyAnnotations }
        });

        const result = await annotationApi.getNearbyAnnotations(39.9042, 116.4074, 100);

        expect(mockApiClient.get).toHaveBeenCalledWith('/annotations/nearby', {
          params: {
            latitude: 39.9042,
            longitude: 116.4074,
            radius: 100
          }
        });
        expect(result.data.data[0].distance).toBe(50);
      });

      it('should use default radius when not provided', async () => {
        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: [] }
        });

        await annotationApi.getNearbyAnnotations(39.9042, 116.4074);

        expect(mockApiClient.get).toHaveBeenCalledWith('/annotations/nearby', {
          params: {
            latitude: 39.9042,
            longitude: 116.4074,
            radius: 1000 // Default radius
          }
        });
      });

      it('should handle invalid coordinates', async () => {
        mockApiClient.get.mockRejectedValue({
          response: {
            status: 400,
            data: { error: 'Invalid coordinates' }
          }
        });

        await expect(
          annotationApi.getNearbyAnnotations(200, 200)
        ).rejects.toMatchObject({
          response: {
            status: 400
          }
        });
      });
    });

    describe('createAnnotation', () => {
      it('should create new annotation successfully', async () => {
        const newAnnotation = {
          title: '新标注',
          description: '测试标注描述',
          latitude: 39.9042,
          longitude: 116.4074,
          rewardAmount: 20,
          images: ['image1.jpg', 'image2.jpg']
        };

        const mockResponse = {
          id: 'new-annotation-id',
          ...newAnnotation,
          status: 'pending',
          createdAt: '2023-01-01T00:00:00Z'
        };

        mockApiClient.post.mockResolvedValue({
          data: { success: true, data: mockResponse }
        });

        const result = await annotationApi.createAnnotation(newAnnotation);

        expect(mockApiClient.post).toHaveBeenCalledWith('/annotations', newAnnotation);
        expect(result.data.data.id).toBe('new-annotation-id');
        expect(result.data.data.status).toBe('pending');
      });

      it('should handle validation errors', async () => {
        const invalidAnnotation = {
          title: '',
          description: 'Test',
          latitude: 200, // Invalid
          longitude: 200, // Invalid
          rewardAmount: -5 // Invalid
        };

        mockApiClient.post.mockRejectedValue({
          response: {
            status: 422,
            data: {
              error: 'Validation failed',
              details: ['Title is required', 'Invalid coordinates', 'Reward amount must be positive']
            }
          }
        });

        await expect(
          annotationApi.createAnnotation(invalidAnnotation)
        ).rejects.toMatchObject({
          response: {
            status: 422
          }
        });
      });

      it('should handle authentication errors', async () => {
        const annotation = {
          title: 'Test',
          description: 'Test',
          latitude: 39.9042,
          longitude: 116.4074,
          rewardAmount: 10
        };

        mockApiClient.post.mockRejectedValue({
          response: {
            status: 401,
            data: { error: 'Unauthorized' }
          }
        });

        await expect(
          annotationApi.createAnnotation(annotation)
        ).rejects.toMatchObject({
          response: {
            status: 401
          }
        });
      });
    });

    describe('updateAnnotation', () => {
      it('should update annotation successfully', async () => {
        const updateData = {
          title: '更新的标题',
          description: '更新的描述'
        };

        const updatedAnnotation = {
          id: 'annotation-1',
          ...updateData,
          updatedAt: '2023-01-02T00:00:00Z'
        };

        mockApiClient.put.mockResolvedValue({
          data: { success: true, data: updatedAnnotation }
        });

        const result = await annotationApi.updateAnnotation('annotation-1', updateData);

        expect(mockApiClient.put).toHaveBeenCalledWith('/annotations/annotation-1', updateData);
        expect(result.data.data.title).toBe('更新的标题');
      });

      it('should handle not found errors', async () => {
        mockApiClient.put.mockRejectedValue({
          response: {
            status: 404,
            data: { error: 'Annotation not found' }
          }
        });

        await expect(
          annotationApi.updateAnnotation('nonexistent', { title: 'Test' })
        ).rejects.toMatchObject({
          response: {
            status: 404
          }
        });
      });
    });

    describe('deleteAnnotation', () => {
      it('should delete annotation successfully', async () => {
        mockApiClient.delete.mockResolvedValue({
          data: { success: true, message: 'Annotation deleted' }
        });

        const result = await annotationApi.deleteAnnotation('annotation-1');

        expect(mockApiClient.delete).toHaveBeenCalledWith('/annotations/annotation-1');
        expect(result.data.success).toBe(true);
      });

      it('should handle permission errors', async () => {
        mockApiClient.delete.mockRejectedValue({
          response: {
            status: 403,
            data: { error: 'Permission denied' }
          }
        });

        await expect(
          annotationApi.deleteAnnotation('annotation-1')
        ).rejects.toMatchObject({
          response: {
            status: 403
          }
        });
      });
    });
  });

  describe('LBS API Integration', () => {
    describe('reportLocation', () => {
      it('should report location and get nearby rewards', async () => {
        const mockRewards = [
          {
            id: 'reward-1',
            annotationId: 'annotation-1',
            amount: 15,
            distance: 80
          }
        ];

        mockApiClient.post.mockResolvedValue({
          data: { success: true, data: mockRewards }
        });

        const result = await lbsApi.reportLocation(39.9042, 116.4074);

        expect(mockApiClient.post).toHaveBeenCalledWith('/lbs/report-location', {
          latitude: 39.9042,
          longitude: 116.4074
        });
        expect(result.data.data).toHaveLength(1);
        expect(result.data.data[0].amount).toBe(15);
      });

      it('should handle no nearby rewards', async () => {
        mockApiClient.post.mockResolvedValue({
          data: { success: true, data: [] }
        });

        const result = await lbsApi.reportLocation(40.0000, 117.0000);

        expect(result.data.data).toHaveLength(0);
      });

      it('should handle invalid location data', async () => {
        mockApiClient.post.mockRejectedValue({
          response: {
            status: 400,
            data: { error: 'Invalid location coordinates' }
          }
        });

        await expect(
          lbsApi.reportLocation(NaN, NaN)
        ).rejects.toMatchObject({
          response: {
            status: 400
          }
        });
      });
    });

    describe('claimReward', () => {
      it('should claim reward successfully', async () => {
        const mockClaimedReward = {
          id: 'claim-1',
          annotationId: 'annotation-1',
          amount: 15,
          claimedAt: '2023-01-01T00:00:00Z',
          status: 'approved'
        };

        mockApiClient.post.mockResolvedValue({
          data: { success: true, data: mockClaimedReward }
        });

        const result = await lbsApi.claimReward('annotation-1', 39.9042, 116.4074);

        expect(mockApiClient.post).toHaveBeenCalledWith('/lbs/claim-reward', {
          annotationId: 'annotation-1',
          latitude: 39.9042,
          longitude: 116.4074
        });
        expect(result.data.data.amount).toBe(15);
        expect(result.data.data.status).toBe('approved');
      });

      it('should handle distance validation errors', async () => {
        mockApiClient.post.mockRejectedValue({
          response: {
            status: 400,
            data: { error: 'Too far from annotation location' }
          }
        });

        await expect(
          lbsApi.claimReward('annotation-1', 40.0000, 117.0000)
        ).rejects.toMatchObject({
          response: {
            status: 400
          }
        });
      });

      it('should handle already claimed rewards', async () => {
        mockApiClient.post.mockRejectedValue({
          response: {
            status: 409,
            data: { error: 'Reward already claimed' }
          }
        });

        await expect(
          lbsApi.claimReward('annotation-1', 39.9042, 116.4074)
        ).rejects.toMatchObject({
          response: {
            status: 409
          }
        });
      });

      it('should handle inactive annotations', async () => {
        mockApiClient.post.mockRejectedValue({
          response: {
            status: 404,
            data: { error: 'Annotation not found or inactive' }
          }
        });

        await expect(
          lbsApi.claimReward('inactive-annotation', 39.9042, 116.4074)
        ).rejects.toMatchObject({
          response: {
            status: 404
          }
        });
      });
    });

    describe('getMyRewards', () => {
      it('should fetch user rewards with pagination', async () => {
        const mockRewards = {
          rewards: [
            {
              id: 'reward-1',
              annotationId: 'annotation-1',
              amount: 15,
              claimedAt: '2023-01-01T00:00:00Z'
            },
            {
              id: 'reward-2',
              annotationId: 'annotation-2',
              amount: 20,
              claimedAt: '2023-01-02T00:00:00Z'
            }
          ],
          total: 2,
          page: 1,
          limit: 20
        };

        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: mockRewards }
        });

        const result = await lbsApi.getMyRewards(1, 20);

        expect(mockApiClient.get).toHaveBeenCalledWith('/lbs/rewards/me', {
          params: { page: 1, limit: 20 }
        });
        expect(result.data.data.rewards).toHaveLength(2);
        expect(result.data.data.total).toBe(2);
      });

      it('should use default pagination parameters', async () => {
        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: { rewards: [], total: 0, page: 1, limit: 20 } }
        });

        await lbsApi.getMyRewards();

        expect(mockApiClient.get).toHaveBeenCalledWith('/lbs/rewards/me', {
          params: { page: 1, limit: 20 }
        });
      });
    });
  });

  describe('Geocoding API Integration', () => {
    describe('geocode', () => {
      it('should geocode address successfully', async () => {
        const mockGeocodingResult = {
          latitude: 39.9042,
          longitude: 116.4074,
          address: '北京市东城区东长安街1号'
        };

        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: mockGeocodingResult }
        });

        const result = await geocodingApi.geocode('天安门广场');

        expect(mockApiClient.get).toHaveBeenCalledWith('/geocoding/geocode', {
          params: { address: '天安门广场' }
        });
        expect(result.data.data.latitude).toBe(39.9042);
        expect(result.data.data.longitude).toBe(116.4074);
      });

      it('should handle geocoding failures', async () => {
        mockApiClient.get.mockRejectedValue({
          response: {
            status: 404,
            data: { error: 'Address not found' }
          }
        });

        await expect(
          geocodingApi.geocode('Nonexistent Address')
        ).rejects.toMatchObject({
          response: {
            status: 404
          }
        });
      });

      it('should handle empty address input', async () => {
        mockApiClient.get.mockRejectedValue({
          response: {
            status: 400,
            data: { error: 'Address parameter is required' }
          }
        });

        await expect(
          geocodingApi.geocode('')
        ).rejects.toMatchObject({
          response: {
            status: 400
          }
        });
      });
    });

    describe('reverseGeocode', () => {
      it('should reverse geocode coordinates successfully', async () => {
        const mockReverseResult = {
          address: '北京市东城区东长安街1号',
          components: {
            country: '中国',
            province: '北京市',
            city: '北京市',
            district: '东城区',
            street: '东长安街'
          }
        };

        mockApiClient.get.mockResolvedValue({
          data: { success: true, data: mockReverseResult }
        });

        const result = await geocodingApi.reverseGeocode(39.9042, 116.4074);

        expect(mockApiClient.get).toHaveBeenCalledWith('/geocoding/reverse', {
          params: {
            latitude: 39.9042,
            longitude: 116.4074
          }
        });
        expect(result.data.data.address).toBe('北京市东城区东长安街1号');
        expect(result.data.data.components.country).toBe('中国');
      });

      it('should handle invalid coordinates', async () => {
        mockApiClient.get.mockRejectedValue({
          response: {
            status: 400,
            data: { error: 'Invalid coordinates' }
          }
        });

        await expect(
          geocodingApi.reverseGeocode(200, 200)
        ).rejects.toMatchObject({
          response: {
            status: 400
          }
        });
      });

      it('should handle coordinates in remote areas', async () => {
        mockApiClient.get.mockResolvedValue({
          data: {
            success: true,
            data: {
              address: 'Remote area coordinates',
              components: {}
            }
          }
        });

        const result = await geocodingApi.reverseGeocode(85.0000, 179.0000);

        expect(result.data.success).toBe(true);
        expect(result.data.data.address).toBe('Remote area coordinates');
      });
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle network timeouts', async () => {
      const timeoutError = new Error('Request timeout');
      timeoutError.name = 'ECONNABORTED';
      
      mockApiClient.get.mockRejectedValue(timeoutError);

      await expect(
        annotationApi.getMapAnnotations()
      ).rejects.toThrow('Request timeout');
    });

    it('should handle server errors', async () => {
      mockApiClient.get.mockRejectedValue({
        response: {
          status: 500,
          data: { error: 'Internal server error' }
        }
      });

      await expect(
        annotationApi.getMapAnnotations()
      ).rejects.toMatchObject({
        response: {
          status: 500
        }
      });
    });

    it('should handle rate limiting', async () => {
      mockApiClient.post.mockRejectedValue({
        response: {
          status: 429,
          data: { error: 'Too many requests' },
          headers: {
            'retry-after': '60'
          }
        }
      });

      await expect(
        lbsApi.reportLocation(39.9042, 116.4074)
      ).rejects.toMatchObject({
        response: {
          status: 429
        }
      });
    });

    it('should handle malformed responses', async () => {
      mockApiClient.get.mockResolvedValue({
        data: 'invalid json'
      });

      const result = await annotationApi.getMapAnnotations();
      
      // Should handle malformed response gracefully
      expect(result.data).toBe('invalid json');
    });

    it('should handle network connectivity issues', async () => {
      const networkError = new Error('Network Error');
      networkError.name = 'NetworkError';
      
      mockApiClient.get.mockRejectedValue(networkError);

      await expect(
        geocodingApi.geocode('test address')
      ).rejects.toThrow('Network Error');
    });
  });

  describe('Performance and Load Testing', () => {
    it('should handle concurrent API requests', async () => {
      const mockResponse = {
        data: { success: true, data: [] }
      };

      mockApiClient.get.mockResolvedValue(mockResponse);

      // Make 10 concurrent requests
      const requests = Array.from({ length: 10 }, () =>
        annotationApi.getMapAnnotations()
      );

      const results = await Promise.all(requests);

      expect(results).toHaveLength(10);
      expect(mockApiClient.get).toHaveBeenCalledTimes(10);
    });

    it('should measure response times', async () => {
      mockApiClient.get.mockImplementation(() =>
        new Promise(resolve =>
          setTimeout(() => resolve({ data: { success: true, data: [] } }), 100)
        )
      );

      const startTime = Date.now();
      await annotationApi.getMapAnnotations();
      const endTime = Date.now();

      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });

    it('should handle large datasets', async () => {
      const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
        id: `annotation-${i}`,
        title: `标注 ${i}`,
        latitude: 39.9042 + (i * 0.001),
        longitude: 116.4074 + (i * 0.001),
        rewardAmount: Math.floor(Math.random() * 50) + 5
      }));

      mockApiClient.get.mockResolvedValue({
        data: { success: true, data: largeDataset }
      });

      const result = await annotationApi.getMapAnnotations();

      expect(result.data.data).toHaveLength(1000);
    });
  });
});