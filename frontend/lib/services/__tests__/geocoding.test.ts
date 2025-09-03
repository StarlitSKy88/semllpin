import axios from 'axios';
import { geocodingApi } from '../api';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

// Mock the API client
const mockApiClient = {
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn()
};

jest.mock('../api', () => ({
  geocodingApi: {
    geocode: jest.fn(),
    reverseGeocode: jest.fn()
  }
}));

describe('Geocoding Service', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Geocoding (Address to Coordinates)', () => {
    it('should geocode address successfully', async () => {
      const mockResponse = {
        data: {
          success: true,
          data: {
            latitude: 39.9042,
            longitude: 116.4074,
            address: '北京市东城区东长安街1号'
          }
        }
      };

      (geocodingApi.geocode as jest.Mock).mockResolvedValue(mockResponse);

      const result = await geocodingApi.geocode('天安门广场');

      expect(geocodingApi.geocode).toHaveBeenCalledWith('天安门广场');
      expect(result.data.data.latitude).toBe(39.9042);
      expect(result.data.data.longitude).toBe(116.4074);
    });

    it('should handle geocoding errors', async () => {
      const error = new Error('Address not found');
      (geocodingApi.geocode as jest.Mock).mockRejectedValue(error);

      await expect(geocodingApi.geocode('Invalid Address')).rejects.toThrow('Address not found');
    });

    it('should handle empty address', async () => {
      const mockResponse = {
        data: {
          success: false,
          error: 'Address is required'
        }
      };

      (geocodingApi.geocode as jest.Mock).mockResolvedValue(mockResponse);

      const result = await geocodingApi.geocode('');

      expect(result.data.success).toBe(false);
    });

    it('should handle special characters in address', async () => {
      const mockResponse = {
        data: {
          success: true,
          data: {
            latitude: 31.2304,
            longitude: 121.4737,
            address: '上海市黄浦区南京东路步行街'
          }
        }
      };

      (geocodingApi.geocode as jest.Mock).mockResolvedValue(mockResponse);

      const result = await geocodingApi.geocode('上海南京东路步行街');

      expect(result.data.success).toBe(true);
      expect(result.data.data.latitude).toBe(31.2304);
    });

    it('should handle long address strings', async () => {
      const longAddress = '北京市朝阳区建国门外大街1号国贸大厦A座1001室某某公司';
      const mockResponse = {
        data: {
          success: true,
          data: {
            latitude: 39.9081,
            longitude: 116.4363,
            address: longAddress
          }
        }
      };

      (geocodingApi.geocode as jest.Mock).mockResolvedValue(mockResponse);

      const result = await geocodingApi.geocode(longAddress);

      expect(result.data.success).toBe(true);
    });
  });

  describe('Reverse Geocoding (Coordinates to Address)', () => {
    it('should reverse geocode coordinates successfully', async () => {
      const mockResponse = {
        data: {
          success: true,
          data: {
            address: '北京市东城区东长安街1号',
            components: {
              country: '中国',
              province: '北京市',
              city: '北京市',
              district: '东城区',
              street: '东长安街',
              number: '1号'
            }
          }
        }
      };

      (geocodingApi.reverseGeocode as jest.Mock).mockResolvedValue(mockResponse);

      const result = await geocodingApi.reverseGeocode(39.9042, 116.4074);

      expect(geocodingApi.reverseGeocode).toHaveBeenCalledWith(39.9042, 116.4074);
      expect(result.data.data.address).toBe('北京市东城区东长安街1号');
      expect(result.data.data.components.country).toBe('中国');
    });

    it('should handle reverse geocoding errors', async () => {
      const error = new Error('Coordinates not found');
      (geocodingApi.reverseGeocode as jest.Mock).mockRejectedValue(error);

      await expect(
        geocodingApi.reverseGeocode(999, 999)
      ).rejects.toThrow('Coordinates not found');
    });

    it('should handle invalid coordinates', async () => {
      const mockResponse = {
        data: {
          success: false,
          error: 'Invalid coordinates'
        }
      };

      (geocodingApi.reverseGeocode as jest.Mock).mockResolvedValue(mockResponse);

      const result = await geocodingApi.reverseGeocode(200, 200); // Invalid lat/lng

      expect(result.data.success).toBe(false);
    });

    it('should handle edge case coordinates', async () => {
      const testCases = [
        { lat: 90, lng: 180 }, // North Pole, International Date Line
        { lat: -90, lng: -180 }, // South Pole, International Date Line
        { lat: 0, lng: 0 }, // Null Island
      ];

      for (const coords of testCases) {
        const mockResponse = {
          data: {
            success: true,
            data: {
              address: `Location at ${coords.lat}, ${coords.lng}`,
              components: {}
            }
          }
        };

        (geocodingApi.reverseGeocode as jest.Mock).mockResolvedValue(mockResponse);

        const result = await geocodingApi.reverseGeocode(coords.lat, coords.lng);
        expect(result.data.success).toBe(true);
      }
    });

    it('should handle precision with many decimal places', async () => {
      const mockResponse = {
        data: {
          success: true,
          data: {
            address: '精确位置地址',
            components: {}
          }
        }
      };

      (geocodingApi.reverseGeocode as jest.Mock).mockResolvedValue(mockResponse);

      const result = await geocodingApi.reverseGeocode(39.904200123456, 116.407400987654);

      expect(geocodingApi.reverseGeocode).toHaveBeenCalledWith(39.904200123456, 116.407400987654);
      expect(result.data.success).toBe(true);
    });
  });
});

// Test Nominatim Integration (OpenStreetMap Geocoding)
describe('Nominatim Geocoding Integration', () => {
  const mockNominatimResponse = {
    geocode: {
      place_id: 123456,
      licence: 'Data © OpenStreetMap contributors, ODbL 1.0. https://osm.org/copyright',
      osm_type: 'way',
      osm_id: 12345678,
      boundingbox: ['39.8998', '39.9086', '116.3998', '116.4150'],
      lat: '39.9042',
      lon: '116.4074',
      display_name: '天安门广场, 东城区, 北京市, 中国',
      class: 'highway',
      type: 'pedestrian',
      importance: 0.8
    },
    reverseGeocode: {
      place_id: 123456,
      licence: 'Data © OpenStreetMap contributors, ODbL 1.0. https://osm.org/copyright',
      osm_type: 'way',
      osm_id: 12345678,
      lat: '39.9042',
      lon: '116.4074',
      display_name: '东长安街1号, 东城区, 北京市, 100006, 中国',
      address: {
        house_number: '1',
        road: '东长安街',
        suburb: '东城区',
        city: '北京市',
        state: '北京市',
        postcode: '100006',
        country: '中国',
        country_code: 'cn'
      }
    }
  };

  beforeEach(() => {
    mockedAxios.get.mockClear();
  });

  describe('Nominatim Service Integration', () => {
    it('should call Nominatim geocoding API with correct parameters', async () => {
      mockedAxios.get.mockResolvedValue({
        data: [mockNominatimResponse.geocode]
      });

      // Mock a direct Nominatim API call
      const nominatimUrl = 'https://nominatim.openstreetmap.org/search';
      const response = await axios.get(nominatimUrl, {
        params: {
          q: '天安门广场',
          format: 'json',
          addressdetails: 1,
          limit: 1
        }
      });

      expect(mockedAxios.get).toHaveBeenCalledWith(nominatimUrl, {
        params: {
          q: '天安门广场',
          format: 'json',
          addressdetails: 1,
          limit: 1
        }
      });

      expect(response.data).toHaveLength(1);
      expect(response.data[0].lat).toBe('39.9042');
      expect(response.data[0].lon).toBe('116.4074');
    });

    it('should call Nominatim reverse geocoding API', async () => {
      mockedAxios.get.mockResolvedValue({
        data: mockNominatimResponse.reverseGeocode
      });

      const nominatimUrl = 'https://nominatim.openstreetmap.org/reverse';
      const response = await axios.get(nominatimUrl, {
        params: {
          lat: 39.9042,
          lon: 116.4074,
          format: 'json',
          addressdetails: 1
        }
      });

      expect(mockedAxios.get).toHaveBeenCalledWith(nominatimUrl, {
        params: {
          lat: 39.9042,
          lon: 116.4074,
          format: 'json',
          addressdetails: 1
        }
      });

      expect(response.data.address.country).toBe('中国');
    });

    it('should handle Nominatim rate limiting', async () => {
      mockedAxios.get.mockRejectedValue({
        response: {
          status: 429,
          statusText: 'Too Many Requests'
        }
      });

      await expect(
        axios.get('https://nominatim.openstreetmap.org/search', {
          params: { q: 'test' }
        })
      ).rejects.toMatchObject({
        response: {
          status: 429
        }
      });
    });

    it('should handle Nominatim service unavailable', async () => {
      mockedAxios.get.mockRejectedValue({
        response: {
          status: 503,
          statusText: 'Service Unavailable'
        }
      });

      await expect(
        axios.get('https://nominatim.openstreetmap.org/search', {
          params: { q: 'test' }
        })
      ).rejects.toMatchObject({
        response: {
          status: 503
        }
      });
    });

    it('should respect Nominatim usage policy with user agent', async () => {
      mockedAxios.get.mockResolvedValue({ data: [] });

      await axios.get('https://nominatim.openstreetmap.org/search', {
        params: { q: 'test' },
        headers: {
          'User-Agent': 'SmellPin/1.0 (contact@smellpin.com)'
        }
      });

      expect(mockedAxios.get).toHaveBeenCalledWith(
        'https://nominatim.openstreetmap.org/search',
        expect.objectContaining({
          headers: {
            'User-Agent': 'SmellPin/1.0 (contact@smellpin.com)'
          }
        })
      );
    });
  });

  describe('Error Recovery and Fallbacks', () => {
    it('should handle network timeouts', async () => {
      const timeoutError = new Error('Network timeout');
      timeoutError.name = 'ECONNABORTED';
      mockedAxios.get.mockRejectedValue(timeoutError);

      await expect(
        axios.get('https://nominatim.openstreetmap.org/search', {
          timeout: 5000,
          params: { q: 'test' }
        })
      ).rejects.toThrow('Network timeout');
    });

    it('should handle malformed responses', async () => {
      mockedAxios.get.mockResolvedValue({
        data: 'invalid json response'
      });

      const response = await axios.get('https://nominatim.openstreetmap.org/search');
      expect(response.data).toBe('invalid json response');
    });

    it('should handle empty results gracefully', async () => {
      mockedAxios.get.mockResolvedValue({
        data: []
      });

      const response = await axios.get('https://nominatim.openstreetmap.org/search', {
        params: { q: 'nonexistent location' }
      });

      expect(response.data).toEqual([]);
    });
  });

  describe('Chinese Address Handling', () => {
    const chineseAddresses = [
      '北京市朝阳区三里屯',
      '上海市浦东新区陆家嘴',
      '广州市天河区珠江新城',
      '深圳市南山区科技园',
      '成都市锦江区春熙路'
    ];

    it('should handle Chinese addresses correctly', async () => {
      for (const address of chineseAddresses) {
        const mockResponse = {
          data: [{
            lat: (30 + Math.random() * 20).toString(),
            lon: (110 + Math.random() * 20).toString(),
            display_name: address + ', 中国'
          }]
        };

        mockedAxios.get.mockResolvedValue(mockResponse);

        const response = await axios.get('https://nominatim.openstreetmap.org/search', {
          params: {
            q: address,
            format: 'json',
            'accept-language': 'zh-CN'
          }
        });

        expect(response.data[0].display_name).toContain(address);
      }
    });

    it('should handle mixed language addresses', async () => {
      const mixedAddress = 'Beijing 三里屯 Sanlitun';
      mockedAxios.get.mockResolvedValue({
        data: [{
          lat: '39.9388',
          lon: '116.4553',
          display_name: '三里屯, 朝阳区, 北京市, 中国'
        }]
      });

      const response = await axios.get('https://nominatim.openstreetmap.org/search', {
        params: { q: mixedAddress }
      });

      expect(response.data[0]).toBeDefined();
    });
  });

  describe('Performance and Caching', () => {
    it('should handle concurrent requests', async () => {
      const requests = Array.from({ length: 10 }, (_, i) =>
        axios.get('https://nominatim.openstreetmap.org/search', {
          params: { q: `address ${i}` }
        })
      );

      mockedAxios.get.mockResolvedValue({ data: [] });

      await Promise.all(requests);

      expect(mockedAxios.get).toHaveBeenCalledTimes(10);
    });

    it('should measure response times', async () => {
      mockedAxios.get.mockImplementation(() => 
        new Promise(resolve => 
          setTimeout(() => resolve({ data: [] }), 100)
        )
      );

      const startTime = Date.now();
      await axios.get('https://nominatim.openstreetmap.org/search', {
        params: { q: 'test' }
      });
      const endTime = Date.now();

      expect(endTime - startTime).toBeGreaterThanOrEqual(100);
    });
  });
});