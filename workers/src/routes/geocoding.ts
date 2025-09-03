import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

// Validation schemas
const geocodeSchema = z.object({
  address: z.string().min(1, 'Address is required'),
  language: z.string().optional().default('en'),
  region: z.string().optional(),
  bounds: z.object({
    northeast: z.object({ lat: z.number(), lng: z.number() }),
    southwest: z.object({ lat: z.number(), lng: z.number() })
  }).optional()
});

const reverseGeocodeSchema = z.object({
  latitude: z.number().min(-90).max(90),
  longitude: z.number().min(-180).max(180),
  language: z.string().optional().default('en'),
  result_type: z.array(z.string()).optional()
});

// Types
interface GeocodeResult {
  formatted_address: string;
  latitude: number;
  longitude: number;
  place_id?: string;
  types: string[];
  address_components: {
    long_name: string;
    short_name: string;
    types: string[];
  }[];
}

interface ReverseGeocodeResult {
  formatted_address: string;
  place_id?: string;
  types: string[];
  address_components: {
    long_name: string;
    short_name: string;
    types: string[];
  }[];
}

// Cache interface
interface CacheEntry {
  data: any;
  timestamp: number;
  expires_at: number;
}

// In-memory cache (for demonstration - in production, use Redis or similar)
const geocodeCache = new Map<string, CacheEntry>();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Helper function to get from cache
function getFromCache(key: string): any | null {
  const entry = geocodeCache.get(key);
  if (!entry) return null;
  
  if (Date.now() > entry.expires_at) {
    geocodeCache.delete(key);
    return null;
  }
  
  return entry.data;
}

// Helper function to set cache
function setCache(key: string, data: any): void {
  const entry: CacheEntry = {
    data,
    timestamp: Date.now(),
    expires_at: Date.now() + CACHE_TTL
  };
  geocodeCache.set(key, entry);
}

// Mock geocoding service (replace with actual service integration)
async function mockGeocodeService(address: string, options: any = {}): Promise<GeocodeResult[]> {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Mock response based on address
  const mockResults: GeocodeResult[] = [
    {
      formatted_address: `${address}, Mock City, Mock Country`,
      latitude: 40.7128 + (Math.random() - 0.5) * 0.1,
      longitude: -74.0060 + (Math.random() - 0.5) * 0.1,
      place_id: `mock_place_${Date.now()}`,
      types: ['street_address'],
      address_components: [
        {
          long_name: address.split(',')[0] || address,
          short_name: address.split(',')[0] || address,
          types: ['street_number', 'route']
        },
        {
          long_name: 'Mock City',
          short_name: 'Mock City',
          types: ['locality', 'political']
        },
        {
          long_name: 'Mock Country',
          short_name: 'MC',
          types: ['country', 'political']
        }
      ]
    }
  ];
  
  return mockResults;
}

// Mock reverse geocoding service
async function mockReverseGeocodeService(lat: number, lng: number, options: any = {}): Promise<ReverseGeocodeResult[]> {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 100));
  
  // Mock response based on coordinates
  const mockResults: ReverseGeocodeResult[] = [
    {
      formatted_address: `Mock Street ${Math.floor(Math.abs(lat * 100))}, Mock City, Mock Country`,
      place_id: `mock_reverse_${Date.now()}`,
      types: ['street_address'],
      address_components: [
        {
          long_name: `Mock Street ${Math.floor(Math.abs(lat * 100))}`,
          short_name: `Mock St ${Math.floor(Math.abs(lat * 100))}`,
          types: ['route']
        },
        {
          long_name: 'Mock City',
          short_name: 'Mock City',
          types: ['locality', 'political']
        },
        {
          long_name: 'Mock Country',
          short_name: 'MC',
          types: ['country', 'political']
        }
      ]
    }
  ];
  
  return mockResults;
}

// Geocode: Convert address to coordinates
export const geocode: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const { address, language, region, bounds } = geocodeSchema.parse(body);

    // Create cache key
    const cacheKey = `geocode:${address}:${language}:${region || ''}:${JSON.stringify(bounds || {})}`;
    
    // Check cache first
    const cachedResult = getFromCache(cacheKey);
    if (cachedResult) {
      return new Response(JSON.stringify({
        success: true,
        data: cachedResult,
        cached: true,
        message: 'Geocoding result retrieved from cache'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Call geocoding service
    const results = await mockGeocodeService(address, { language, region, bounds });
    
    if (!results || results.length === 0) {
      return new Response(JSON.stringify({
        error: 'No results found',
        message: 'No geocoding results found for the provided address'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Cache the result
    setCache(cacheKey, results);

    return new Response(JSON.stringify({
      success: true,
      data: results,
      cached: false,
      message: 'Geocoding completed successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Geocoding error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid request data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to process geocoding request'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Reverse Geocode: Convert coordinates to address
export const reverseGeocode: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const { latitude, longitude, language, result_type } = reverseGeocodeSchema.parse(body);

    // Create cache key
    const cacheKey = `reverse:${latitude}:${longitude}:${language}:${JSON.stringify(result_type || [])}`;
    
    // Check cache first
    const cachedResult = getFromCache(cacheKey);
    if (cachedResult) {
      return new Response(JSON.stringify({
        success: true,
        data: cachedResult,
        cached: true,
        message: 'Reverse geocoding result retrieved from cache'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Call reverse geocoding service
    const results = await mockReverseGeocodeService(latitude, longitude, { language, result_type });
    
    if (!results || results.length === 0) {
      return new Response(JSON.stringify({
        error: 'No results found',
        message: 'No reverse geocoding results found for the provided coordinates'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Cache the result
    setCache(cacheKey, results);

    return new Response(JSON.stringify({
      success: true,
      data: results,
      cached: false,
      message: 'Reverse geocoding completed successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Reverse geocoding error:', error);
    
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation Error',
        message: 'Invalid request data',
        details: error.errors
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to process reverse geocoding request'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get geocoding cache statistics
export const getCacheStats: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const now = Date.now();
    let validEntries = 0;
    let expiredEntries = 0;
    
    for (const [key, entry] of geocodeCache.entries()) {
      if (now > entry.expires_at) {
        expiredEntries++;
        geocodeCache.delete(key); // Clean up expired entries
      } else {
        validEntries++;
      }
    }

    return new Response(JSON.stringify({
      success: true,
      data: {
        total_entries: validEntries,
        expired_cleaned: expiredEntries,
        cache_ttl_hours: CACHE_TTL / (60 * 60 * 1000),
        memory_usage_estimate: `${geocodeCache.size} entries`
      },
      message: 'Cache statistics retrieved successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Cache stats error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to retrieve cache statistics'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Clear geocoding cache (admin only)
export const clearCache: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // In a real application, you would check if user is admin
    // For now, we'll allow any authenticated user to clear cache
    
    const entriesCleared = geocodeCache.size;
    geocodeCache.clear();

    return new Response(JSON.stringify({
      success: true,
      data: {
        entries_cleared: entriesCleared
      },
      message: 'Geocoding cache cleared successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Clear cache error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to clear cache'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};