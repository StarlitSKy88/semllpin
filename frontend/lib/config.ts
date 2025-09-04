/**
 * SmellPin Frontend Configuration
 * Centralized configuration for all frontend services
 */

// API Configuration
export const API_CONFIG = {
  // Base URLs
  BASE_URL: process.env.NEXT_PUBLIC_API_URL || 'https://semllpin.onrender.com',
  API_BASE_URL: process.env.NEXT_PUBLIC_API_BASE_URL || 'https://semllpin.onrender.com/api',
  
  // API Endpoints
  ENDPOINTS: {
    // Authentication
    AUTH: {
      LOGIN: '/auth/login',
      REGISTER: '/auth/register',
      LOGOUT: '/auth/logout',
      REFRESH: '/auth/refresh',
      FORGOT_PASSWORD: '/auth/forgot-password',
      RESET_PASSWORD: '/auth/reset-password',
      VERIFY_EMAIL: '/auth/verify-email',
    },
    
    // User Management
    USER: {
      PROFILE: '/users/profile',
      UPDATE_PROFILE: '/users/profile',
      CHANGE_PASSWORD: '/users/password',
      GET_BY_ID: '/users',
    },
    
    // Annotations
    ANNOTATIONS: {
      CREATE: '/annotations',
      LIST: '/annotations',
      GET_BY_ID: '/annotations',
      UPDATE: '/annotations',
      DELETE: '/annotations',
      NEARBY: '/annotations/nearby',
      SEARCH: '/annotations/search',
    },
    
    // Geocoding
    GEOCODING: {
      SEARCH: '/geocoding/search',
      REVERSE: '/geocoding/reverse',
      NEARBY: '/geocoding/nearby',
      IP_LOCATION: '/geocoding/ip-location',
      POI_TYPES: '/geocoding/poi-types',
    },
    
    // Payments
    PAYMENTS: {
      CREATE_PAYMENT: '/payments/create',
      EXECUTE_PAYMENT: '/payments/execute',
      CANCEL_PAYMENT: '/payments/cancel',
      REFUND_PAYMENT: '/payments/refund',
      GET_PAYMENT: '/payments',
    },
    
    // Health & Monitoring
    HEALTH: '/health',
    METRICS: '/metrics',
  },
  
  // Request Configuration
  REQUEST: {
    TIMEOUT: 10000, // 10 seconds
    RETRY_ATTEMPTS: 3,
    RETRY_DELAY: 1000, // 1 second
  },
} as const;

// Environment Configuration
export const ENV_CONFIG = {
  NODE_ENV: process.env.NODE_ENV || 'development',
  IS_DEVELOPMENT: process.env.NODE_ENV === 'development',
  IS_PRODUCTION: process.env.NODE_ENV === 'production',
  IS_TEST: process.env.NODE_ENV === 'test',
} as const;

// Maps Configuration
export const MAPS_CONFIG = {
  GOOGLE_MAPS_API_KEY: process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY || '',
  MAPBOX_ACCESS_TOKEN: process.env.NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN || '',
  DEFAULT_CENTER: {
    lat: 39.9042,
    lng: 116.4074, // Beijing coordinates
  },
  DEFAULT_ZOOM: 10,
} as const;

// PayPal Configuration
export const PAYPAL_CONFIG = {
  CLIENT_ID: process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID || '',
  ENVIRONMENT: (process.env.NEXT_PUBLIC_PAYPAL_ENVIRONMENT || 'sandbox') as 'sandbox' | 'production',
  CURRENCY: 'USD',
  INTENT: 'capture' as const,
} as const;

// Cache Configuration
export const CACHE_CONFIG = {
  TTL: parseInt(process.env.NEXT_PUBLIC_CACHE_TTL || '3600000'), // 1 hour
  GEOCODING_TTL: 3600000, // 1 hour
  IP_LOCATION_TTL: 1800000, // 30 minutes
  POI_TYPES_TTL: 86400000, // 24 hours
} as const;

// Feature Flags
export const FEATURE_FLAGS = {
  ENABLE_ANALYTICS: process.env.NEXT_PUBLIC_ENABLE_ANALYTICS === 'true',
  ENABLE_GEOLOCATION: process.env.NEXT_PUBLIC_ENABLE_GEOLOCATION !== 'false',
  ENABLE_NOTIFICATIONS: process.env.NEXT_PUBLIC_ENABLE_NOTIFICATIONS !== 'false',
  ENABLE_PWA: process.env.NEXT_PUBLIC_ENABLE_PWA === 'true',
  ENABLE_OFFLINE: process.env.NEXT_PUBLIC_ENABLE_OFFLINE === 'true',
} as const;

// Analytics Configuration
export const ANALYTICS_CONFIG = {
  VERCEL_ANALYTICS_ID: process.env.NEXT_PUBLIC_VERCEL_ANALYTICS_ID || '',
  SENTRY_DSN: process.env.NEXT_PUBLIC_SENTRY_DSN || '',
} as const;

// UI Configuration
export const UI_CONFIG = {
  THEME: {
    DEFAULT: 'light' as const,
    STORAGE_KEY: 'smellpin-theme',
  },
  LANGUAGE: {
    DEFAULT: 'zh' as const,
    STORAGE_KEY: 'smellpin-language',
  },
  PAGINATION: {
    DEFAULT_PAGE_SIZE: 20,
    MAX_PAGE_SIZE: 100,
  },
  TOAST: {
    DURATION: 5000, // 5 seconds
    MAX_VISIBLE: 5,
  },
} as const;

// Validation Configuration
export const VALIDATION_CONFIG = {
  PASSWORD: {
    MIN_LENGTH: 8,
    MAX_LENGTH: 128,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBER: true,
    REQUIRE_SPECIAL_CHAR: true,
  },
  EMAIL: {
    MAX_LENGTH: 255,
  },
  ANNOTATION: {
    TITLE_MAX_LENGTH: 100,
    DESCRIPTION_MAX_LENGTH: 1000,
    MAX_IMAGES: 5,
    MAX_FILE_SIZE: 5 * 1024 * 1024, // 5MB
  },
  GEOLOCATION: {
    MAX_ACCURACY: 100, // meters
    TIMEOUT: 10000, // 10 seconds
    MAX_AGE: 300000, // 5 minutes
  },
} as const;

// Export all configurations
export const CONFIG = {
  API: API_CONFIG,
  ENV: ENV_CONFIG,
  MAPS: MAPS_CONFIG,
  PAYPAL: PAYPAL_CONFIG,
  CACHE: CACHE_CONFIG,
  FEATURES: FEATURE_FLAGS,
  ANALYTICS: ANALYTICS_CONFIG,
  UI: UI_CONFIG,
  VALIDATION: VALIDATION_CONFIG,
} as const;

export default CONFIG;