// Bundle analyzer configuration
const withBundleAnalyzer = (config) => config;

const nextConfig = {
  // Enable experimental features for better performance
  experimental: {
    // Optimize CSS loading
    optimizeCss: true,
    // Enable modern JavaScript features
    esmExternals: true,
  },

  // Compiler optimizations
  compiler: {
    // Remove console.log in production
    removeConsole: process.env.NODE_ENV === 'production' ? {
      exclude: ['error', 'warn'],
    } : false,
    // Enable React compiler optimizations
    reactRemoveProperties: process.env.NODE_ENV === 'production',
  },

  // Image optimization
  images: {
    // Enable modern image formats
    formats: ['image/webp', 'image/avif'],
    // Optimize image loading
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
    // Enable image optimization
    minimumCacheTTL: 60 * 60 * 24 * 365, // 1 year
    // Allow external image domains
    domains: [],
  },

  // Performance optimizations
  poweredByHeader: false,
  generateEtags: true,
  compress: true,

  // Custom webpack configuration for advanced optimizations
  webpack: (config, { dev, isServer }) => {
    // Optimize bundle size
    if (!dev && !isServer) {
      config.resolve.alias = {
        ...config.resolve.alias,
        // Reduce bundle size by aliasing heavy libraries
        'react/jsx-runtime.js': 'preact/compat/jsx-runtime',
      }
    }

    // Optimize for Node.js environment
    if (isServer) {
      // Skip external configuration to avoid webpack errors
      // config.externals can be configured here if needed
    }

    // Disable Node.js polyfills for client-side
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
        crypto: false,
        stream: false,
        url: false,
        zlib: false,
        http: false,
        https: false,
        assert: false,
        path: false,
        os: false,
      }
    }

    // Aggressive production optimizations for bundle splitting
    if (!dev) {
      config.optimization = {
        ...config.optimization,
        splitChunks: {
          chunks: 'all',
          minSize: 20000,
          maxSize: 100000,
          minChunks: 1,
          maxAsyncRequests: 30,
          maxInitialRequests: 30,
          cacheGroups: {
            // UI libraries
            ui: {
              test: /[\/]node_modules[\/](@radix-ui|lucide-react|framer-motion)[\/]/,
              name: 'ui-libs',
              priority: 20,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Map libraries
            map: {
              test: /[\/]node_modules[\/](leaflet|react-leaflet)[\/]/,
              name: 'map-libs',
              priority: 15,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Animation libraries
            animation: {
              test: /[\/]node_modules[\/](gsap|@gsap|three|@react-three)[\/]/,
              name: 'animation-libs',
              priority: 15,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Payment libraries
            payment: {
              test: /[\/]node_modules[\/](@paypal)[\/]/,
              name: 'payment-libs',
              priority: 15,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // React ecosystem
            react: {
              test: /[\/]node_modules[\/](react|react-dom|@tanstack)[\/]/,
              name: 'react-vendor',
              priority: 12,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Default vendor chunk for remaining modules
            vendor: {
              test: /[\/]node_modules[\/]/,
              name: 'vendors',
              priority: 10,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Common chunks for shared components
            common: {
              name: 'common',
              minChunks: 2,
              priority: 5,
              reuseExistingChunk: true,
              chunks: 'all',
            },
          },
        },
        // Enable tree shaking and dead code elimination
        usedExports: true,
        sideEffects: false,
      }
    }

    // Bundle analyzer disabled for now to avoid import issues
    // Can be enabled later with proper dynamic imports
    
    return config
  },

  // Enhanced security and performance headers
  async headers() {
    const isProd = process.env.NODE_ENV === 'production';
    
    return [
      {
        source: '/(.*)',
        headers: [
          // Security headers
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Referrer-Policy',
            value: 'origin-when-cross-origin',
          },
          // Enhanced Permissions Policy for SmellPin features
          {
            key: 'Permissions-Policy',
            value: 'geolocation=(self), camera=(), microphone=(), payment=(self), usb=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=(self), fullscreen=(self), autoplay=(self)',
          },
          // HSTS header for production only
          ...(isProd ? [{
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          }] : []),
          // Content Security Policy
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.paypal.com https://maps.googleapis.com",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://maps.googleapis.com",
              "font-src 'self' https://fonts.gstatic.com",
              "img-src 'self' data: https: blob:",
              "connect-src 'self' https://api.paypal.com https://api-m.sandbox.paypal.com https://maps.googleapis.com",
              "frame-src 'self' https://www.paypal.com https://maps.google.com",
              "object-src 'none'",
              "media-src 'self'",
              "worker-src 'self' blob:",
              "child-src 'self'",
              "form-action 'self'",
              ...(isProd ? ["upgrade-insecure-requests"] : [])
            ].join('; '),
          },
          // Performance headers
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'on',
          },
        ],
      },
      // Static assets headers
      {
        source: '/static/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
      // API routes headers
      {
        source: '/api/(.*)',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
        ],
      },
    ]
  },

  // Redirects for better UX
  async redirects() {
    return [
      {
        source: '/home',
        destination: '/',
        permanent: true,
      },
    ]
  },
}

export default nextConfig
