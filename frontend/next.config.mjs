/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable React strict mode for better development
  reactStrictMode: true,
  
  // Enable powered by header optimization
  poweredByHeader: false,
  
  // Enable experimental features for performance
  experimental: {
    optimizePackageImports: [
      '@radix-ui/react-icons',
      'lucide-react',
      'framer-motion'
    ],
    turbo: {
      rules: {
        '*.svg': {
          loaders: ['@svgr/webpack'],
          as: '*.js',
        },
      },
    },
  },

  eslint: {
    // Only ignore during builds for now - will be fixed later
    ignoreDuringBuilds: false,
  },
  typescript: {
    // Enable strict type checking
    ignoreBuildErrors: false,
  },

  // Optimized image configuration
  images: {
    formats: ['image/webp', 'image/avif'],
    domains: [
      'images.unsplash.com', 
      'localhost',
      'api.smellpin.com',
      'assets.smellpin.com'
    ],
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'images.unsplash.com',
        port: '',
        pathname: '/**',
      },
      {
        protocol: 'http',
        hostname: 'localhost',
        port: '3000',
        pathname: '/**',
      },
      {
        protocol: 'https',
        hostname: '**.smellpin.com',
        port: '',
        pathname: '/**',
      },
    ],
    deviceSizes: [640, 750, 828, 1080, 1200, 1920, 2048, 3840],
    imageSizes: [16, 32, 48, 64, 96, 128, 256, 384],
  },

  // Performance optimizations
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production',
  },

  // Advanced webpack configuration
  webpack: (config, { isServer, dev }) => {
    // Resolve GSAP modules properly
    config.resolve.alias = {
      ...config.resolve.alias,
      'gsap/ScrollTrigger': 'gsap/dist/ScrollTrigger',
      'gsap/ScrollToPlugin': 'gsap/dist/ScrollToPlugin',
      '@': import.meta.dirname,
    }
    
    // Client-side optimizations
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
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
              test: /[\\/]node_modules[\\/](@radix-ui|lucide-react|framer-motion)[\\/]/,
              name: 'ui-libs',
              priority: 20,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Map libraries
            map: {
              test: /[\\/]node_modules[\\/](leaflet|react-leaflet)[\\/]/,
              name: 'map-libs',
              priority: 15,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Animation libraries
            animation: {
              test: /[\\/]node_modules[\\/](gsap|@gsap|three|@react-three)[\\/]/,
              name: 'animation-libs',
              priority: 15,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Payment libraries
            payment: {
              test: /[\\/]node_modules[\\/](@paypal|stripe)[\\/]/,
              name: 'payment-libs',
              priority: 15,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // React ecosystem
            react: {
              test: /[\\/]node_modules[\\/](react|react-dom|@tanstack)[\\/]/,
              name: 'react-vendor',
              priority: 12,
              chunks: 'all',
              reuseExistingChunk: true,
            },
            // Default vendor chunk for remaining modules
            vendor: {
              test: /[\\/]node_modules[\\/]/,
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

    // Bundle analyzer for optimization (synchronous)
    if (process.env.ANALYZE === 'true') {
      const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer')
      config.plugins.push(
        new BundleAnalyzerPlugin({
          analyzerMode: 'static',
          openAnalyzer: true,
          generateStatsFile: true,
          statsOptions: {
            source: false,
          },
        })
      )
    }
    
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
              "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.paypal.com https://maps.googleapis.com",
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://maps.googleapis.com",
              "font-src 'self' https://fonts.gstatic.com",
              "img-src 'self' data: https: blob:",
              "connect-src 'self' https://api.stripe.com https://api.paypal.com https://api-m.sandbox.paypal.com https://maps.googleapis.com",
              "frame-src 'self' https://js.stripe.com https://www.paypal.com https://maps.google.com",
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
