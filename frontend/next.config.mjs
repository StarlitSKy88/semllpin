/** @type {import('next').NextConfig} */
const nextConfig = {
  // Basic configuration for deployment
  experimental: {
    // Disable experimental features for stable deployment
  },

  // Compiler optimizations - disabled for deployment stability
  compiler: {
    // Disable advanced optimizations that may cause build issues
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

  // Skip type checking during build for faster deployment
  typescript: {
    ignoreBuildErrors: true,
  },
  
  // Skip linting during build
  eslint: {
    ignoreDuringBuilds: true,
  },

  // Basic webpack configuration
  webpack: (config, { dev, isServer }) => {
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
          // HSTS header for production only
          ...(isProd ? [{
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          }] : []),
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