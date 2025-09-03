module.exports = {
  ci: {
    collect: {
      numberOfRuns: 3,
      startServerCommand: 'npm run preview',
      startServerReadyPattern: 'ready in',
      url: [
        'http://localhost:4173/',
        'http://localhost:4173/map',
        'http://localhost:4173/profile',
        'http://localhost:4173/wallet'
      ],
      settings: {
        chromeFlags: '--no-sandbox --headless',
        preset: 'desktop',
        throttling: {
          rttMs: 40,
          throughputKbps: 10240,
          cpuSlowdownMultiplier: 1,
          requestLatencyMs: 0,
          downloadThroughputKbps: 0,
          uploadThroughputKbps: 0
        }
      }
    },
    assert: {
      assertions: {
        'categories:performance': ['error', {minScore: 0.95}],
        'categories:accessibility': ['error', {minScore: 0.95}],
        'categories:best-practices': ['error', {minScore: 0.90}],
        'categories:seo': ['error', {minScore: 0.90}],
        'categories:pwa': ['warn', {minScore: 0.80}],
        
        // Core Web Vitals
        'largest-contentful-paint': ['error', {maxNumericValue: 2500}],
        'max-potential-fid': ['error', {maxNumericValue: 100}],
        'cumulative-layout-shift': ['error', {maxNumericValue: 0.1}],
        
        // Performance metrics
        'first-contentful-paint': ['warn', {maxNumericValue: 1800}],
        'speed-index': ['warn', {maxNumericValue: 3000}],
        'interactive': ['warn', {maxNumericValue: 3800}],
        
        // Resource optimization
        'unused-javascript': ['warn', {maxNumericValue: 30000}],
        'unused-css-rules': ['warn', {maxNumericValue: 20000}],
        'render-blocking-resources': ['warn', {maxNumericValue: 1000}],
        
        // Accessibility
        'color-contrast': 'error',
        'image-alt': 'error',
        'heading-order': 'error',
        'link-name': 'error',
        
        // Security
        'is-on-https': 'error',
        'uses-https': 'error',
        'external-anchors-use-rel-noopener': 'error'
      }
    },
    upload: {
      target: 'temporary-public-storage'
    },
    server: {
      port: 9001,
      storage: '.lighthouseci'
    }
  }
};