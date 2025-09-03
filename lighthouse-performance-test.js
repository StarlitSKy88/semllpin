#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class LighthousePerformanceTester {
  constructor() {
    this.results = {
      timestamp: new Date().toISOString(),
      tests: [],
      summary: {},
      recommendations: []
    };
    
    this.config = {
      urls: [
        { path: '/', name: 'Homepage' },
        { path: '/map', name: 'Map View' },
        { path: '/profile', name: 'User Profile' },
        { path: '/wallet', name: 'Wallet' }
      ],
      baseUrl: process.env.FRONTEND_URL || 'http://localhost:3001',
      devices: ['desktop', 'mobile'],
      networks: ['desktop', '4G', '3G']
    };
  }

  async runLighthouseTests() {
    console.log('🚀 Starting Lighthouse Performance Tests...\n');
    
    try {
      // Check if lighthouse is installed globally
      this.ensureLighthouseInstalled();
      
      // Test each URL with different configurations
      for (const device of this.config.devices) {
        for (const network of this.config.networks) {
          if (device === 'desktop' && network !== 'desktop') continue;
          if (device === 'mobile' && network === 'desktop') continue;
          
          await this.testConfiguration(device, network);
        }
      }
      
      // Generate analysis
      this.analyzeResults();
      
      // Generate report
      await this.generateReport();
      
      console.log('✅ Lighthouse tests completed!\n');
      
    } catch (error) {
      console.error('❌ Lighthouse tests failed:', error.message);
      this.results.error = error.message;
    }
  }

  ensureLighthouseInstalled() {
    try {
      execSync('lighthouse --version', { stdio: 'pipe' });
    } catch (error) {
      console.log('Installing lighthouse-cli...');
      try {
        execSync('npm install -g lighthouse', { stdio: 'inherit' });
      } catch (installError) {
        throw new Error('Failed to install Lighthouse. Please run: npm install -g lighthouse');
      }
    }
  }

  async testConfiguration(device, network) {
    console.log(`📱 Testing ${device} with ${network} network...`);
    
    for (const urlConfig of this.config.urls) {
      const url = `${this.config.baseUrl}${urlConfig.path}`;
      
      try {
        console.log(`  🔍 Testing ${urlConfig.name} (${url})`);
        
        const result = await this.runLighthouseTest(url, device, network);
        
        this.results.tests.push({
          url: url,
          name: urlConfig.name,
          path: urlConfig.path,
          device: device,
          network: network,
          timestamp: new Date().toISOString(),
          ...result
        });
        
        console.log(`    ✅ Performance: ${result.performance}/100`);
        
      } catch (error) {
        console.error(`    ❌ Failed to test ${urlConfig.name}: ${error.message}`);
        
        this.results.tests.push({
          url: url,
          name: urlConfig.name,
          path: urlConfig.path,
          device: device,
          network: network,
          timestamp: new Date().toISOString(),
          error: error.message
        });
      }
    }
  }

  async runLighthouseTest(url, device, network) {
    const outputFile = path.join(__dirname, 'temp-lighthouse-report.json');
    
    let command = `lighthouse "${url}" --output json --output-path "${outputFile}" --quiet`;
    
    // Device configuration
    if (device === 'mobile') {
      command += ' --preset mobile --emulated-form-factor mobile';
    } else {
      command += ' --preset desktop --emulated-form-factor desktop';
    }
    
    // Network configuration
    if (network === '4G') {
      command += ' --throttling-method simulate --throttling.cpuSlowdownMultiplier 4 --throttling.rttMs 150 --throttling.throughputKbps 1638';
    } else if (network === '3G') {
      command += ' --throttling-method simulate --throttling.cpuSlowdownMultiplier 4 --throttling.rttMs 300 --throttling.throughputKbps 819';
    }
    
    // Additional flags
    command += ' --chrome-flags="--headless --no-sandbox --disable-dev-shm-usage"';
    
    try {
      execSync(command, { stdio: 'pipe', timeout: 120000 }); // 2 minute timeout
      
      const reportData = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
      fs.unlinkSync(outputFile); // Clean up temp file
      
      return this.parseResultData(reportData);
      
    } catch (error) {
      if (fs.existsSync(outputFile)) {
        fs.unlinkSync(outputFile);
      }
      throw new Error(`Lighthouse test failed: ${error.message}`);
    }
  }

  parseResultData(reportData) {
    const categories = reportData.categories;
    const audits = reportData.audits;
    
    return {
      performance: Math.round(categories.performance.score * 100),
      accessibility: Math.round(categories.accessibility.score * 100),
      bestPractices: Math.round(categories['best-practices'].score * 100),
      seo: Math.round(categories.seo.score * 100),
      metrics: {
        firstContentfulPaint: audits['first-contentful-paint'].numericValue,
        largestContentfulPaint: audits['largest-contentful-paint'].numericValue,
        timeToInteractive: audits['interactive'].numericValue,
        cumulativeLayoutShift: audits['cumulative-layout-shift'].numericValue,
        speedIndex: audits['speed-index'].numericValue,
        totalBlockingTime: audits['total-blocking-time'].numericValue
      },
      opportunities: this.extractOpportunities(audits),
      diagnostics: this.extractDiagnostics(audits)
    };
  }

  extractOpportunities(audits) {
    const opportunities = [];
    const opportunityAudits = [
      'unused-javascript',
      'unused-css-rules',
      'render-blocking-resources',
      'opportunities-to-minify-css',
      'efficient-animated-content',
      'uses-optimized-images',
      'uses-webp-images',
      'offscreen-images',
      'uses-text-compression'
    ];
    
    opportunityAudits.forEach(auditId => {
      if (audits[auditId] && audits[auditId].score < 1) {
        opportunities.push({
          id: auditId,
          title: audits[auditId].title,
          description: audits[auditId].description,
          score: Math.round(audits[auditId].score * 100),
          numericValue: audits[auditId].numericValue || 0,
          displayValue: audits[auditId].displayValue || ''
        });
      }
    });
    
    return opportunities;
  }

  extractDiagnostics(audits) {
    const diagnostics = [];
    const diagnosticAudits = [
      'dom-size',
      'uses-passive-event-listeners',
      'no-document-write',
      'uses-http2',
      'uses-rel-preload',
      'critical-request-chains'
    ];
    
    diagnosticAudits.forEach(auditId => {
      if (audits[auditId]) {
        diagnostics.push({
          id: auditId,
          title: audits[auditId].title,
          score: audits[auditId].score !== null ? Math.round(audits[auditId].score * 100) : null,
          numericValue: audits[auditId].numericValue || 0,
          displayValue: audits[auditId].displayValue || ''
        });
      }
    });
    
    return diagnostics;
  }

  analyzeResults() {
    console.log('📊 Analyzing results...');
    
    const validTests = this.results.tests.filter(test => !test.error);
    
    if (validTests.length === 0) {
      this.results.summary = { error: 'No valid test results' };
      return;
    }
    
    // Calculate averages by device and page
    this.results.summary = {
      overall: this.calculateAverages(validTests),
      byDevice: {
        desktop: this.calculateAverages(validTests.filter(t => t.device === 'desktop')),
        mobile: this.calculateAverages(validTests.filter(t => t.device === 'mobile'))
      },
      byPage: {}
    };
    
    // Calculate by page
    this.config.urls.forEach(urlConfig => {
      const pageTests = validTests.filter(t => t.path === urlConfig.path);
      if (pageTests.length > 0) {
        this.results.summary.byPage[urlConfig.path] = this.calculateAverages(pageTests);
      }
    });
    
    // Identify critical issues
    this.identifyCriticalIssues(validTests);
    
    // Generate recommendations
    this.generateRecommendations(validTests);
  }

  calculateAverages(tests) {
    if (tests.length === 0) return null;
    
    const sum = (key) => tests.reduce((total, test) => total + (test[key] || 0), 0);
    const avg = (key) => Math.round(sum(key) / tests.length);
    
    const metricSum = (metric) => tests.reduce((total, test) => 
      total + (test.metrics?.[metric] || 0), 0);
    const metricAvg = (metric) => Math.round(metricSum(metric) / tests.length);
    
    return {
      performance: avg('performance'),
      accessibility: avg('accessibility'),
      bestPractices: avg('bestPractices'),
      seo: avg('seo'),
      metrics: {
        firstContentfulPaint: metricAvg('firstContentfulPaint'),
        largestContentfulPaint: metricAvg('largestContentfulPaint'),
        timeToInteractive: metricAvg('timeToInteractive'),
        cumulativeLayoutShift: tests.reduce((total, test) => 
          total + (test.metrics?.cumulativeLayoutShift || 0), 0) / tests.length,
        speedIndex: metricAvg('speedIndex'),
        totalBlockingTime: metricAvg('totalBlockingTime')
      }
    };
  }

  identifyCriticalIssues(validTests) {
    this.results.criticalIssues = [];
    
    validTests.forEach(test => {
      // Performance issues
      if (test.performance < 50) {
        this.results.criticalIssues.push({
          type: 'performance',
          severity: 'critical',
          page: test.name,
          device: test.device,
          score: test.performance,
          message: `Very poor performance score: ${test.performance}/100`
        });
      }
      
      // Core Web Vitals issues
      if (test.metrics?.largestContentfulPaint > 4000) {
        this.results.criticalIssues.push({
          type: 'core-web-vitals',
          severity: 'high',
          page: test.name,
          device: test.device,
          metric: 'LCP',
          value: test.metrics.largestContentfulPaint,
          message: `Poor Largest Contentful Paint: ${Math.round(test.metrics.largestContentfulPaint)}ms (should be < 2.5s)`
        });
      }
      
      if (test.metrics?.cumulativeLayoutShift > 0.25) {
        this.results.criticalIssues.push({
          type: 'core-web-vitals',
          severity: 'high',
          page: test.name,
          device: test.device,
          metric: 'CLS',
          value: test.metrics.cumulativeLayoutShift,
          message: `Poor Cumulative Layout Shift: ${test.metrics.cumulativeLayoutShift.toFixed(3)} (should be < 0.1)`
        });
      }
      
      // Accessibility issues
      if (test.accessibility < 90) {
        this.results.criticalIssues.push({
          type: 'accessibility',
          severity: 'medium',
          page: test.name,
          device: test.device,
          score: test.accessibility,
          message: `Accessibility score below recommended threshold: ${test.accessibility}/100`
        });
      }
    });
  }

  generateRecommendations(validTests) {
    const recommendations = new Map();
    
    validTests.forEach(test => {
      if (!test.opportunities) return;
      
      test.opportunities.forEach(opp => {
        const key = opp.id;
        if (!recommendations.has(key)) {
          recommendations.set(key, {
            id: opp.id,
            title: opp.title,
            description: opp.description,
            occurrences: 0,
            averageImpact: 0,
            pages: new Set()
          });
        }
        
        const rec = recommendations.get(key);
        rec.occurrences++;
        rec.averageImpact += opp.numericValue || 0;
        rec.pages.add(test.name);
      });
    });
    
    this.results.recommendations = Array.from(recommendations.values())
      .map(rec => ({
        ...rec,
        averageImpact: rec.averageImpact / rec.occurrences,
        pages: Array.from(rec.pages),
        priority: this.calculatePriority(rec)
      }))
      .sort((a, b) => {
        const priorityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
        return priorityOrder[b.priority] - priorityOrder[a.priority];
      });
  }

  calculatePriority(recommendation) {
    if (recommendation.occurrences >= 3 && recommendation.averageImpact > 1000) return 'critical';
    if (recommendation.occurrences >= 2 && recommendation.averageImpact > 500) return 'high';
    if (recommendation.occurrences >= 2 || recommendation.averageImpact > 200) return 'medium';
    return 'low';
  }

  async generateReport() {
    console.log('📄 Generating reports...');
    
    // Save detailed JSON report
    const jsonReportPath = path.join(__dirname, 'lighthouse-performance-report.json');
    fs.writeFileSync(jsonReportPath, JSON.stringify(this.results, null, 2));
    
    // Generate markdown summary
    const markdownReportPath = path.join(__dirname, 'lighthouse-performance-summary.md');
    const markdownContent = this.generateMarkdownReport();
    fs.writeFileSync(markdownReportPath, markdownContent);
    
    console.log(`📊 Detailed report: ${jsonReportPath}`);
    console.log(`📋 Summary report: ${markdownReportPath}`);
    
    // Display key findings
    this.displayKeyFindings();
  }

  generateMarkdownReport() {
    const timestamp = new Date().toLocaleString();
    
    return `# Lighthouse Performance Test Report

Generated: ${timestamp}

## Executive Summary

${this.results.summary.overall ? `
**Overall Performance Scores:**
- 🖥️  Desktop: ${this.results.summary.byDevice.desktop?.performance || 'N/A'}/100
- 📱 Mobile: ${this.results.summary.byDevice.mobile?.performance || 'N/A'}/100

**Core Web Vitals (Average):**
- **LCP**: ${Math.round(this.results.summary.overall.metrics.largestContentfulPaint)}ms ${this.results.summary.overall.metrics.largestContentfulPaint <= 2500 ? '✅' : '❌'}
- **CLS**: ${this.results.summary.overall.metrics.cumulativeLayoutShift.toFixed(3)} ${this.results.summary.overall.metrics.cumulativeLayoutShift <= 0.1 ? '✅' : '❌'}
- **FCP**: ${Math.round(this.results.summary.overall.metrics.firstContentfulPaint)}ms ${this.results.summary.overall.metrics.firstContentfulPaint <= 1800 ? '✅' : '❌'}
- **TTI**: ${Math.round(this.results.summary.overall.metrics.timeToInteractive)}ms
- **SI**: ${Math.round(this.results.summary.overall.metrics.speedIndex)}ms
- **TBT**: ${Math.round(this.results.summary.overall.metrics.totalBlockingTime)}ms
` : 'No valid test results available'}

## Critical Issues

${this.results.criticalIssues && this.results.criticalIssues.length > 0 ? 
  this.results.criticalIssues
    .filter(issue => issue.severity === 'critical')
    .map(issue => `### 🔴 ${issue.message}\n**Page**: ${issue.page} (${issue.device})\n**Score**: ${issue.score}/100\n`)
    .join('\n') : 'No critical issues detected ✅'}

## High Priority Issues

${this.results.criticalIssues && this.results.criticalIssues.length > 0 ?
  this.results.criticalIssues
    .filter(issue => issue.severity === 'high')
    .map(issue => `### 🟡 ${issue.message}\n**Page**: ${issue.page} (${issue.device})\n${issue.metric ? `**Metric**: ${issue.metric} - ${issue.value}` : ''}\n`)
    .join('\n') : 'No high priority issues detected ✅'}

## Performance by Page

${Object.entries(this.results.summary.byPage || {})
  .map(([path, data]) => `
### ${path === '/' ? 'Homepage' : path}
- **Performance**: ${data.performance}/100
- **Accessibility**: ${data.accessibility}/100  
- **Best Practices**: ${data.bestPractices}/100
- **SEO**: ${data.seo}/100
- **LCP**: ${Math.round(data.metrics.largestContentfulPaint)}ms
- **CLS**: ${data.metrics.cumulativeLayoutShift.toFixed(3)}
`).join('\n')}

## Optimization Recommendations

${this.results.recommendations.length > 0 ?
  this.results.recommendations.slice(0, 10)
    .map((rec, index) => `
### ${index + 1}. ${rec.title} [${rec.priority.toUpperCase()}]

**Impact**: ${rec.averageImpact > 0 ? Math.round(rec.averageImpact) + 'ms saved' : 'Improved user experience'}  
**Pages Affected**: ${rec.pages.join(', ')}  
**Occurrences**: ${rec.occurrences}

${rec.description}
`).join('\n') : 'No specific recommendations available'}

## Test Configuration

**URLs Tested**: ${this.config.urls.map(u => u.path).join(', ')}  
**Devices**: ${this.config.devices.join(', ')}  
**Networks**: ${this.config.networks.join(', ')}  
**Total Tests**: ${this.results.tests.length}  
**Failed Tests**: ${this.results.tests.filter(t => t.error).length}

## Raw Test Results

${this.results.tests.map(test => `
### ${test.name} - ${test.device} - ${test.network}
${test.error ? `**Error**: ${test.error}` : `
**Performance**: ${test.performance}/100  
**Accessibility**: ${test.accessibility}/100  
**Best Practices**: ${test.bestPractices}/100  
**SEO**: ${test.seo}/100  
**LCP**: ${Math.round(test.metrics?.largestContentfulPaint || 0)}ms  
**FCP**: ${Math.round(test.metrics?.firstContentfulPaint || 0)}ms  
**TTI**: ${Math.round(test.metrics?.timeToInteractive || 0)}ms
`}
`).join('\n')}

---
*Generated by Lighthouse Performance Tester*
`;
  }

  displayKeyFindings() {
    console.log('\n🎯 KEY FINDINGS:');
    console.log('================');
    
    if (this.results.summary.overall) {
      console.log(`📊 Overall Performance: ${this.results.summary.overall.performance}/100`);
      console.log(`📱 Mobile Performance: ${this.results.summary.byDevice.mobile?.performance || 'N/A'}/100`);
      console.log(`🖥️  Desktop Performance: ${this.results.summary.byDevice.desktop?.performance || 'N/A'}/100`);
    }
    
    if (this.results.criticalIssues) {
      const criticalCount = this.results.criticalIssues.filter(i => i.severity === 'critical').length;
      const highCount = this.results.criticalIssues.filter(i => i.severity === 'high').length;
      
      console.log(`\n🔥 Critical Issues: ${criticalCount}`);
      console.log(`⚠️  High Priority Issues: ${highCount}`);
    }
    
    if (this.results.recommendations.length > 0) {
      console.log('\n🚀 TOP RECOMMENDATIONS:');
      this.results.recommendations.slice(0, 3).forEach((rec, index) => {
        console.log(`${index + 1}. [${rec.priority.toUpperCase()}] ${rec.title}`);
      });
    }
    
    console.log(`\n📈 Tests Completed: ${this.results.tests.filter(t => !t.error).length}/${this.results.tests.length}`);
  }
}

// CLI execution
if (require.main === module) {
  const tester = new LighthousePerformanceTester();
  tester.runLighthouseTests().catch(console.error);
}

module.exports = LighthousePerformanceTester;