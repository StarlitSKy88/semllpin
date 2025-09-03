"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UXMetricsCollector = void 0;
class UXMetricsCollector {
    constructor(page) {
        this.metrics = {};
        this.startTimes = new Map();
        this.interactionTimes = [];
        this.errorEvents = [];
        this.page = page;
        this.setupMetricsCollection();
    }
    async setupMetricsCollection() {
        this.page.on('pageerror', (error) => {
            this.errorEvents.push(`Page Error: ${error.message}`);
        });
        this.page.on('requestfailed', (request) => {
            this.errorEvents.push(`Request Failed: ${request.url()}`);
        });
        this.page.on('console', (msg) => {
            if (msg.type() === 'error') {
                this.errorEvents.push(`Console Error: ${msg.text()}`);
            }
        });
        await this.page.addInitScript(() => {
            let interactionStartTime;
            document.addEventListener('click', () => {
                interactionStartTime = performance.now();
                requestAnimationFrame(() => {
                    const responseTime = performance.now() - interactionStartTime;
                    window.__interactionTimes = window.__interactionTimes || [];
                    window.__interactionTimes.push(responseTime);
                });
            });
            document.addEventListener('input', () => {
                if (!window.__formStartTime) {
                    window.__formStartTime = performance.now();
                }
            });
            document.addEventListener('submit', () => {
                if (window.__formStartTime) {
                    const formFillTime = performance.now() - window.__formStartTime;
                    window.__formFillTime = formFillTime;
                }
            });
            let clsValue = 0;
            new PerformanceObserver((entryList) => {
                for (const entry of entryList.getEntries()) {
                    if (!entry.hadRecentInput) {
                        clsValue += entry.value;
                    }
                }
                window.__clsValue = clsValue;
            }).observe({ type: 'layout-shift', buffered: true });
        });
    }
    startTask(taskName) {
        this.startTimes.set(taskName, Date.now());
    }
    endTask(taskName) {
        const startTime = this.startTimes.get(taskName);
        if (!startTime) {
            throw new Error(`Task ${taskName} was not started`);
        }
        const duration = Date.now() - startTime;
        this.startTimes.delete(taskName);
        return duration;
    }
    async collectWebVitals() {
        const vitals = await this.page.evaluate(() => {
            return new Promise((resolve) => {
                const vitals = {
                    fcp: 0,
                    lcp: 0,
                    cls: window.__clsValue || 0,
                    fid: 0,
                    ttfb: 0
                };
                new PerformanceObserver((entryList) => {
                    for (const entry of entryList.getEntries()) {
                        if (entry.name === 'first-contentful-paint') {
                            vitals.fcp = entry.startTime;
                        }
                    }
                }).observe({ type: 'paint', buffered: true });
                new PerformanceObserver((entryList) => {
                    const entries = entryList.getEntries();
                    const lastEntry = entries[entries.length - 1];
                    vitals.lcp = lastEntry.startTime;
                }).observe({ type: 'largest-contentful-paint', buffered: true });
                const navigation = performance.getEntriesByType('navigation')[0];
                if (navigation) {
                    vitals.ttfb = navigation.responseStart - navigation.fetchStart;
                }
                setTimeout(() => resolve(vitals), 1000);
            });
        });
        this.metrics.firstContentfulPaint = vitals.fcp;
        this.metrics.largestContentfulPaint = vitals.lcp;
        this.metrics.cumulativeLayoutShift = vitals.cls;
    }
    async collectInteractionMetrics() {
        const interactions = await this.page.evaluate(() => {
            return {
                interactionTimes: window.__interactionTimes || [],
                formFillTime: window.__formFillTime || 0
            };
        });
        this.metrics.clickResponseTime = interactions.interactionTimes;
        this.metrics.formFillTime = interactions.formFillTime;
    }
    async collectDeviceInfo() {
        const deviceInfo = await this.page.evaluate(() => {
            return {
                userAgent: navigator.userAgent,
                viewport: {
                    width: window.innerWidth,
                    height: window.innerHeight
                },
                devicePixelRatio: window.devicePixelRatio,
                isMobile: /Mobile|Android|iPhone|iPad/i.test(navigator.userAgent),
                isTablet: /iPad|Tablet/i.test(navigator.userAgent)
            };
        });
        this.metrics.deviceInfo = {
            ...deviceInfo,
            browserName: this.getBrowserName(deviceInfo.userAgent)
        };
    }
    async collectNetworkConditions() {
        const networkInfo = await this.page.evaluate(() => {
            const connection = navigator.connection;
            if (connection) {
                return {
                    effectiveType: connection.effectiveType,
                    downlink: connection.downlink,
                    rtt: connection.rtt,
                    saveData: connection.saveData
                };
            }
            return null;
        });
        this.metrics.networkConditions = networkInfo || {
            effectiveType: 'unknown',
            downlink: 0,
            rtt: 0,
            saveData: false
        };
    }
    async measurePageLoadTime() {
        const loadTime = await this.page.evaluate(() => {
            const navigation = performance.getEntriesByType('navigation')[0];
            return navigation ? navigation.loadEventEnd - navigation.fetchStart : 0;
        });
        this.metrics.pageLoadTime = loadTime;
        return loadTime;
    }
    async measureTimeToInteractive() {
        const tti = await this.page.evaluate(() => {
            return new Promise((resolve) => {
                let lastLongTaskEnd = 0;
                new PerformanceObserver((entryList) => {
                    for (const entry of entryList.getEntries()) {
                        lastLongTaskEnd = entry.startTime + entry.duration;
                    }
                }).observe({ type: 'longtask', buffered: true });
                setTimeout(() => {
                    const navigation = performance.getEntriesByType('navigation')[0];
                    const tti = Math.max(navigation.domContentLoadedEventEnd, lastLongTaskEnd) - navigation.fetchStart;
                    resolve(tti);
                }, 2000);
            });
        });
        this.metrics.timeToInteractive = tti;
        return tti;
    }
    evaluateUserSatisfaction() {
        let score = 10;
        if (this.metrics.pageLoadTime && this.metrics.pageLoadTime > 3000) {
            score -= 2;
        }
        if (this.metrics.largestContentfulPaint && this.metrics.largestContentfulPaint > 2500) {
            score -= 1;
        }
        if (this.metrics.cumulativeLayoutShift && this.metrics.cumulativeLayoutShift > 0.1) {
            score -= 1;
        }
        if (this.metrics.clickResponseTime && this.metrics.clickResponseTime.length > 0) {
            const avgResponseTime = this.metrics.clickResponseTime.reduce((a, b) => a + b, 0) / this.metrics.clickResponseTime.length;
            if (avgResponseTime > 100) {
                score -= 1;
            }
        }
        if (this.errorEvents.length > 0) {
            score -= this.errorEvents.length * 0.5;
        }
        return Math.max(1, Math.min(10, score));
    }
    createConversionFunnel(steps) {
        const funnel = {};
        let currentUsers = 100;
        for (let i = 0; i < steps.length; i++) {
            funnel[steps[i]] = currentUsers;
            currentUsers *= 0.8;
        }
        return funnel;
    }
    async generateUXReport() {
        await this.collectWebVitals();
        await this.collectInteractionMetrics();
        await this.collectDeviceInfo();
        await this.collectNetworkConditions();
        const report = {
            pageLoadTime: this.metrics.pageLoadTime || 0,
            timeToInteractive: this.metrics.timeToInteractive || 0,
            firstContentfulPaint: this.metrics.firstContentfulPaint || 0,
            largestContentfulPaint: this.metrics.largestContentfulPaint || 0,
            cumulativeLayoutShift: this.metrics.cumulativeLayoutShift || 0,
            clickResponseTime: this.metrics.clickResponseTime || [],
            formFillTime: this.metrics.formFillTime || 0,
            navigationTime: 0,
            taskCompletionTime: 0,
            errorRate: this.errorEvents.length,
            conversionFunnelMetrics: {},
            deviceInfo: this.metrics.deviceInfo,
            networkConditions: this.metrics.networkConditions,
            perceivedPerformance: this.evaluateUserSatisfaction(),
            taskSuccess: this.errorEvents.length === 0,
            userFrustrationEvents: this.errorEvents
        };
        return report;
    }
    async exportMetrics(filename) {
        const report = await this.generateUXReport();
        const fs = require('fs');
        const path = require('path');
        const reportPath = path.join('test-results', 'ux-metrics', filename);
        const dir = path.dirname(reportPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        console.log(`UX指标报告已导出到: ${reportPath}`);
    }
    getBrowserName(userAgent) {
        if (userAgent.includes('Chrome'))
            return 'Chrome';
        if (userAgent.includes('Firefox'))
            return 'Firefox';
        if (userAgent.includes('Safari') && !userAgent.includes('Chrome'))
            return 'Safari';
        if (userAgent.includes('Edge'))
            return 'Edge';
        return 'Unknown';
    }
    checkPerformanceBudget(budget) {
        const violations = [];
        if (budget.pageLoadTime && this.metrics.pageLoadTime > budget.pageLoadTime) {
            violations.push(`页面加载时间超预算: ${this.metrics.pageLoadTime}ms > ${budget.pageLoadTime}ms`);
        }
        if (budget.largestContentfulPaint && this.metrics.largestContentfulPaint > budget.largestContentfulPaint) {
            violations.push(`LCP超预算: ${this.metrics.largestContentfulPaint}ms > ${budget.largestContentfulPaint}ms`);
        }
        if (budget.cumulativeLayoutShift && this.metrics.cumulativeLayoutShift > budget.cumulativeLayoutShift) {
            violations.push(`CLS超预算: ${this.metrics.cumulativeLayoutShift} > ${budget.cumulativeLayoutShift}`);
        }
        return {
            passed: violations.length === 0,
            violations
        };
    }
}
exports.UXMetricsCollector = UXMetricsCollector;
//# sourceMappingURL=ux-metrics.js.map