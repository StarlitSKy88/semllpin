"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const test_1 = require("@playwright/test");
async function globalSetup(config) {
    const browser = await test_1.chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    console.log('🚀 Starting global setup for SmellPin E2E tests...');
    try {
        await page.goto('http://localhost:3003/api/test/cleanup', {
            waitUntil: 'networkidle'
        });
        console.log('✅ Test data cleanup completed');
    }
    catch (error) {
        console.log('⚠️  Test cleanup endpoint not available, continuing...');
    }
    try {
        await page.goto('http://localhost:3003/api/test/seed', {
            waitUntil: 'networkidle'
        });
        console.log('✅ Test data seeding completed');
    }
    catch (error) {
        console.log('⚠️  Test seeding endpoint not available, continuing...');
    }
    const services = [
        { name: 'Backend API', url: 'http://localhost:3003/health' }
    ];
    for (const service of services) {
        try {
            await page.goto(service.url, {
                waitUntil: 'networkidle',
                timeout: 30000
            });
            console.log(`✅ ${service.name} is available`);
        }
        catch (error) {
            console.error(`❌ ${service.name} is not available at ${service.url}`);
            throw error;
        }
    }
    await context.close();
    await browser.close();
    console.log('🎉 Global setup completed successfully!');
}
exports.default = globalSetup;
//# sourceMappingURL=global-setup.js.map