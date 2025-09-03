"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const test_1 = require("@playwright/test");
async function globalTeardown(config) {
    const browser = await test_1.chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    console.log('🧹 Starting global teardown for SmellPin E2E tests...');
    try {
        await page.goto('http://localhost:3000/api/test/cleanup', {
            waitUntil: 'networkidle'
        });
        console.log('✅ Test data cleanup completed');
    }
    catch (error) {
        console.log('⚠️  Test cleanup endpoint not available during teardown');
    }
    try {
        await page.goto('http://localhost:3000/api/test/cleanup-files', {
            waitUntil: 'networkidle'
        });
        console.log('✅ Test files cleanup completed');
    }
    catch (error) {
        console.log('⚠️  Test files cleanup endpoint not available');
    }
    await context.close();
    await browser.close();
    console.log('🎉 Global teardown completed successfully!');
}
exports.default = globalTeardown;
//# sourceMappingURL=global-teardown.js.map