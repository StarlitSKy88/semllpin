// Simple test script to verify annotation ID creation
const { execSync } = require('child_process');

function runTest() {
  try {
    console.log('🧪 Running annotation ID test...');
    
    // Run a simple Jest test that focuses on annotation creation
    const result = execSync('npx jest --testNamePattern="should create annotation" tests/e2e/user-interactions.test.js --config=jest.e2e.config.js --verbose --silent', {
      encoding: 'utf8',
      timeout: 30000
    });
    
    console.log('✅ Test completed successfully');
    console.log(result);
    
  } catch (error) {
    console.log('📝 Test output:');
    console.log(error.stdout || '');
    console.log('❌ Test errors:');
    console.log(error.stderr || '');
  }
}

runTest();