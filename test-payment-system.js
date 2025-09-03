// Test script for payment system functionality
const API_BASE = 'http://localhost:8787';

async function testPaymentSystem() {
  console.log('🧪 Testing Payment System...');
  
  try {
    // Test 1: Create payment intent without authentication (should work with test endpoint)
    console.log('\n1. Testing payment creation (test endpoint)...');
    const testPaymentResponse = await fetch(`${API_BASE}/payments/test-create`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    console.log('Test payment status:', testPaymentResponse.status);
    const testPaymentResult = await testPaymentResponse.text();
    console.log('Test payment response:', testPaymentResult);
    
    // Test 2: Register a user for authenticated payment test
    console.log('\n2. Registering test user...');
    const registerResponse = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: `payment-test-${Date.now()}@example.com`,
        password: 'testpassword123',
        username: `paymentuser${Date.now()}`
      })
    });
    
    const registerResult = await registerResponse.json();
    console.log('Registration result:', registerResult);
    
    if (registerResult.success && registerResult.data && registerResult.data.token) {
      // Test 3: Create payment intent with authentication
      console.log('\n3. Testing authenticated payment creation...');
      const authPaymentResponse = await fetch(`${API_BASE}/payments/create`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${registerResult.data.token}`
        },
        body: JSON.stringify({
          amount: 1000, // $10.00
          currency: 'usd',
          description: 'Test payment with auth'
        })
      });
      
      console.log('Authenticated payment status:', authPaymentResponse.status);
      const authPaymentResult = await authPaymentResponse.text();
      console.log('Authenticated payment response:', authPaymentResult);
    } else {
      console.log('❌ Registration failed, cannot test authenticated payment');
    }
    
  } catch (error) {
    console.error('❌ Payment test error:', error.message);
    console.error('Error stack:', error.stack);
  }
  
  console.log('\n✅ Payment system test completed');
}

// Run the test
testPaymentSystem();