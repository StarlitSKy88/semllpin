const jwt = require('jsonwebtoken');

// 使用默认的JWT secret
const JWT_SECRET = 'your-secret-key';

// 测试令牌
const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXItaWQtMTIzIiwiZW1haWwiOiJ0ZXN0dXNlcjEyMzQ1QGV4YW1wbGUuY29tIiwidXNlcm5hbWUiOiJ0ZXN0dXNlcjEyMzQ1Iiwicm9sZSI6InVzZXIiLCJpYXQiOjE3NTYxNzAxMjksImV4cCI6MTc1NjE3MzcyOX0.cc_eIRoU8IlX69MK4GJqf0WXXexptQeI-I87ATw9rsE';

console.log('Testing JWT verification...');
console.log('Token:', token);
console.log('Secret:', JWT_SECRET);

try {
  const decoded = jwt.verify(token, JWT_SECRET);
  console.log('Token verification successful!');
  console.log('Decoded payload:', decoded);
} catch (error) {
  console.log('Token verification failed!');
  console.log('Error:', error.message);
}

// 也测试解码（不验证签名）
console.log('\nDecoding without verification:');
const decodedWithoutVerify = jwt.decode(token);
console.log('Decoded payload:', decodedWithoutVerify);