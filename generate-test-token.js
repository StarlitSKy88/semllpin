const jwt = require('jsonwebtoken');

// 使用.env文件中的JWT secret
const JWT_SECRET = 'your-secret-key-here';

// 生成测试用户的JWT令牌
const payload = {
  sub: 'test-user-id-123',
  email: 'testuser12345@example.com',
  username: 'testuser12345',
  role: 'user'
};

const token = jwt.sign(payload, JWT_SECRET, {
  expiresIn: '1h'
});

console.log('Generated JWT Token:');
console.log(token);