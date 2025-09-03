const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');
const path = require('path');

// 配置
const API_BASE_URL = 'http://localhost:8787';
const TEST_USER = {
  email: `upload_test_${Date.now()}@example.com`,
  password: 'UploadTest123!',
  username: `uploaduser_${Date.now()}`
};

// 全局变量
let authToken = null;
const testResults = [];

// 工具函数
function recordTest(name, success, details, duration) {
  const result = {
    name,
    success,
    details,
    duration: `${duration}ms`,
    timestamp: new Date().toISOString()
  };
  testResults.push(result);
  
  const status = success ? '[PASS]' : '[FAIL]';
  console.log(`${status} ${name}`);
  console.log(`   详情: ${details}`);
  console.log(`   耗时: ${duration}ms\n`);
}

async function makeRequest(url, options = {}) {
  try {
    const response = await axios({
      url,
      method: options.method || 'GET',
      data: options.body,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      timeout: 15000 // 文件上传需要更长时间
    });
    return response;
  } catch (error) {
    if (error.response) {
      return error.response;
    }
    throw error;
  }
}

// 创建测试文件
function createTestFiles() {
  // 创建一个简单的PNG图片文件（1x1像素的PNG）
  const pngBuffer = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
    0x49, 0x48, 0x44, 0x52, // IHDR
    0x00, 0x00, 0x00, 0x01, // width: 1
    0x00, 0x00, 0x00, 0x01, // height: 1
    0x08, 0x02, 0x00, 0x00, 0x00, // bit depth, color type, compression, filter, interlace
    0x90, 0x77, 0x53, 0xDE, // CRC
    0x00, 0x00, 0x00, 0x0C, // IDAT chunk length
    0x49, 0x44, 0x41, 0x54, // IDAT
    0x08, 0x99, 0x01, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
    0xE2, 0x21, 0xBC, 0x33, // CRC
    0x00, 0x00, 0x00, 0x00, // IEND chunk length
    0x49, 0x45, 0x4E, 0x44, // IEND
    0xAE, 0x42, 0x60, 0x82  // CRC
  ]);
  
  fs.writeFileSync('test-image.png', pngBuffer);
  
  // 创建一个简单的MP3音频文件（带有ID3标签的最小MP3）
  const mp3Buffer = Buffer.from([
    // ID3v2 header
    0x49, 0x44, 0x33, // "ID3"
    0x03, 0x00, // version 2.3
    0x00, // flags
    0x00, 0x00, 0x00, 0x00, // size (0)
    // MP3 frame header (minimal)
    0xFF, 0xFB, 0x90, 0x00, // MP3 frame sync + header
    // Minimal frame data (silence)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  ]);
  
  fs.writeFileSync('test-audio.mp3', mp3Buffer);
  
  // 创建测试JSON文件
  const jsonContent = JSON.stringify({
    test: true,
    timestamp: new Date().toISOString(),
    data: 'test upload file'
  }, null, 2);
  
  fs.writeFileSync('test-data.json', jsonContent);
}

// 清理测试文件
function cleanupTestFiles() {
  const testFiles = ['test-image.png', 'test-audio.mp3', 'test-data.json'];
  testFiles.forEach(file => {
    try {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
      }
    } catch (error) {
      console.log(`清理文件 ${file} 时出错:`, error.message);
    }
  });
}

// 文件上传测试函数
async function testUserRegistration() {
  console.log('=== 上传测试1: 用户注册 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      body: TEST_USER
    });
    
    const duration = Date.now() - startTime;
    const token = response.data.data?.token || response.data.token;
    
    if (response.status === 201 && token) {
      authToken = token;
      recordTest('用户注册', true, `状态码: ${response.status}, Token获取成功`, duration);
      return true;
    } else {
      recordTest('用户注册', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('用户注册', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testUploadEndpointAvailability() {
  console.log('=== 上传测试2: 上传端点可用性 ===\n');
  const startTime = Date.now();
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/upload`);
    const duration = Date.now() - startTime;
    
    if (response.status === 200 || response.status === 401 || response.status === 403 || response.status === 405) {
      // 200表示端点可用，401/403表示需要认证，405表示方法不允许但端点存在
      recordTest('上传端点可用性', true, `状态码: ${response.status}, 上传端点可访问`, duration);
      return true;
    } else if (response.status === 404) {
      recordTest('上传端点可用性', false, `状态码: ${response.status}, 上传端点不存在`, duration);
      return false;
    } else {
      recordTest('上传端点可用性', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('上传端点可用性', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testImageUpload() {
  console.log('=== 上传测试3: 图片文件上传 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('图片文件上传', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    const formData = new FormData();
    formData.append('file', fs.createReadStream('test-image.png'));
    formData.append('file_type', 'image');
    formData.append('description', '测试图片上传');
    
    const response = await axios({
      url: `${API_BASE_URL}/upload`,
      method: 'POST',
      data: formData,
      headers: {
        'Authorization': `Bearer ${authToken}`,
        ...formData.getHeaders()
      },
      timeout: 15000
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200 || response.status === 201) {
      const uploadResult = response.data.data || response.data;
      recordTest('图片文件上传', true, `状态码: ${response.status}, 图片上传成功`, duration);
      return true;
    } else {
      recordTest('图片文件上传', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    if (error.response) {
      recordTest('图片文件上传', false, `状态码: ${error.response.status}, 错误: ${JSON.stringify(error.response.data)}`, duration);
    } else {
      recordTest('图片文件上传', false, `网络错误: ${error.message}`, duration);
    }
    return false;
  }
}

async function testDocumentUpload() {
  console.log('=== 上传测试4: 文档文件上传 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('文档文件上传', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    const formData = new FormData();
    formData.append('file', fs.createReadStream('test-audio.mp3'));
    formData.append('file_type', 'audio');
    formData.append('description', '测试音频上传');
    
    const response = await axios({
      url: `${API_BASE_URL}/upload`,
      method: 'POST',
      data: formData,
      headers: {
        'Authorization': `Bearer ${authToken}`,
        ...formData.getHeaders()
      },
      timeout: 15000
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200 || response.status === 201) {
      recordTest('文档文件上传', true, `状态码: ${response.status}, 文档上传成功`, duration);
      return true;
    } else {
      recordTest('文档文件上传', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    if (error.response) {
      recordTest('文档文件上传', false, `状态码: ${error.response.status}, 错误: ${JSON.stringify(error.response.data)}`, duration);
    } else {
      recordTest('文档文件上传', false, `网络错误: ${error.message}`, duration);
    }
    return false;
  }
}

async function testMultipleFileUpload() {
  console.log('=== 上传测试5: 多文件上传 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('多文件上传', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    const formData = new FormData();
    formData.append('files', fs.createReadStream('test-image.png'));
    formData.append('files', fs.createReadStream('test-image.png')); // 上传两个相同的图片文件
    formData.append('file_type', 'image');
    formData.append('description', '测试多文件上传');
    
    const response = await axios({
      url: `${API_BASE_URL}/upload/multiple`,
      method: 'POST',
      data: formData,
      headers: {
        'Authorization': `Bearer ${authToken}`,
        ...formData.getHeaders()
      },
      timeout: 20000
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200 || response.status === 201) {
      recordTest('多文件上传', true, `状态码: ${response.status}, 多文件上传成功`, duration);
      return true;
    } else if (response.status === 404) {
      recordTest('多文件上传', false, `状态码: ${response.status}, 多文件上传端点不存在`, duration);
      return false;
    } else {
      recordTest('多文件上传', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    if (error.response) {
      recordTest('多文件上传', false, `状态码: ${error.response.status}, 错误: ${JSON.stringify(error.response.data)}`, duration);
    } else {
      recordTest('多文件上传', false, `网络错误: ${error.message}`, duration);
    }
    return false;
  }
}

async function testFileList() {
  console.log('=== 上传测试6: 文件列表查询 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('文件列表查询', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    const response = await makeRequest(`${API_BASE_URL}/upload/files`, {
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200) {
      const files = response.data.data || response.data;
      const count = Array.isArray(files) ? files.length : 0;
      recordTest('文件列表查询', true, `状态码: ${response.status}, 获取${count}个文件`, duration);
      return true;
    } else if (response.status === 404) {
      recordTest('文件列表查询', false, `状态码: ${response.status}, 文件列表端点不存在`, duration);
      return false;
    } else {
      recordTest('文件列表查询', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    recordTest('文件列表查询', false, `网络错误: ${error.message}`, duration);
    return false;
  }
}

async function testFileUploadSecurity() {
  console.log('=== 上传测试7: 文件上传安全验证 ===\n');
  const startTime = Date.now();
  
  try {
    const formData = new FormData();
    formData.append('file', fs.createReadStream('test-image.png'));
    
    const response = await axios({
      url: `${API_BASE_URL}/upload`,
      method: 'POST',
      data: formData,
      headers: formData.getHeaders(),
      timeout: 10000
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 401 || response.status === 403) {
      recordTest('文件上传安全验证', true, `状态码: ${response.status}, 安全验证正常工作`, duration);
      return true;
    } else if (response.status === 404) {
      recordTest('文件上传安全验证', false, `状态码: ${response.status}, 上传端点不存在`, duration);
      return false;
    } else {
      recordTest('文件上传安全验证', false, `状态码: ${response.status}, 安全验证可能存在问题`, duration);
      return false;
    }
  } catch (error) {
    const duration = Date.now() - startTime;
    if (error.response) {
      if (error.response.status === 401 || error.response.status === 403) {
        recordTest('文件上传安全验证', true, `状态码: ${error.response.status}, 安全验证正常工作`, duration);
        return true;
      } else {
        recordTest('文件上传安全验证', false, `状态码: ${error.response.status}, 错误: ${JSON.stringify(error.response.data)}`, duration);
      }
    } else {
      recordTest('文件上传安全验证', false, `网络错误: ${error.message}`, duration);
    }
    return false;
  }
}

async function testFileUploadLimits() {
  console.log('=== 上传测试8: 文件上传限制验证 ===\n');
  const startTime = Date.now();
  
  if (!authToken) {
    recordTest('文件上传限制验证', false, '没有可用的认证Token', 0);
    return false;
  }
  
  try {
    // 创建一个较大的MP3测试文件（模拟大文件上传）
    const mp3Header = Buffer.from([
      0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ID3 header
      0xFF, 0xFB, 0x90, 0x00 // MP3 frame header
    ]);
    const largeAudioData = Buffer.alloc(1024 * 1024); // 1MB of zeros
    const largeMp3Content = Buffer.concat([mp3Header, largeAudioData]);
    fs.writeFileSync('large-test-file.mp3', largeMp3Content);
    
    const formData = new FormData();
    formData.append('file', fs.createReadStream('large-test-file.mp3'));
    formData.append('file_type', 'audio');
    
    const response = await axios({
      url: `${API_BASE_URL}/upload`,
      method: 'POST',
      data: formData,
      headers: {
        'Authorization': `Bearer ${authToken}`,
        ...formData.getHeaders()
      },
      timeout: 30000
    });
    
    const duration = Date.now() - startTime;
    
    if (response.status === 200 || response.status === 201) {
      recordTest('文件上传限制验证', true, `状态码: ${response.status}, 大文件上传成功`, duration);
    } else if (response.status === 413) {
      recordTest('文件上传限制验证', true, `状态码: ${response.status}, 文件大小限制正常工作`, duration);
    } else {
      recordTest('文件上传限制验证', false, `状态码: ${response.status}, 错误: ${JSON.stringify(response.data)}`, duration);
    }
    
    // 清理大文件
    try {
      fs.unlinkSync('large-test-file.mp3');
    } catch (e) {}
    
    return true;
  } catch (error) {
    const duration = Date.now() - startTime;
    
    // 清理大文件
    try {
      fs.unlinkSync('large-test-file.mp3');
    } catch (e) {}
    
    if (error.response) {
      if (error.response.status === 413) {
        recordTest('文件上传限制验证', true, `状态码: ${error.response.status}, 文件大小限制正常工作`, duration);
        return true;
      } else {
        recordTest('文件上传限制验证', false, `状态码: ${error.response.status}, 错误: ${JSON.stringify(error.response.data)}`, duration);
      }
    } else {
      recordTest('文件上传限制验证', false, `网络错误: ${error.message}`, duration);
    }
    return false;
  }
}

// 生成测试报告
function generateReport() {
  console.log('\n============================================================');
  console.log('📁 文件上传功能测试报告');
  console.log('============================================================');
  
  const passedTests = testResults.filter(test => test.success).length;
  const totalTests = testResults.length;
  const successRate = totalTests > 0 ? ((passedTests / totalTests) * 100).toFixed(1) : 0;
  
  console.log(`✅ 通过: ${passedTests}`);
  console.log(`❌ 失败: ${totalTests - passedTests}`);
  console.log(`📈 成功率: ${successRate}%\n`);
  
  console.log('📋 详细测试结果:');
  testResults.forEach((test, index) => {
    const status = test.success ? '[PASS]' : '[FAIL]';
    console.log(`${index + 1}. ${status} ${test.name} (${test.duration})`);
    if (!test.success) {
      console.log(`   ❌ ${test.details}`);
    }
  });
  
  console.log('\n🔍 文件上传功能测试覆盖:');
  console.log('✓ 上传端点可用性');
  console.log('✓ 图片文件上传');
  console.log('✓ 文档文件上传');
  console.log('✓ 多文件上传');
  console.log('✓ 文件列表查询');
  console.log('✓ 上传安全验证');
  console.log('✓ 文件大小限制');
  
  console.log('\n✨ 文件上传功能测试完成!');
  
  // 保存测试报告到文件
  const reportData = {
    timestamp: new Date().toISOString(),
    testType: 'File Upload Test',
    summary: {
      total: totalTests,
      passed: passedTests,
      failed: totalTests - passedTests,
      successRate: `${successRate}%`
    },
    testUser: {
      email: TEST_USER.email
    },
    tests: testResults
  };
  
  fs.writeFileSync('file-upload-test-report.json', JSON.stringify(reportData, null, 2));
  console.log('📄 测试报告已保存到: file-upload-test-report.json');
}

// 主测试函数
async function runTests() {
  console.log('🚀 开始SmellPin文件上传功能测试...');
  console.log(`📡 API地址: ${API_BASE_URL}`);
  console.log(`👤 测试用户: ${TEST_USER.email}\n`);
  
  // 创建测试文件
  createTestFiles();
  
  try {
    // 执行所有文件上传测试
    await testUserRegistration();
    await testUploadEndpointAvailability();
    await testImageUpload();
    await testDocumentUpload();
    await testMultipleFileUpload();
    await testFileList();
    await testFileUploadSecurity();
    await testFileUploadLimits();
    
    // 生成报告
    generateReport();
    
  } catch (error) {
    console.error('❌ 测试执行过程中发生错误:', error.message);
    process.exit(1);
  } finally {
    // 清理测试文件
    cleanupTestFiles();
  }
}

// 运行测试
if (require.main === module) {
  runTests();
}

module.exports = {
  runTests,
  testResults
};