#!/usr/bin/env node

/**
 * SmellPin 地理编码服务API测试脚本
 * 测试所有地理编码功能端点
 */

const axios = require('axios');

const BASE_URL = process.env.BASE_URL || 'http://localhost:3004/api/v1/geocoding';

console.log('\n🌍 SmellPin 地理编码服务API测试\n');

async function testAPI() {
  try {
    // 1. 测试地址搜索 (Geocoding)
    console.log('1️⃣ 测试地址搜索 (Geocoding)...');
    
    const geocodeTests = [
      { q: '北京天安门', country: 'CN' },
      { q: 'Times Square New York', country: 'US' },
      { q: '东京塔', limit: 3 }
    ];

    for (const test of geocodeTests) {
      try {
        const response = await axios.get(`${BASE_URL}/search`, { params: test });
        if (response.data.success) {
          console.log(`✅ 地址搜索 "${test.q}": 找到 ${response.data.data.results.length} 个结果`);
          if (response.data.data.results.length > 0) {
            const first = response.data.data.results[0];
            console.log(`   📍 ${first.formatted_address_zh}`);
            console.log(`   🎯 坐标: ${first.coordinates.latitude}, ${first.coordinates.longitude}`);
          }
        } else {
          console.log(`❌ 地址搜索失败: ${response.data.error}`);
        }
      } catch (error) {
        console.log(`❌ 地址搜索错误: ${error.message}`);
      }
      console.log(''); // 空行
    }

    // 2. 测试反向地理编码 (Reverse Geocoding)
    console.log('2️⃣ 测试反向地理编码 (Reverse Geocoding)...');
    
    const reverseTests = [
      { lat: 39.9042, lng: 116.4074, description: '天安门广场' },
      { lat: 40.7589, lng: -73.9851, description: '纽约时代广场' },
      { lat: 35.6586, lng: 139.7454, description: '东京塔' }
    ];

    for (const test of reverseTests) {
      try {
        const response = await axios.get(`${BASE_URL}/reverse`, { 
          params: { lat: test.lat, lng: test.lng, zoom: 18 } 
        });
        if (response.data.success && response.data.data.result) {
          console.log(`✅ 反向地理编码 ${test.description}:`);
          console.log(`   📍 ${response.data.data.result.formatted_address_zh}`);
          console.log(`   🌐 ${response.data.data.result.formatted_address_en}`);
        } else {
          console.log(`❌ 反向地理编码失败: ${response.data.error || 'No result'}`);
        }
      } catch (error) {
        console.log(`❌ 反向地理编码错误: ${error.message}`);
      }
      console.log(''); // 空行
    }

    // 3. 测试附近POI搜索
    console.log('3️⃣ 测试附近POI搜索...');
    
    const poiTests = [
      { lat: 39.9042, lng: 116.4074, type: 'restaurant', description: '天安门附近餐厅' },
      { lat: 40.7589, lng: -73.9851, type: 'hotel', description: '时代广场附近酒店' },
      { lat: 35.6586, lng: 139.7454, type: 'atm', description: '东京塔附近ATM' }
    ];

    for (const test of poiTests) {
      try {
        const response = await axios.get(`${BASE_URL}/nearby`, { 
          params: { 
            lat: test.lat, 
            lng: test.lng, 
            type: test.type, 
            radius: 2,
            limit: 5
          } 
        });
        if (response.data.success) {
          console.log(`✅ POI搜索 "${test.description}": 找到 ${response.data.data.results.length} 个结果`);
          response.data.data.results.slice(0, 3).forEach((poi, index) => {
            console.log(`   ${index + 1}. ${poi.name || poi.display_name} - ${poi.distance_text || '距离未知'}`);
          });
        } else {
          console.log(`❌ POI搜索失败: ${response.data.error}`);
        }
      } catch (error) {
        console.log(`❌ POI搜索错误: ${error.message}`);
      }
      console.log(''); // 空行
    }

    // 4. 测试IP地理定位
    console.log('4️⃣ 测试IP地理定位...');
    
    try {
      const response = await axios.get(`${BASE_URL}/ip-location`);
      if (response.data.success) {
        const location = response.data.data.result;
        console.log('✅ IP地理定位成功:');
        console.log(`   📍 位置: ${location.address.city}, ${location.address.region}, ${location.address.country}`);
        console.log(`   🎯 坐标: ${location.coordinates.latitude}, ${location.coordinates.longitude}`);
        console.log(`   🌐 IP: ${location.ip} (${location.isp})`);
      } else {
        console.log(`❌ IP地理定位失败: ${response.data.error}`);
      }
    } catch (error) {
      console.log(`❌ IP地理定位错误: ${error.message}`);
    }
    console.log(''); // 空行

    // 5. 测试POI类型列表
    console.log('5️⃣ 测试POI类型列表...');
    
    try {
      const response = await axios.get(`${BASE_URL}/poi-types`);
      if (response.data.success) {
        console.log(`✅ 获取POI类型列表: ${response.data.data.poi_types.length} 种类型`);
        console.log('   支持的POI类型:');
        response.data.data.poi_types.slice(0, 6).forEach(poi => {
          console.log(`   • ${poi.name} (${poi.name_en}) - ${poi.type}`);
        });
        if (response.data.data.poi_types.length > 6) {
          console.log(`   • ... 还有 ${response.data.data.poi_types.length - 6} 种类型`);
        }
      } else {
        console.log(`❌ 获取POI类型列表失败: ${response.data.error}`);
      }
    } catch (error) {
      console.log(`❌ 获取POI类型列表错误: ${error.message}`);
    }

    // 6. 测试缓存统计（开发环境）
    if (process.env.NODE_ENV !== 'production') {
      console.log('\n6️⃣ 测试缓存统计（开发环境）...');
      
      try {
        const response = await axios.get(`${BASE_URL}/cache/stats`);
        if (response.data.success) {
          console.log('✅ 缓存统计获取成功:');
          console.log(`   📦 缓存键数量: ${response.data.data.keys}`);
          console.log(`   🎯 命中次数: ${response.data.data.hits}`);
          console.log(`   ❌ 未命中次数: ${response.data.data.misses}`);
        } else {
          console.log(`❌ 获取缓存统计失败: ${response.data.error}`);
        }
      } catch (error) {
        console.log(`❌ 获取缓存统计错误: ${error.message}`);
      }
    }

  } catch (error) {
    console.log('\n❌ 测试过程中发生错误:', error.message);
    if (error.code === 'ECONNREFUSED') {
      console.log('\n💡 请确保后端服务正在运行在 http://localhost:3000');
      console.log('   可以运行: npm run dev');
    }
  }
}

// 性能测试函数
async function performanceTest() {
  console.log('\n🚀 性能测试...');
  
  const testCases = [
    { q: '北京', country: 'CN' },
    { q: '上海', country: 'CN' },
    { q: '广州', country: 'CN' }
  ];

  console.log('测试同一查询的缓存效果...');
  
  for (const testCase of testCases) {
    try {
      // 第一次请求（无缓存）
      const start1 = Date.now();
      const response1 = await axios.get(`${BASE_URL}/search`, { params: testCase });
      const time1 = Date.now() - start1;

      // 第二次请求（有缓存）
      const start2 = Date.now();
      const response2 = await axios.get(`${BASE_URL}/search`, { params: testCase });
      const time2 = Date.now() - start2;

      if (response1.data.success && response2.data.success) {
        console.log(`✅ "${testCase.q}" - 首次: ${time1}ms, 缓存: ${time2}ms (${time1 > time2 ? '缓存有效' : '可能无缓存'})`);
      }
    } catch (error) {
      console.log(`❌ 性能测试错误: ${error.message}`);
    }
  }
}

// 运行测试
async function runTests() {
  await testAPI();
  await performanceTest();
  
  console.log('\n✨ 地理编码API测试完成！\n');
  console.log('📚 API文档说明:');
  console.log('• GET /api/v1/geocoding/search?q=地址&country=CN&limit=5');
  console.log('• GET /api/v1/geocoding/reverse?lat=39.9042&lng=116.4074&zoom=18');
  console.log('• GET /api/v1/geocoding/nearby?lat=39.9042&lng=116.4074&type=restaurant&radius=2&limit=10');
  console.log('• GET /api/v1/geocoding/ip-location?ip=8.8.8.8');
  console.log('• GET /api/v1/geocoding/poi-types');
  console.log('\n🎯 所有API都支持中英文地址查询和返回结果');
}

// 捕获未处理的错误
process.on('unhandledRejection', (err) => {
  console.error('❌ 未处理的Promise拒绝:', err);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('❌ 未捕获的异常:', err);
  process.exit(1);
});

// 运行测试
runTests().catch(console.error);