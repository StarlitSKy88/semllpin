// Artillery多Agent处理器 - SmellPin自动化测试方案2.0

const { faker } = require('@faker-js/faker');

// 配置Faker为中文
faker.locale = 'zh_CN';

// 模拟数据池
const smellTypes = ['食物香味', '垃圾异味', '化学品味', '花香', '汽油味', '香水味', '烟味', '油漆味'];
const locationNames = ['天安门广场', '故宫博物院', '天坛公园', '颐和园', '北海公园', '景山公园', '雍和宫', '国家博物馆'];
const searchQueries = ['食物', '垃圾', '香味', '异味', '测试', '北京', '公园', '地铁站'];

// 预设用户池
const activeUsers = [
  { email: 'active1@smellpin.test', password: 'Active123!' },
  { email: 'active2@smellpin.test', password: 'Active123!' },
  { email: 'active3@smellpin.test', password: 'Active123!' },
  { email: 'active4@smellpin.test', password: 'Active123!' },
  { email: 'active5@smellpin.test', password: 'Active123!' }
];

const socialUsers = [
  { email: 'social1@smellpin.test', password: 'Social123!' },
  { email: 'social2@smellpin.test', password: 'Social123!' },
  { email: 'social3@smellpin.test', password: 'Social123!' }
];

const mobileUsers = [
  { email: 'mobile1@smellpin.test', password: 'Mobile123!' },
  { email: 'mobile2@smellpin.test', password: 'Mobile123!' }
];

// 移动轨迹模拟（北京市内的路线）
let movementPaths = [
  [
    { lat: 39.9042, lng: 116.4074 }, // 天安门
    { lat: 39.9163, lng: 116.3972 }, // 故宫
    { lat: 39.9280, lng: 116.3830 }, // 北海
  ],
  [
    { lat: 39.8847, lng: 116.3975 }, // 天坛
    { lat: 39.8950, lng: 116.4100 }, // 前门
    { lat: 39.9042, lng: 116.4074 }, // 天安门
  ]
];

let userMovementState = new Map();

// 生成新用户数据
function generateNewUserData(requestParams, context, ee, next) {
  const timestamp = Date.now();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  
  context.vars.newUsername = `newuser_${timestamp}_${randomSuffix}`;
  context.vars.newEmail = `newuser_${timestamp}_${randomSuffix}@smellpin.test`;
  context.vars.newPassword = 'NewUser123!';
  context.vars.newFirstName = faker.person.firstName();
  context.vars.newLastName = faker.person.lastName();
  
  return next();
}

// 生成标注数据
function generateAnnotationData(requestParams, context, ee, next) {
  const smellType = smellTypes[Math.floor(Math.random() * smellTypes.length)];
  const location = locationNames[Math.floor(Math.random() * locationNames.length)];
  
  context.vars.annotationTitle = `${faker.person.firstName()}发现的${smellType}`;
  context.vars.annotationDescription = `在${location}附近发现了${smellType}，强度为${Math.floor(Math.random() * 5) + 1}级。`;
  context.vars.smellType = smellType;
  context.vars.intensity = Math.floor(Math.random() * 5) + 1;
  context.vars.latitude = 39.85 + Math.random() * 0.15; // 北京范围内
  context.vars.longitude = 116.30 + Math.random() * 0.20;
  context.vars.locationName = location;
  
  return next();
}

// 获取活跃用户凭据
function getActiveUserCredentials(requestParams, context, ee, next) {
  const user = activeUsers[Math.floor(Math.random() * activeUsers.length)];
  context.vars.activeUserEmail = user.email;
  context.vars.activeUserPassword = user.password;
  
  // 模拟活跃用户已有的标注ID列表
  context.vars.annotationIds = [
    Math.floor(Math.random() * 100) + 1,
    Math.floor(Math.random() * 100) + 1,
    Math.floor(Math.random() * 100) + 1
  ];
  
  return next();
}

// 生成随机标注数据
function generateRandomAnnotation(requestParams, context, ee, next) {
  const smellType = smellTypes[Math.floor(Math.random() * smellTypes.length)];
  
  context.vars.randomTitle = `随机标注_${Date.now()}`;
  context.vars.randomDescription = faker.lorem.sentence();
  context.vars.randomSmellType = smellType;
  context.vars.randomIntensity = Math.floor(Math.random() * 5) + 1;
  context.vars.randomLatitude = 39.85 + Math.random() * 0.15;
  context.vars.randomLongitude = 116.30 + Math.random() * 0.20;
  
  return next();
}

// 生成搜索查询
function generateSearchQuery(requestParams, context, ee, next) {
  context.vars.searchQuery = searchQueries[Math.floor(Math.random() * searchQueries.length)];
  return next();
}

// 生成地理搜索参数
function generateGeoSearch(requestParams, context, ee, next) {
  context.vars.geoLat = 39.85 + Math.random() * 0.15;
  context.vars.geoLng = 116.30 + Math.random() * 0.20;
  context.vars.geoRadius = Math.floor(Math.random() * 5000) + 500; // 500m - 5.5km
  
  return next();
}

// 获取社交用户凭据
function getSocialUserCredentials(requestParams, context, ee, next) {
  const user = socialUsers[Math.floor(Math.random() * socialUsers.length)];
  context.vars.socialUserEmail = user.email;
  context.vars.socialUserPassword = user.password;
  
  return next();
}

// 获取移动用户凭据
function getMobileUserCredentials(requestParams, context, ee, next) {
  const user = mobileUsers[Math.floor(Math.random() * mobileUsers.length)];
  context.vars.mobileUserEmail = user.email;
  context.vars.mobileUserPassword = user.password;
  
  // 初始化用户移动状态
  const userId = `${user.email}_${context.vars.$uuid}`;
  if (!userMovementState.has(userId)) {
    const pathIndex = Math.floor(Math.random() * movementPaths.length);
    userMovementState.set(userId, {
      pathIndex: pathIndex,
      positionIndex: 0,
      path: movementPaths[pathIndex]
    });
  }
  
  context.vars.mobileUserId = userId;
  
  return next();
}

// 模拟移动设备位置变化
function simulateMovement(requestParams, context, ee, next) {
  const userId = context.vars.mobileUserId;
  let userState = userMovementState.get(userId);
  
  if (!userState) {
    // 如果没有状态，创建一个
    const pathIndex = Math.floor(Math.random() * movementPaths.length);
    userState = {
      pathIndex: pathIndex,
      positionIndex: 0,
      path: movementPaths[pathIndex]
    };
  }
  
  // 获取当前位置
  const currentPosition = userState.path[userState.positionIndex];
  
  // 添加一些随机偏移来模拟GPS不准确性
  const latOffset = (Math.random() - 0.5) * 0.001; // ±50米左右
  const lngOffset = (Math.random() - 0.5) * 0.001;
  
  context.vars.currentLat = currentPosition.lat + latOffset;
  context.vars.currentLng = currentPosition.lng + lngOffset;
  
  // 移动到路径上的下一个点
  userState.positionIndex = (userState.positionIndex + 1) % userState.path.length;
  userMovementState.set(userId, userState);
  
  return next();
}

// 生成移动设备标注
function generateMobileAnnotation(requestParams, context, ee, next) {
  const smellType = smellTypes[Math.floor(Math.random() * smellTypes.length)];
  
  context.vars.mobileTitle = `移动发现: ${smellType}`;
  context.vars.mobileDescription = `通过移动设备在此位置发现${smellType}`;
  context.vars.mobileSmellType = smellType;
  context.vars.mobileIntensity = Math.floor(Math.random() * 5) + 1;
  
  return next();
}

// 随机选择数组元素的辅助函数
function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// 生成随机字符串的辅助函数  
function randomString(length = 8) {
  return Math.random().toString(36).substring(2, 2 + length);
}

// 生成随机整数的辅助函数
function randomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// 生成随机浮点数的辅助函数
function randomFloat(min, max) {
  return Math.random() * (max - min) + min;
}

// 日志记录增强
function logAgentActivity(requestParams, context, ee, next) {
  const agentType = context.vars.agentType || 'unknown';
  const action = context.vars.lastAction || 'unknown';
  
  console.log(`[Agent: ${agentType}] Performing: ${action} at ${new Date().toISOString()}`);
  
  return next();
}

// 性能指标收集
function collectMetrics(requestParams, context, ee, next) {
  const startTime = Date.now();
  context.vars._requestStartTime = startTime;
  
  return next();
}

// 错误处理
function handleError(requestParams, context, ee, next) {
  if (context.vars.$failed) {
    console.error(`Agent request failed: ${context.vars.$failed}`);
    
    // 可以在这里添加重试逻辑或错误恢复机制
    if (context.vars.retryCount < 3) {
      context.vars.retryCount = (context.vars.retryCount || 0) + 1;
      console.log(`Retrying request (attempt ${context.vars.retryCount})`);
    }
  }
  
  return next();
}

module.exports = {
  generateNewUserData,
  generateAnnotationData,
  getActiveUserCredentials,
  generateRandomAnnotation,
  generateSearchQuery,
  generateGeoSearch,
  getSocialUserCredentials,
  getMobileUserCredentials,
  simulateMovement,
  generateMobileAnnotation,
  logAgentActivity,
  collectMetrics,
  handleError,
  
  // 导出辅助函数供模板使用
  randomItem,
  randomString,
  randomInt,
  randomFloat
};