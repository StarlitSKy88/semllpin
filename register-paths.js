try {
  const tsConfigPaths = require('tsconfig-paths');
  const tsConfig = require('./tsconfig.json');

  // 注册路径映射
  tsConfigPaths.register({
    baseUrl: './dist',
    paths: {
      '@/*': ['*']
    }
  });
  
  console.log('✅ Path mapping registered successfully');
} catch (error) {
  console.warn('⚠️ tsconfig-paths not available, path mapping disabled:', error.message);
  // 在生产环境中，路径映射可能不是必需的，因为编译后的代码已经解析了所有路径
}