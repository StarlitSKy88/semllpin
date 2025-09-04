const tsConfigPaths = require('tsconfig-paths');
const tsConfig = require('./tsconfig.json');

// 注册路径映射
tsConfigPaths.register({
  baseUrl: './dist',
  paths: {
    '@/*': ['*']
  }
});