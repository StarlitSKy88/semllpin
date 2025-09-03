#!/usr/bin/env node

/**
 * SmellPin 测试Token获取工具
 * 此脚本帮助用户获取有效的测试token，用于绕过频率限制进行完整功能测试
 */

const axios = require('axios');
const readline = require('readline');

const colors = {
  red: (text) => `\x1b[31m${text}\x1b[0m`,
  green: (text) => `\x1b[32m${text}\x1b[0m`,
  yellow: (text) => `\x1b[33m${text}\x1b[0m`,
  blue: (text) => `\x1b[34m${text}\x1b[0m`,
  cyan: (text) => `\x1b[36m${text}\x1b[0m`,
  magenta: (text) => `\x1b[35m${text}\x1b[0m`
};

const config = {
  baseURL: 'http://localhost:3000',
  timeout: 10000
};

// 创建readline接口
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// 提示用户输入
function askQuestion(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim());
    });
  });
}

// 尝试使用现有用户登录
async function loginWithExistingUser(email, password) {
  try {
    console.log(colors.blue('🔐 尝试登录...'));
    
    const response = await axios.post(`${config.baseURL}/api/v1/auth/login`, {
      email,
      password
    }, {
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: config.timeout
    });
    
    if (response.data.success && response.data.data.token) {
      console.log(colors.green('✅ 登录成功!'));
      console.log(colors.cyan(`📋 用户信息:`));
      console.log(`   邮箱: ${response.data.data.user.email}`);
      console.log(`   用户名: ${response.data.data.user.username}`);
      console.log(`   显示名: ${response.data.data.user.display_name}`);
      
      console.log(colors.yellow('\n🔑 您的测试Token:'));
      console.log(colors.green(response.data.data.token));
      
      console.log(colors.cyan('\n💡 使用方法:'));
      console.log('1. 复制上面的token');
      console.log('2. 设置环境变量: export TEST_USER_TOKEN="your-token-here"');
      console.log('3. 运行: node test-with-existing-user.js');
      
      console.log(colors.cyan('\n或者直接运行:'));
      console.log(colors.green(`TEST_USER_TOKEN="${response.data.data.token}" node test-with-existing-user.js`));
      
      return response.data.data.token;
    } else {
      console.log(colors.red('❌ 登录失败: 响应格式不正确'));
      return null;
    }
  } catch (error) {
    if (error.response?.status === 429) {
      console.log(colors.yellow('⚠️  登录API频率限制: 每15分钟最多10次请求'));
      console.log(colors.cyan('💡 请等待15分钟后重试，或使用以下替代方案:'));
      console.log('1. 使用浏览器登录网站，从开发者工具获取token');
      console.log('2. 直接在数据库中查询现有用户的token');
      console.log('3. 临时调整API频率限制设置');
    } else if (error.response?.status === 401) {
      console.log(colors.red('❌ 登录失败: 邮箱或密码错误'));
    } else {
      console.log(colors.red('❌ 登录失败:'), error.response?.data?.message || error.message);
    }
    return null;
  }
}

// 提供数据库查询方案
function showDatabaseSolution() {
  console.log(colors.cyan('\n🗄️  数据库直接查询方案:'));
  console.log(colors.yellow('如果您有数据库访问权限，可以直接查询用户token:'));
  console.log('');
  console.log(colors.green('-- 查询现有用户'));
  console.log(colors.green('SELECT id, email, username, display_name FROM users LIMIT 5;'));
  console.log('');
  console.log(colors.green('-- 为用户生成新token（需要在应用中实现）'));
  console.log(colors.green('-- 或者查看现有的有效session'));
  console.log('');
  console.log(colors.cyan('💡 建议在开发环境中创建专门的测试用户:'));
  console.log('   邮箱: test@example.com');
  console.log('   密码: Test123456');
  console.log('   用户名: testuser');
}

// 提供浏览器获取token方案
function showBrowserSolution() {
  console.log(colors.cyan('\n🌐 浏览器获取Token方案:'));
  console.log('1. 打开浏览器，访问 http://localhost:3000');
  console.log('2. 打开开发者工具 (F12)');
  console.log('3. 进行用户登录');
  console.log('4. 在Network标签中查看登录请求的响应');
  console.log('5. 复制响应中的token字段');
  console.log('');
  console.log(colors.yellow('或者在Application/Storage标签中查看localStorage或sessionStorage中的token'));
}

// 主函数
async function main() {
  console.log(colors.cyan('🔑 SmellPin 测试Token获取工具\n'));
  
  console.log(colors.blue('请选择获取token的方式:'));
  console.log('1. 使用现有用户邮箱和密码登录');
  console.log('2. 查看数据库直接查询方案');
  console.log('3. 查看浏览器获取token方案');
  console.log('4. 退出');
  
  const choice = await askQuestion('\n请输入选项 (1-4): ');
  
  switch (choice) {
    case '1':
      console.log(colors.yellow('\n📝 请输入现有用户的登录信息:'));
      const email = await askQuestion('邮箱: ');
      const password = await askQuestion('密码: ');
      
      if (email && password) {
        await loginWithExistingUser(email, password);
      } else {
        console.log(colors.red('❌ 邮箱和密码不能为空'));
      }
      break;
      
    case '2':
      showDatabaseSolution();
      break;
      
    case '3':
      showBrowserSolution();
      break;
      
    case '4':
      console.log(colors.green('👋 再见!'));
      break;
      
    default:
      console.log(colors.red('❌ 无效选项'));
      break;
  }
  
  rl.close();
}

// 运行主函数
if (require.main === module) {
  main().catch(error => {
    console.error(colors.red('\n💥 程序执行出错:'), error.message);
    rl.close();
    process.exit(1);
  });
}

module.exports = {
  loginWithExistingUser,
  showDatabaseSolution,
  showBrowserSolution
};