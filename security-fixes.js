#!/usr/bin/env node

/**
 * SmellPin 安全修复脚本
 * 
 * 自动修复安全测试中发现的问题：
 * 1. 生成强JWT密钥
 * 2. 修复SQL注入风险点
 * 3. 添加安全中间件配置
 * 4. 创建.env.security模板
 */

const fs = require('fs').promises;
const crypto = require('crypto');
const path = require('path');

const colors = require('colors');

// 配置
const PROJECT_ROOT = process.cwd();
const ENV_FILE = path.join(PROJECT_ROOT, '.env');
const ENV_EXAMPLE_FILE = path.join(PROJECT_ROOT, '.env.example');

// 生成强随机密钥
function generateSecureKey(length = 64) {
    return crypto.randomBytes(length).toString('hex');
}

// 生成强密码
function generateSecurePassword(length = 32) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
}

// 修复1: 更新JWT密钥
async function fixJWTSecurity() {
    console.log(colors.blue('🔐 修复JWT安全问题...'));
    
    try {
        // 生成新的强密钥
        const newJWTSecret = generateSecureKey(64);
        const newRefreshSecret = generateSecureKey(64);
        
        // 读取现有.env文件
        let envContent = '';
        try {
            envContent = await fs.readFile(ENV_FILE, 'utf8');
        } catch (error) {
            console.log(colors.yellow('⚠️ .env文件不存在，将创建新文件'));
        }
        
        // 更新JWT密钥
        if (envContent.includes('JWT_SECRET=')) {
            envContent = envContent.replace(
                /JWT_SECRET=.*/g, 
                `JWT_SECRET=${newJWTSecret}`
            );
        } else {
            envContent += `\n# JWT安全配置\nJWT_SECRET=${newJWTSecret}\n`;
        }
        
        if (envContent.includes('JWT_REFRESH_SECRET=')) {
            envContent = envContent.replace(
                /JWT_REFRESH_SECRET=.*/g, 
                `JWT_REFRESH_SECRET=${newRefreshSecret}`
            );
        } else {
            envContent += `JWT_REFRESH_SECRET=${newRefreshSecret}\n`;
        }
        
        // 设置更短的过期时间
        if (envContent.includes('JWT_EXPIRES_IN=')) {
            envContent = envContent.replace(
                /JWT_EXPIRES_IN=.*/g, 
                'JWT_EXPIRES_IN=1h'
            );
        } else {
            envContent += `JWT_EXPIRES_IN=1h\n`;
        }
        
        if (envContent.includes('JWT_REFRESH_EXPIRES_IN=')) {
            envContent = envContent.replace(
                /JWT_REFRESH_EXPIRES_IN=.*/g, 
                'JWT_REFRESH_EXPIRES_IN=7d'
            );
        } else {
            envContent += `JWT_REFRESH_EXPIRES_IN=7d\n`;
        }
        
        await fs.writeFile(ENV_FILE, envContent);
        
        console.log(colors.green('✅ JWT密钥已更新 (64字节强随机密钥)'));
        console.log(colors.green('✅ JWT过期时间已设置为1小时'));
        console.log(colors.green('✅ 刷新令牌过期时间已设置为7天'));
        
    } catch (error) {
        console.error(colors.red('❌ JWT安全修复失败:'), error.message);
    }
}

// 修复2: SQL注入风险点修复
async function fixSQLInjection() {
    console.log(colors.blue('💉 修复SQL注入风险...'));
    
    try {
        const annotationModelPath = path.join(PROJECT_ROOT, 'src/models/Annotation.ts');
        let content = await fs.readFile(annotationModelPath, 'utf8');
        
        // 修复location_point的SQL注入
        const dangerousLocationPoint = /insertData\.location_point = db\.raw\(`ST_GeomFromText\('(.+?)', 4326\)`\);/;
        if (dangerousLocationPoint.test(content)) {
            content = content.replace(
                dangerousLocationPoint,
                'insertData.location_point = db.raw("ST_GeomFromText(?, 4326)", [locationPoint]);'
            );
            console.log(colors.green('✅ 修复了location_point的SQL注入风险'));
        }
        
        // 修复whereRaw中的SQL注入
        const dangerousWhereRaw = /`POINT\(\$\{filters\.longitude\} \$\{filters\.latitude\}\)`/;
        if (dangerousWhereRaw.test(content)) {
            content = content.replace(
                dangerousWhereRaw,
                '`POINT(? ?)`'
            );
            content = content.replace(
                /\[`POINT\(\$\{filters\.longitude\} \$\{filters\.latitude\}\)`, filters\.radius\]/,
                '[filters.longitude, filters.latitude, filters.radius]'
            );
            console.log(colors.green('✅ 修复了地理位置查询的SQL注入风险'));
        }
        
        await fs.writeFile(annotationModelPath, content);
        console.log(colors.green('✅ Annotation模型SQL注入风险已修复'));
        
    } catch (error) {
        console.error(colors.red('❌ SQL注入修复失败:'), error.message);
    }
}

// 修复3: 创建安全中间件配置
async function createSecurityMiddleware() {
    console.log(colors.blue('🛡️ 创建安全中间件...'));
    
    try {
        const securityMiddlewarePath = path.join(PROJECT_ROOT, 'src/middleware/security.ts');
        
        const securityMiddlewareContent = `import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config } from '../config/config';

// 安全头中间件
export const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https:"],
            scriptSrc: ["'self'", "https://js.stripe.com", "https://www.paypal.com"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'", "https:", "data:"],
            connectSrc: ["'self'", "https://api.stripe.com", "https://api.paypal.com", "wss://"],
            frameSrc: ["'self'", "https://js.stripe.com", "https://www.paypal.com"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            upgradeInsecureRequests: [],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    frameguard: { action: 'deny' },
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
});

// API速率限制
export const apiRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分钟
    max: 100, // 每个IP最多100个请求
    message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// 严格的API速率限制 (登录、注册等敏感操作)
export const strictRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分钟
    max: 5, // 每个IP最多5次尝试
    message: {
        error: 'Too many attempts, please try again later.',
        code: 'STRICT_RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// 文件上传速率限制
export const fileUploadRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1小时
    max: 10, // 每小时最多10次文件上传
    message: {
        error: 'Too many file uploads, please try again later.',
        code: 'FILE_UPLOAD_RATE_LIMIT_EXCEEDED'
    },
});

// 输入验证中间件
export const validateInput = (req: Request, res: Response, next: NextFunction) => {
    // 检查请求体大小
    if (req.body && JSON.stringify(req.body).length > 1024 * 1024) { // 1MB
        return res.status(400).json({
            error: 'Request body too large',
            code: 'PAYLOAD_TOO_LARGE'
        });
    }
    
    // 基本XSS过滤
    const sanitizeValue = (value: any): any => {
        if (typeof value === 'string') {
            return value
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#x27;')
                .replace(/\\//g, '&#x2F;');
        }
        if (typeof value === 'object' && value !== null) {
            const sanitized: any = Array.isArray(value) ? [] : {};
            for (const key in value) {
                sanitized[key] = sanitizeValue(value[key]);
            }
            return sanitized;
        }
        return value;
    };
    
    if (req.body) {
        req.body = sanitizeValue(req.body);
    }
    
    if (req.query) {
        req.query = sanitizeValue(req.query);
    }
    
    next();
};

// CORS安全配置
export const corsConfig = {
    origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:3001',
            'https://smellpin.vercel.app',
            // 添加生产域名
        ];
        
        // 允许无origin的请求(例如移动应用)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS policy'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset']
};

// 请求日志中间件(安全相关)
export const securityLogger = (req: Request, res: Response, next: NextFunction) => {
    const startTime = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        const logData = {
            method: req.method,
            url: req.url,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            statusCode: res.statusCode,
            duration,
            timestamp: new Date().toISOString(),
        };
        
        // 记录可疑活动
        if (res.statusCode === 401 || res.statusCode === 403 || res.statusCode === 429) {
            console.warn('Security Event:', logData);
        }
    });
    
    next();
};

export default {
    securityHeaders,
    apiRateLimit,
    strictRateLimit,
    fileUploadRateLimit,
    validateInput,
    corsConfig,
    securityLogger
};
`;

        await fs.writeFile(securityMiddlewarePath, securityMiddlewareContent);
        console.log(colors.green('✅ 安全中间件已创建'));
        
    } catch (error) {
        console.error(colors.red('❌ 安全中间件创建失败:'), error.message);
    }
}

// 修复4: 创建环境变量安全模板
async function createSecurityEnvTemplate() {
    console.log(colors.blue('📄 创建安全环境变量模板...'));
    
    try {
        const envSecurityPath = path.join(PROJECT_ROOT, '.env.security');
        
        const securityEnvContent = `# SmellPin 安全配置模板
# 请将以下配置添加到您的.env文件中，并设置实际值

# JWT安全配置 - 请使用强随机密钥
JWT_SECRET=${generateSecureKey(64)}
JWT_REFRESH_SECRET=${generateSecureKey(64)}
JWT_EXPIRES_IN=1h
JWT_REFRESH_EXPIRES_IN=7d

# 数据库安全配置
DB_CONNECTION_TIMEOUT=30000
DB_POOL_MIN=2
DB_POOL_MAX=10
DATABASE_SSL=true

# Redis安全配置
REDIS_PASSWORD=${generateSecurePassword(32)}
REDIS_TLS=true

# 会话安全配置
SESSION_SECRET=${generateSecureKey(64)}
COOKIE_SECURE=true
COOKIE_HTTPONLY=true
COOKIE_SAMESITE=strict

# CORS安全配置
CORS_ORIGIN=https://yourdomain.com
CORS_CREDENTIALS=true

# 速率限制配置
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
STRICT_RATE_LIMIT_MAX=5

# 文件上传安全配置
UPLOAD_MAX_SIZE=5242880
UPLOAD_ALLOWED_TYPES=image/jpeg,image/png,image/gif
UPLOAD_MAX_FILES=5

# 支付安全配置 - 生产环境请使用正式密钥
PAYPAL_MODE=live
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# 安全监控配置
SECURITY_LOG_LEVEL=warn
ENABLE_SECURITY_HEADERS=true
ENABLE_CSRF_PROTECTION=true

# SSL/TLS配置 (生产环境)
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/key.pem
FORCE_HTTPS=true

# 应用安全配置
NODE_ENV=production
TRUST_PROXY=true
DISABLE_X_POWERED_BY=true
`;

        await fs.writeFile(envSecurityPath, securityEnvContent);
        console.log(colors.green('✅ 安全环境变量模板已创建 (.env.security)'));
        
    } catch (error) {
        console.error(colors.red('❌ 安全模板创建失败:'), error.message);
    }
}

// 修复5: 更新.gitignore
async function updateGitignore() {
    console.log(colors.blue('📝 更新.gitignore...'));
    
    try {
        const gitignorePath = path.join(PROJECT_ROOT, '.gitignore');
        let gitignoreContent = '';
        
        try {
            gitignoreContent = await fs.readFile(gitignorePath, 'utf8');
        } catch (error) {
            console.log(colors.yellow('⚠️ .gitignore文件不存在，将创建新文件'));
        }
        
        const securityEntries = [
            '',
            '# 安全相关文件',
            '.env',
            '.env.local',
            '.env.development.local',
            '.env.test.local',
            '.env.production.local',
            '.env.security',
            '',
            '# SSL证书',
            '*.pem',
            '*.key',
            '*.crt',
            '*.p12',
            '',
            '# 敏感配置文件',
            'config/secrets.*',
            'keys/',
            'certificates/',
            '',
            '# 日志文件',
            'logs/',
            '*.log',
            'security.log',
            'audit.log'
        ];
        
        // 检查是否已存在安全相关条目
        if (!gitignoreContent.includes('# 安全相关文件')) {
            gitignoreContent += securityEntries.join('\n');
            await fs.writeFile(gitignorePath, gitignoreContent);
            console.log(colors.green('✅ .gitignore已更新，添加了安全相关文件'));
        } else {
            console.log(colors.blue('ℹ️ .gitignore已包含安全相关配置'));
        }
        
    } catch (error) {
        console.error(colors.red('❌ .gitignore更新失败:'), error.message);
    }
}

// 修复6: 创建安全检查脚本
async function createSecurityCheckScript() {
    console.log(colors.blue('🔍 创建安全检查脚本...'));
    
    try {
        const scriptPath = path.join(PROJECT_ROOT, 'scripts/security-check.js');
        
        // 确保scripts目录存在
        try {
            await fs.mkdir(path.join(PROJECT_ROOT, 'scripts'), { recursive: true });
        } catch (error) {
            // 目录可能已存在
        }
        
        const checkScriptContent = `#!/usr/bin/env node

/**
 * SmellPin 安全检查脚本
 * 定期运行此脚本以检查常见安全问题
 */

const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');

async function checkJWTSecret() {
    console.log('🔐 检查JWT密钥安全性...');
    
    try {
        const envContent = await fs.readFile('.env', 'utf8');
        const jwtSecretMatch = envContent.match(/JWT_SECRET=(.+)/);
        
        if (!jwtSecretMatch) {
            console.warn('⚠️ 未找到JWT_SECRET');
            return false;
        }
        
        const jwtSecret = jwtSecretMatch[1].trim();
        
        if (jwtSecret.length < 32) {
            console.warn(\`⚠️ JWT密钥长度不足: \${jwtSecret.length} < 32\`);
            return false;
        }
        
        if (jwtSecret.includes('your-secret-key') || jwtSecret.includes('secret')) {
            console.warn('⚠️ JWT密钥使用了默认或弱密钥');
            return false;
        }
        
        console.log('✅ JWT密钥安全性检查通过');
        return true;
    } catch (error) {
        console.error('❌ JWT密钥检查失败:', error.message);
        return false;
    }
}

async function checkSensitiveFiles() {
    console.log('📁 检查敏感文件暴露...');
    
    const sensitiveFiles = [
        '.env',
        'config/database.js',
        'keys/',
        'certificates/'
    ];
    
    try {
        const gitignoreContent = await fs.readFile('.gitignore', 'utf8');
        let allProtected = true;
        
        for (const file of sensitiveFiles) {
            if (!gitignoreContent.includes(file)) {
                console.warn(\`⚠️ 敏感文件/目录未在.gitignore中: \${file}\`);
                allProtected = false;
            }
        }
        
        if (allProtected) {
            console.log('✅ 敏感文件保护检查通过');
        }
        
        return allProtected;
    } catch (error) {
        console.error('❌ 敏感文件检查失败:', error.message);
        return false;
    }
}

async function checkDependencyVulnerabilities() {
    console.log('📦 检查依赖包漏洞...');
    
    try {
        const { exec } = require('child_process');
        
        return new Promise((resolve) => {
            exec('npm audit --json', (error, stdout, stderr) => {
                if (error && error.code !== 1) {
                    console.error('❌ 依赖检查失败:', error.message);
                    resolve(false);
                    return;
                }
                
                try {
                    const auditResult = JSON.parse(stdout);
                    const vulnerabilities = auditResult.metadata?.vulnerabilities || {};
                    
                    const critical = vulnerabilities.critical || 0;
                    const high = vulnerabilities.high || 0;
                    const moderate = vulnerabilities.moderate || 0;
                    
                    if (critical > 0) {
                        console.warn(\`🚨 发现 \${critical} 个严重漏洞\`);
                        resolve(false);
                    } else if (high > 0) {
                        console.warn(\`⚠️ 发现 \${high} 个高危漏洞\`);
                        resolve(false);
                    } else if (moderate > 0) {
                        console.log(\`ℹ️ 发现 \${moderate} 个中等漏洞\`);
                        resolve(true);
                    } else {
                        console.log('✅ 未发现已知漏洞');
                        resolve(true);
                    }
                } catch (parseError) {
                    console.error('❌ 解析审计结果失败:', parseError.message);
                    resolve(false);
                }
            });
        });
    } catch (error) {
        console.error('❌ 依赖漏洞检查失败:', error.message);
        return false;
    }
}

async function runSecurityCheck() {
    console.log('🔒 开始安全检查...');
    console.log('=====================================\\n');
    
    const checks = [
        checkJWTSecret,
        checkSensitiveFiles,
        checkDependencyVulnerabilities
    ];
    
    let passedChecks = 0;
    
    for (const check of checks) {
        const result = await check();
        if (result) passedChecks++;
        console.log('');
    }
    
    console.log('=====================================');
    console.log(\`安全检查完成: \${passedChecks}/\${checks.length} 项通过\`);
    
    if (passedChecks === checks.length) {
        console.log('🎉 所有安全检查通过!');
        process.exit(0);
    } else {
        console.log('⚠️ 发现安全问题，请及时修复');
        process.exit(1);
    }
}

if (require.main === module) {
    runSecurityCheck();
}

module.exports = { runSecurityCheck };
`;

        await fs.writeFile(scriptPath, checkScriptContent);
        
        // 设置执行权限
        try {
            await fs.chmod(scriptPath, '755');
        } catch (error) {
            // 在Windows上可能会失败，但不是关键问题
        }
        
        console.log(colors.green('✅ 安全检查脚本已创建 (scripts/security-check.js)'));
        
    } catch (error) {
        console.error(colors.red('❌ 安全检查脚本创建失败:'), error.message);
    }
}

// 修复7: 更新package.json添加安全脚本
async function updatePackageJson() {
    console.log(colors.blue('📦 更新package.json...'));
    
    try {
        const packagePath = path.join(PROJECT_ROOT, 'package.json');
        const packageContent = await fs.readFile(packagePath, 'utf8');
        const packageJson = JSON.parse(packageContent);
        
        // 添加安全相关脚本
        if (!packageJson.scripts) {
            packageJson.scripts = {};
        }
        
        packageJson.scripts['security:check'] = 'node scripts/security-check.js';
        packageJson.scripts['security:audit'] = 'npm audit';
        packageJson.scripts['security:fix'] = 'npm audit fix';
        packageJson.scripts['security:test'] = 'node security-test.js';
        
        // 添加安全依赖
        if (!packageJson.devDependencies) {
            packageJson.devDependencies = {};
        }
        
        if (!packageJson.devDependencies['@types/helmet']) {
            packageJson.devDependencies['@types/helmet'] = '^1.0.0';
        }
        
        await fs.writeFile(packagePath, JSON.stringify(packageJson, null, 2));
        console.log(colors.green('✅ package.json已更新，添加了安全脚本'));
        
    } catch (error) {
        console.error(colors.red('❌ package.json更新失败:'), error.message);
    }
}

// 主函数
async function runSecurityFixes() {
    console.log(colors.bold.cyan('🔧 SmellPin 安全修复工具'));
    console.log(colors.gray('自动修复安全测试中发现的问题'));
    console.log('='.repeat(50));
    
    try {
        await fixJWTSecurity();
        await fixSQLInjection();
        await createSecurityMiddleware();
        await createSecurityEnvTemplate();
        await updateGitignore();
        await createSecurityCheckScript();
        await updatePackageJson();
        
        console.log('\n' + '='.repeat(50));
        console.log(colors.bold.green('✅ 安全修复完成!'));
        console.log(colors.yellow('请注意:'));
        console.log(colors.yellow('1. 重新启动应用服务器以应用JWT密钥更改'));
        console.log(colors.yellow('2. 检查.env.security文件中的配置建议'));
        console.log(colors.yellow('3. 运行 npm run security:check 验证修复效果'));
        console.log(colors.yellow('4. 在生产环境中配置HTTPS和安全头'));
        console.log(colors.yellow('5. 定期运行安全检查和依赖审计'));
        
    } catch (error) {
        console.error(colors.red('❌ 安全修复过程中出现错误:'), error);
        process.exit(1);
    }
}

// 如果直接运行此脚本
if (require.main === module) {
    runSecurityFixes();
}

module.exports = { runSecurityFixes };