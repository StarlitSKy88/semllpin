#!/usr/bin/env node

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
            console.warn(`⚠️ JWT密钥长度不足: ${jwtSecret.length} < 32`);
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
                console.warn(`⚠️ 敏感文件/目录未在.gitignore中: ${file}`);
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
                        console.warn(`🚨 发现 ${critical} 个严重漏洞`);
                        resolve(false);
                    } else if (high > 0) {
                        console.warn(`⚠️ 发现 ${high} 个高危漏洞`);
                        resolve(false);
                    } else if (moderate > 0) {
                        console.log(`ℹ️ 发现 ${moderate} 个中等漏洞`);
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
    console.log('=====================================\n');
    
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
    console.log(`安全检查完成: ${passedChecks}/${checks.length} 项通过`);
    
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
