/**
 * 管理员权限验证中间件
 * 提供角色管理和权限控制功能
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

/**
 * 管理员角色定义
 */
const ADMIN_ROLES = {
    SUPER_ADMIN: 'super_admin',     // 超级管理员 - 所有权限
    ADMIN: 'admin',                 // 管理员 - 大部分权限
    MODERATOR: 'moderator',         // 内容审核员 - 内容管理权限
    FINANCE: 'finance',             // 财务管理员 - 财务相关权限
    ANALYST: 'analyst'              // 数据分析师 - 只读分析权限
};

/**
 * 权限定义
 */
const PERMISSIONS = {
    // 用户管理权限
    USER_READ: 'user:read',
    USER_WRITE: 'user:write',
    USER_DELETE: 'user:delete',
    USER_BAN: 'user:ban',
    
    // 内容管理权限
    CONTENT_READ: 'content:read',
    CONTENT_MODERATE: 'content:moderate',
    CONTENT_DELETE: 'content:delete',
    
    // 财务管理权限
    FINANCE_READ: 'finance:read',
    FINANCE_WRITE: 'finance:write',
    FINANCE_WITHDRAW: 'finance:withdraw',
    FINANCE_REFUND: 'finance:refund',
    
    // 数据分析权限
    ANALYTICS_READ: 'analytics:read',
    ANALYTICS_EXPORT: 'analytics:export',
    
    // 系统配置权限
    SYSTEM_READ: 'system:read',
    SYSTEM_WRITE: 'system:write',
    SYSTEM_MAINTENANCE: 'system:maintenance'
};

/**
 * 角色权限映射
 */
const ROLE_PERMISSIONS = {
    [ADMIN_ROLES.SUPER_ADMIN]: Object.values(PERMISSIONS),
    [ADMIN_ROLES.ADMIN]: [
        PERMISSIONS.USER_READ, PERMISSIONS.USER_WRITE, PERMISSIONS.USER_BAN,
        PERMISSIONS.CONTENT_READ, PERMISSIONS.CONTENT_MODERATE, PERMISSIONS.CONTENT_DELETE,
        PERMISSIONS.FINANCE_READ, PERMISSIONS.FINANCE_WRITE,
        PERMISSIONS.ANALYTICS_READ, PERMISSIONS.ANALYTICS_EXPORT,
        PERMISSIONS.SYSTEM_READ, PERMISSIONS.SYSTEM_WRITE
    ],
    [ADMIN_ROLES.MODERATOR]: [
        PERMISSIONS.USER_READ,
        PERMISSIONS.CONTENT_READ, PERMISSIONS.CONTENT_MODERATE, PERMISSIONS.CONTENT_DELETE,
        PERMISSIONS.ANALYTICS_READ
    ],
    [ADMIN_ROLES.FINANCE]: [
        PERMISSIONS.USER_READ,
        PERMISSIONS.FINANCE_READ, PERMISSIONS.FINANCE_WRITE, PERMISSIONS.FINANCE_WITHDRAW, PERMISSIONS.FINANCE_REFUND,
        PERMISSIONS.ANALYTICS_READ
    ],
    [ADMIN_ROLES.ANALYST]: [
        PERMISSIONS.USER_READ,
        PERMISSIONS.CONTENT_READ,
        PERMISSIONS.FINANCE_READ,
        PERMISSIONS.ANALYTICS_READ, PERMISSIONS.ANALYTICS_EXPORT
    ]
};

/**
 * 验证JWT Token
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        throw new Error('无效的访问令牌');
    }
}

/**
 * 获取用户管理员信息
 */
async function getAdminUser(db, userId) {
    const query = `
        SELECT 
            u.id,
            u.username,
            u.email,
            u.phone,
            a.role,
            a.permissions,
            a.is_active,
            a.created_at as admin_since,
            a.last_login_at
        FROM users u
        INNER JOIN admin_users a ON u.id = a.user_id
        WHERE u.id = $1 AND a.is_active = true
    `;
    
    const result = await db.query(query, [userId]);
    return result.rows[0] || null;
}

/**
 * 检查用户是否有指定权限
 */
function hasPermission(userRole, userPermissions, requiredPermission) {
    // 超级管理员拥有所有权限
    if (userRole === ADMIN_ROLES.SUPER_ADMIN) {
        return true;
    }
    
    // 检查角色默认权限
    const rolePermissions = ROLE_PERMISSIONS[userRole] || [];
    if (rolePermissions.includes(requiredPermission)) {
        return true;
    }
    
    // 检查用户自定义权限
    if (userPermissions && Array.isArray(userPermissions)) {
        return userPermissions.includes(requiredPermission);
    }
    
    return false;
}

/**
 * 管理员身份验证中间件
 */
const authenticateAdmin = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                message: '缺少访问令牌',
                code: 'MISSING_TOKEN'
            });
        }
        
        const token = authHeader.substring(7);
        const decoded = verifyToken(token);
        
        // 获取管理员用户信息
        const adminUser = await getAdminUser(req.db, decoded.userId);
        
        if (!adminUser) {
            return res.status(403).json({
                success: false,
                message: '无管理员权限',
                code: 'NOT_ADMIN'
            });
        }
        
        // 更新最后登录时间
        await req.db.query(
            'UPDATE admin_users SET last_login_at = NOW() WHERE user_id = $1',
            [adminUser.id]
        );
        
        // 将管理员信息添加到请求对象
        req.admin = {
            id: adminUser.id,
            username: adminUser.username,
            email: adminUser.email,
            phone: adminUser.phone,
            role: adminUser.role,
            permissions: adminUser.permissions || [],
            adminSince: adminUser.admin_since,
            lastLoginAt: adminUser.last_login_at
        };
        
        next();
        
    } catch (error) {
        console.error('Admin authentication error:', error);
        return res.status(401).json({
            success: false,
            message: error.message || '身份验证失败',
            code: 'AUTH_FAILED'
        });
    }
};

/**
 * 权限检查中间件工厂函数
 */
const requirePermission = (permission) => {
    return (req, res, next) => {
        if (!req.admin) {
            return res.status(401).json({
                success: false,
                message: '未通过管理员身份验证',
                code: 'NOT_AUTHENTICATED'
            });
        }
        
        if (!hasPermission(req.admin.role, req.admin.permissions, permission)) {
            return res.status(403).json({
                success: false,
                message: '权限不足',
                code: 'INSUFFICIENT_PERMISSION',
                required: permission,
                userRole: req.admin.role
            });
        }
        
        next();
    };
};

/**
 * 角色检查中间件工厂函数
 */
const requireRole = (roles) => {
    const allowedRoles = Array.isArray(roles) ? roles : [roles];
    
    return (req, res, next) => {
        if (!req.admin) {
            return res.status(401).json({
                success: false,
                message: '未通过管理员身份验证',
                code: 'NOT_AUTHENTICATED'
            });
        }
        
        if (!allowedRoles.includes(req.admin.role)) {
            return res.status(403).json({
                success: false,
                message: '角色权限不足',
                code: 'INSUFFICIENT_ROLE',
                required: allowedRoles,
                userRole: req.admin.role
            });
        }
        
        next();
    };
};

/**
 * 记录管理员操作日志
 */
const logAdminAction = (action, resource = null) => {
    return async (req, res, next) => {
        // 记录操作前的信息
        const operationLog = {
            adminId: req.admin?.id,
            action,
            resource,
            method: req.method,
            path: req.path,
            query: req.query,
            body: req.method !== 'GET' ? req.body : null,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            timestamp: new Date().toISOString()
        };
        
        // 继续执行请求
        const originalSend = res.send;
        res.send = function(data) {
            // 记录响应信息
            operationLog.statusCode = res.statusCode;
            operationLog.success = res.statusCode < 400;
            
            // 异步记录日志（不阻塞响应）
            setImmediate(async () => {
                try {
                    await req.db.query(`
                        INSERT INTO admin_operation_logs 
                        (admin_id, action, resource, method, path, query_params, request_body, 
                         response_status, success, ip_address, user_agent, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    `, [
                        operationLog.adminId,
                        operationLog.action,
                        operationLog.resource,
                        operationLog.method,
                        operationLog.path,
                        JSON.stringify(operationLog.query),
                        JSON.stringify(operationLog.body),
                        operationLog.statusCode,
                        operationLog.success,
                        operationLog.ip,
                        operationLog.userAgent,
                        operationLog.timestamp
                    ]);
                } catch (error) {
                    console.error('Failed to log admin action:', error);
                }
            });
            
            originalSend.call(this, data);
        };
        
        next();
    };
};

module.exports = {
    ADMIN_ROLES,
    PERMISSIONS,
    ROLE_PERMISSIONS,
    authenticateAdmin,
    requirePermission,
    requireRole,
    logAdminAction,
    hasPermission
};