/**
 * SmellPin Role-Based Access Control (RBAC) System
 * Implements comprehensive RBAC with permissions, roles, and policies
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

class RBACSystem {
    constructor() {
        // Define system permissions
        this.permissions = {
            // User management
            'users:read': 'View user information',
            'users:write': 'Create and update users',
            'users:delete': 'Delete users',
            'users:admin': 'Full user administration',

            // Annotation management
            'annotations:read': 'View annotations',
            'annotations:write': 'Create and update annotations',
            'annotations:delete': 'Delete annotations',
            'annotations:moderate': 'Moderate and approve annotations',

            // Payment system
            'payments:read': 'View payment information',
            'payments:process': 'Process payments',
            'payments:refund': 'Issue refunds',
            'payments:admin': 'Full payment administration',

            // LBS (Location-Based Services)
            'lbs:read': 'View location data',
            'lbs:write': 'Create location rewards',
            'lbs:admin': 'Administer LBS system',

            // Content moderation
            'content:moderate': 'Moderate user content',
            'content:delete': 'Delete inappropriate content',
            'content:ban': 'Ban users for content violations',

            // System administration
            'system:metrics': 'View system metrics',
            'system:logs': 'Access system logs',
            'system:config': 'Configure system settings',
            'system:admin': 'Full system administration',

            // API access
            'api:read': 'Read access to API',
            'api:write': 'Write access to API',
            'api:admin': 'Administrative API access'
        };

        // Define system roles
        this.roles = {
            'guest': {
                name: 'Guest User',
                description: 'Unauthenticated user with minimal access',
                permissions: ['annotations:read']
            },
            'user': {
                name: 'Regular User',
                description: 'Authenticated user with standard access',
                permissions: [
                    'users:read',
                    'annotations:read',
                    'annotations:write',
                    'lbs:read',
                    'lbs:write',
                    'payments:read',
                    'api:read',
                    'api:write'
                ]
            },
            'premium': {
                name: 'Premium User',
                description: 'Premium subscriber with enhanced features',
                permissions: [
                    'users:read',
                    'users:write', // Can edit own profile
                    'annotations:read',
                    'annotations:write',
                    'lbs:read',
                    'lbs:write',
                    'payments:read',
                    'payments:process',
                    'api:read',
                    'api:write'
                ]
            },
            'moderator': {
                name: 'Content Moderator',
                description: 'User with content moderation privileges',
                permissions: [
                    'users:read',
                    'annotations:read',
                    'annotations:write',
                    'annotations:moderate',
                    'content:moderate',
                    'content:delete',
                    'lbs:read',
                    'api:read',
                    'api:write'
                ]
            },
            'support': {
                name: 'Support Agent',
                description: 'Customer support representative',
                permissions: [
                    'users:read',
                    'users:write',
                    'annotations:read',
                    'annotations:moderate',
                    'payments:read',
                    'payments:refund',
                    'lbs:read',
                    'system:metrics',
                    'api:read',
                    'api:write'
                ]
            },
            'admin': {
                name: 'Administrator',
                description: 'Full system administrator',
                permissions: [
                    'users:read',
                    'users:write',
                    'users:delete',
                    'users:admin',
                    'annotations:read',
                    'annotations:write',
                    'annotations:delete',
                    'annotations:moderate',
                    'payments:read',
                    'payments:process',
                    'payments:refund',
                    'payments:admin',
                    'lbs:read',
                    'lbs:write',
                    'lbs:admin',
                    'content:moderate',
                    'content:delete',
                    'content:ban',
                    'system:metrics',
                    'system:logs',
                    'system:config',
                    'system:admin',
                    'api:read',
                    'api:write',
                    'api:admin'
                ]
            },
            'superadmin': {
                name: 'Super Administrator',
                description: 'Highest level system administrator',
                permissions: Object.keys(this.permissions) // All permissions
            }
        };

        // Security policies
        this.policies = {
            sessionTimeout: 24 * 60 * 60, // 24 hours in seconds
            maxFailedLogins: 5,
            lockoutDuration: 15 * 60, // 15 minutes in seconds
            passwordMinLength: 8,
            passwordRequireSpecialChars: true,
            mfaRequired: ['admin', 'superadmin'],
            ipWhitelist: {
                admin: [], // Empty means no restriction
                superadmin: [] // Can be populated with specific IPs
            }
        };
    }

    /**
     * Hash password securely
     */
    async hashPassword(password) {
        const saltRounds = 12;
        return await bcrypt.hash(password, saltRounds);
    }

    /**
     * Verify password
     */
    async verifyPassword(password, hash) {
        return await bcrypt.compare(password, hash);
    }

    /**
     * Generate secure token
     */
    generateSecureToken() {
        return crypto.randomBytes(32).toString('hex');
    }

    /**
     * Create JWT token with RBAC claims
     */
    createAccessToken(user, sessionData = {}) {
        const payload = {
            userId: user.id,
            email: user.email,
            roles: user.roles || ['user'],
            permissions: this.getUserPermissions(user.roles || ['user']),
            sessionId: sessionData.sessionId || this.generateSecureToken(),
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + this.policies.sessionTimeout
        };

        return jwt.sign(payload, process.env.JWT_SECRET, {
            algorithm: 'HS256',
            issuer: 'smellpin',
            audience: 'smellpin-users'
        });
    }

    /**
     * Verify and decode JWT token
     */
    verifyAccessToken(token) {
        try {
            return jwt.verify(token, process.env.JWT_SECRET, {
                algorithms: ['HS256'],
                issuer: 'smellpin',
                audience: 'smellpin-users'
            });
        } catch (error) {
            throw new Error(`Token verification failed: ${error.message}`);
        }
    }

    /**
     * Get all permissions for given roles
     */
    getUserPermissions(userRoles) {
        const permissions = new Set();
        
        userRoles.forEach(roleName => {
            const role = this.roles[roleName];
            if (role && role.permissions) {
                role.permissions.forEach(permission => {
                    permissions.add(permission);
                });
            }
        });

        return Array.from(permissions);
    }

    /**
     * Check if user has specific permission
     */
    hasPermission(userPermissions, requiredPermission) {
        return userPermissions.includes(requiredPermission);
    }

    /**
     * Check if user has any of the required permissions
     */
    hasAnyPermission(userPermissions, requiredPermissions) {
        return requiredPermissions.some(permission => 
            userPermissions.includes(permission)
        );
    }

    /**
     * Check if user has all required permissions
     */
    hasAllPermissions(userPermissions, requiredPermissions) {
        return requiredPermissions.every(permission => 
            userPermissions.includes(permission)
        );
    }

    /**
     * Express middleware for authentication
     */
    authenticate() {
        return async (req, res, next) => {
            try {
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return res.status(401).json({
                        error: 'Authentication required',
                        code: 'AUTH_REQUIRED'
                    });
                }

                const token = authHeader.substring(7);
                const decoded = this.verifyAccessToken(token);
                
                // Check token expiration
                if (decoded.exp < Math.floor(Date.now() / 1000)) {
                    return res.status(401).json({
                        error: 'Token expired',
                        code: 'TOKEN_EXPIRED'
                    });
                }

                // Add user info to request
                req.user = {
                    id: decoded.userId,
                    email: decoded.email,
                    roles: decoded.roles,
                    permissions: decoded.permissions,
                    sessionId: decoded.sessionId
                };

                // Log authentication for audit
                console.log(`Authentication successful for user ${decoded.userId} with roles: ${decoded.roles.join(', ')}`);

                next();
            } catch (error) {
                console.error('Authentication error:', error);
                return res.status(401).json({
                    error: 'Invalid authentication token',
                    code: 'INVALID_TOKEN'
                });
            }
        };
    }

    /**
     * Express middleware for authorization (permission-based)
     */
    authorize(requiredPermissions, options = {}) {
        const { requireAll = false, allowSelf = false } = options;

        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });
            }

            // Check if user is accessing their own resource
            if (allowSelf && req.params.userId && req.params.userId === req.user.id) {
                return next();
            }

            // Check permissions
            const userPermissions = req.user.permissions || [];
            const hasRequiredPermissions = requireAll 
                ? this.hasAllPermissions(userPermissions, requiredPermissions)
                : this.hasAnyPermission(userPermissions, requiredPermissions);

            if (!hasRequiredPermissions) {
                console.warn(`Authorization failed for user ${req.user.id}. Required: ${requiredPermissions.join(', ')}, Has: ${userPermissions.join(', ')}`);
                
                return res.status(403).json({
                    error: 'Insufficient permissions',
                    code: 'INSUFFICIENT_PERMISSIONS',
                    required: requiredPermissions,
                    available: userPermissions
                });
            }

            // Log authorization success for sensitive operations
            if (requiredPermissions.some(p => p.includes('admin') || p.includes('delete'))) {
                console.log(`Authorized sensitive operation for user ${req.user.id}: ${requiredPermissions.join(', ')}`);
            }

            next();
        };
    }

    /**
     * Express middleware for role-based authorization
     */
    requireRole(requiredRoles) {
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({
                    error: 'Authentication required',
                    code: 'AUTH_REQUIRED'
                });
            }

            const userRoles = req.user.roles || [];
            const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

            if (!hasRequiredRole) {
                console.warn(`Role authorization failed for user ${req.user.id}. Required: ${requiredRoles.join(', ')}, Has: ${userRoles.join(', ')}`);
                
                return res.status(403).json({
                    error: 'Insufficient role privileges',
                    code: 'INSUFFICIENT_ROLE',
                    required: requiredRoles,
                    available: userRoles
                });
            }

            next();
        };
    }

    /**
     * Resource ownership check
     */
    checkOwnership(resourceType) {
        return async (req, res, next) => {
            try {
                const resourceId = req.params.id || req.params.resourceId;
                const userId = req.user.id;

                // This would typically involve database queries
                // For now, we'll use a simplified check
                const resource = await this.getResource(resourceType, resourceId);
                
                if (!resource) {
                    return res.status(404).json({
                        error: 'Resource not found',
                        code: 'RESOURCE_NOT_FOUND'
                    });
                }

                // Check if user owns the resource or has admin permissions
                const isOwner = resource.userId === userId;
                const hasAdminPermission = this.hasPermission(req.user.permissions, `${resourceType}:admin`);

                if (!isOwner && !hasAdminPermission) {
                    return res.status(403).json({
                        error: 'Access denied - not resource owner',
                        code: 'NOT_RESOURCE_OWNER'
                    });
                }

                req.resource = resource;
                next();
            } catch (error) {
                console.error('Ownership check error:', error);
                return res.status(500).json({
                    error: 'Failed to verify resource ownership',
                    code: 'OWNERSHIP_CHECK_FAILED'
                });
            }
        };
    }

    /**
     * Rate limiting based on user role
     */
    getRoleBasedRateLimit(userRoles) {
        const roleHierarchy = {
            guest: { requestsPerMinute: 10, requestsPerHour: 100 },
            user: { requestsPerMinute: 30, requestsPerHour: 500 },
            premium: { requestsPerMinute: 60, requestsPerHour: 1000 },
            moderator: { requestsPerMinute: 100, requestsPerHour: 2000 },
            support: { requestsPerMinute: 150, requestsPerHour: 3000 },
            admin: { requestsPerMinute: 300, requestsPerHour: 10000 },
            superadmin: { requestsPerMinute: 1000, requestsPerHour: 50000 }
        };

        // Get the highest privilege level
        let maxLimits = roleHierarchy.guest;
        
        userRoles.forEach(role => {
            const roleLimits = roleHierarchy[role];
            if (roleLimits && roleLimits.requestsPerMinute > maxLimits.requestsPerMinute) {
                maxLimits = roleLimits;
            }
        });

        return maxLimits;
    }

    /**
     * Audit logging for sensitive operations
     */
    auditLog(action, req, additionalData = {}) {
        const auditEntry = {
            timestamp: new Date().toISOString(),
            action,
            userId: req.user?.id,
            userEmail: req.user?.email,
            userRoles: req.user?.roles,
            ip: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            path: req.path,
            method: req.method,
            sessionId: req.user?.sessionId,
            ...additionalData
        };

        // Log to audit system (database, file, external service)
        console.log('AUDIT:', JSON.stringify(auditEntry));
        
        // In production, this would write to a secure audit log
        // await this.writeAuditLog(auditEntry);
    }

    /**
     * Security context for operations
     */
    createSecurityContext(req) {
        return {
            user: req.user,
            permissions: req.user?.permissions || [],
            roles: req.user?.roles || ['guest'],
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            sessionId: req.user?.sessionId,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Validate password strength
     */
    validatePasswordStrength(password) {
        const errors = [];

        if (password.length < this.policies.passwordMinLength) {
            errors.push(`Password must be at least ${this.policies.passwordMinLength} characters long`);
        }

        if (this.policies.passwordRequireSpecialChars) {
            if (!/[A-Z]/.test(password)) {
                errors.push('Password must contain at least one uppercase letter');
            }
            if (!/[a-z]/.test(password)) {
                errors.push('Password must contain at least one lowercase letter');
            }
            if (!/[0-9]/.test(password)) {
                errors.push('Password must contain at least one number');
            }
            if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
                errors.push('Password must contain at least one special character');
            }
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }

    /**
     * Mock resource getter (replace with actual database queries)
     */
    async getResource(resourceType, resourceId) {
        // This would be replaced with actual database queries
        // For now, return a mock resource
        return {
            id: resourceId,
            type: resourceType,
            userId: 'user123', // This would come from database
            createdAt: new Date()
        };
    }
}

module.exports = RBACSystem;