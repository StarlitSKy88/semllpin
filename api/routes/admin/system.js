/**
 * 管理后台系统配置API路由
 * 提供系统参数设置、公告管理、版本管理等接口
 * 符合项目规则：使用Neon PostgreSQL，严格禁止Supabase
 */

const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const {
    authenticateAdmin,
    requirePermission,
    requireRole,
    logAdminAction,
    PERMISSIONS,
    ADMIN_ROLES
} = require('../../middleware/adminAuth');

// 应用管理员身份验证中间件
router.use(authenticateAdmin);

/**
 * @route GET /api/admin/system/config
 * @desc 获取系统配置参数
 * @access Admin (System Config Read Permission)
 */
router.get('/config', [
    requirePermission(PERMISSIONS.SYSTEM_CONFIG_READ),
    query('category').optional().isAlpha().withMessage('配置分类格式无效'),
    logAdminAction('view_system_config', 'system')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { category } = req.query;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        
        if (category) {
            whereClause += ' AND category = $1';
            queryParams.push(category);
        }
        
        const result = await req.db.query(`
            SELECT 
                id,
                category,
                config_key,
                config_value,
                data_type,
                description,
                is_public,
                is_editable,
                validation_rule,
                updated_at,
                updated_by
            FROM system_configs 
            ${whereClause}
            ORDER BY category, config_key
        `, queryParams);
        
        // 按分类组织配置数据
        const configsByCategory = result.rows.reduce((acc, row) => {
            const category = row.category;
            if (!acc[category]) {
                acc[category] = [];
            }
            
            // 根据数据类型转换值
            let value = row.config_value;
            switch (row.data_type) {
                case 'number':
                    value = parseFloat(value);
                    break;
                case 'boolean':
                    value = value === 'true';
                    break;
                case 'json':
                    try {
                        value = JSON.parse(value);
                    } catch (e) {
                        value = row.config_value;
                    }
                    break;
                default:
                    value = row.config_value;
            }
            
            acc[category].push({
                id: row.id,
                key: row.config_key,
                value: value,
                dataType: row.data_type,
                description: row.description,
                isPublic: row.is_public,
                isEditable: row.is_editable,
                validationRule: row.validation_rule,
                updatedAt: row.updated_at,
                updatedBy: row.updated_by
            });
            
            return acc;
        }, {});
        
        res.json({
            success: true,
            data: {
                configs: configsByCategory,
                categories: Object.keys(configsByCategory)
            }
        });
        
    } catch (error) {
        console.error('Get system config error:', error);
        res.status(500).json({
            success: false,
            message: '获取系统配置失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route PUT /api/admin/system/config/:id
 * @desc 更新系统配置参数
 * @access Admin (System Config Write Permission)
 */
router.put('/config/:id', [
    requirePermission(PERMISSIONS.SYSTEM_CONFIG_WRITE),
    body('value').notEmpty().withMessage('配置值不能为空'),
    body('description').optional().isLength({ max: 500 }).withMessage('描述长度不能超过500字符'),
    logAdminAction('update_system_config', 'system')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { id } = req.params;
        const { value, description } = req.body;
        const adminId = req.admin.id;
        
        // 检查配置是否存在且可编辑
        const configResult = await req.db.query(`
            SELECT id, config_key, data_type, validation_rule, is_editable
            FROM system_configs 
            WHERE id = $1
        `, [id]);
        
        if (configResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: '配置项不存在'
            });
        }
        
        const config = configResult.rows[0];
        
        if (!config.is_editable) {
            return res.status(403).json({
                success: false,
                message: '该配置项不允许编辑'
            });
        }
        
        // 验证配置值格式
        let validatedValue = value;
        
        switch (config.data_type) {
            case 'number':
                if (isNaN(value)) {
                    return res.status(400).json({
                        success: false,
                        message: '配置值必须为数字'
                    });
                }
                validatedValue = value.toString();
                break;
                
            case 'boolean':
                if (typeof value !== 'boolean') {
                    return res.status(400).json({
                        success: false,
                        message: '配置值必须为布尔值'
                    });
                }
                validatedValue = value.toString();
                break;
                
            case 'json':
                try {
                    JSON.parse(typeof value === 'string' ? value : JSON.stringify(value));
                    validatedValue = typeof value === 'string' ? value : JSON.stringify(value);
                } catch (e) {
                    return res.status(400).json({
                        success: false,
                        message: '配置值必须为有效的JSON格式'
                    });
                }
                break;
                
            default:
                validatedValue = value.toString();
        }
        
        // 应用验证规则
        if (config.validation_rule) {
            try {
                const regex = new RegExp(config.validation_rule);
                if (!regex.test(validatedValue)) {
                    return res.status(400).json({
                        success: false,
                        message: '配置值不符合验证规则'
                    });
                }
            } catch (e) {
                console.warn('Invalid validation rule:', config.validation_rule);
            }
        }
        
        // 更新配置
        const updateFields = ['config_value = $2', 'updated_at = NOW()', 'updated_by = $3'];
        const updateParams = [id, validatedValue, adminId];
        
        if (description !== undefined) {
            updateFields.push('description = $4');
            updateParams.push(description);
        }
        
        const updateResult = await req.db.query(`
            UPDATE system_configs 
            SET ${updateFields.join(', ')}
            WHERE id = $1
            RETURNING *
        `, updateParams);
        
        res.json({
            success: true,
            message: '系统配置更新成功',
            data: {
                id: updateResult.rows[0].id,
                key: updateResult.rows[0].config_key,
                value: validatedValue,
                updatedAt: updateResult.rows[0].updated_at
            }
        });
        
    } catch (error) {
        console.error('Update system config error:', error);
        res.status(500).json({
            success: false,
            message: '更新系统配置失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/system/announcements
 * @desc 获取系统公告列表
 * @access Admin (Content Read Permission)
 */
router.get('/announcements', [
    requirePermission(PERMISSIONS.CONTENT_READ),
    query('status').optional().isIn(['draft', 'published', 'archived']).withMessage('无效的公告状态'),
    query('type').optional().isIn(['system', 'maintenance', 'feature', 'promotion']).withMessage('无效的公告类型'),
    query('page').optional().isInt({ min: 1 }).withMessage('页码必须为正整数'),
    query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('每页数量必须在1-50之间'),
    logAdminAction('view_announcements', 'system')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { status, type, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        // 构建查询条件
        let whereClause = 'WHERE 1=1';
        let queryParams = [];
        let paramIndex = 1;
        
        if (status) {
            whereClause += ` AND status = $${paramIndex}`;
            queryParams.push(status);
            paramIndex++;
        }
        
        if (type) {
            whereClause += ` AND announcement_type = $${paramIndex}`;
            queryParams.push(type);
            paramIndex++;
        }
        
        // 查询公告列表
        const announcementsQuery = `
            SELECT 
                id,
                title,
                content,
                announcement_type,
                status,
                priority,
                target_audience,
                start_time,
                end_time,
                created_by,
                created_at,
                updated_at
            FROM system_announcements 
            ${whereClause}
            ORDER BY priority DESC, created_at DESC
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `;
        
        queryParams.push(limit, offset);
        
        // 查询总数
        const countQuery = `
            SELECT COUNT(*) as total
            FROM system_announcements 
            ${whereClause}
        `;
        
        const [announcementsResult, countResult] = await Promise.all([
            req.db.query(announcementsQuery, queryParams),
            req.db.query(countQuery, queryParams.slice(0, -2))
        ]);
        
        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);
        
        res.json({
            success: true,
            data: {
                announcements: announcementsResult.rows.map(row => ({
                    id: row.id,
                    title: row.title,
                    content: row.content,
                    type: row.announcement_type,
                    status: row.status,
                    priority: row.priority,
                    targetAudience: row.target_audience,
                    startTime: row.start_time,
                    endTime: row.end_time,
                    createdBy: row.created_by,
                    createdAt: row.created_at,
                    updatedAt: row.updated_at
                })),
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });
        
    } catch (error) {
        console.error('Get announcements error:', error);
        res.status(500).json({
            success: false,
            message: '获取系统公告失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route POST /api/admin/system/announcements
 * @desc 创建系统公告
 * @access Admin (Content Write Permission)
 */
router.post('/announcements', [
    requirePermission(PERMISSIONS.CONTENT_WRITE),
    body('title').isLength({ min: 1, max: 200 }).withMessage('标题长度必须在1-200字符之间'),
    body('content').isLength({ min: 1, max: 5000 }).withMessage('内容长度必须在1-5000字符之间'),
    body('type').isIn(['system', 'maintenance', 'feature', 'promotion']).withMessage('无效的公告类型'),
    body('priority').optional().isInt({ min: 1, max: 10 }).withMessage('优先级必须在1-10之间'),
    body('targetAudience').optional().isIn(['all', 'users', 'admins']).withMessage('无效的目标受众'),
    body('startTime').optional().isISO8601().withMessage('开始时间格式无效'),
    body('endTime').optional().isISO8601().withMessage('结束时间格式无效'),
    logAdminAction('create_announcement', 'system')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const {
            title,
            content,
            type,
            priority = 5,
            targetAudience = 'all',
            startTime,
            endTime
        } = req.body;
        
        const adminId = req.admin.id;
        
        // 验证时间范围
        if (startTime && endTime && new Date(startTime) >= new Date(endTime)) {
            return res.status(400).json({
                success: false,
                message: '开始时间必须早于结束时间'
            });
        }
        
        const result = await req.db.query(`
            INSERT INTO system_announcements (
                title, content, announcement_type, priority, 
                target_audience, start_time, end_time, 
                created_by, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'draft')
            RETURNING *
        `, [
            title, content, type, priority,
            targetAudience, startTime || null, endTime || null,
            adminId
        ]);
        
        res.status(201).json({
            success: true,
            message: '系统公告创建成功',
            data: {
                id: result.rows[0].id,
                title: result.rows[0].title,
                type: result.rows[0].announcement_type,
                status: result.rows[0].status,
                createdAt: result.rows[0].created_at
            }
        });
        
    } catch (error) {
        console.error('Create announcement error:', error);
        res.status(500).json({
            success: false,
            message: '创建系统公告失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route PUT /api/admin/system/announcements/:id
 * @desc 更新系统公告
 * @access Admin (Content Write Permission)
 */
router.put('/announcements/:id', [
    requirePermission(PERMISSIONS.CONTENT_WRITE),
    body('title').optional().isLength({ min: 1, max: 200 }).withMessage('标题长度必须在1-200字符之间'),
    body('content').optional().isLength({ min: 1, max: 5000 }).withMessage('内容长度必须在1-5000字符之间'),
    body('type').optional().isIn(['system', 'maintenance', 'feature', 'promotion']).withMessage('无效的公告类型'),
    body('status').optional().isIn(['draft', 'published', 'archived']).withMessage('无效的公告状态'),
    body('priority').optional().isInt({ min: 1, max: 10 }).withMessage('优先级必须在1-10之间'),
    body('targetAudience').optional().isIn(['all', 'users', 'admins']).withMessage('无效的目标受众'),
    body('startTime').optional().isISO8601().withMessage('开始时间格式无效'),
    body('endTime').optional().isISO8601().withMessage('结束时间格式无效'),
    logAdminAction('update_announcement', 'system')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { id } = req.params;
        const updateData = req.body;
        
        // 检查公告是否存在
        const existingResult = await req.db.query(`
            SELECT id FROM system_announcements WHERE id = $1
        `, [id]);
        
        if (existingResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: '公告不存在'
            });
        }
        
        // 验证时间范围
        if (updateData.startTime && updateData.endTime && 
            new Date(updateData.startTime) >= new Date(updateData.endTime)) {
            return res.status(400).json({
                success: false,
                message: '开始时间必须早于结束时间'
            });
        }
        
        // 构建更新字段
        const updateFields = [];
        const updateParams = [id];
        let paramIndex = 2;
        
        const fieldMapping = {
            title: 'title',
            content: 'content',
            type: 'announcement_type',
            status: 'status',
            priority: 'priority',
            targetAudience: 'target_audience',
            startTime: 'start_time',
            endTime: 'end_time'
        };
        
        Object.keys(updateData).forEach(key => {
            if (fieldMapping[key] && updateData[key] !== undefined) {
                updateFields.push(`${fieldMapping[key]} = $${paramIndex}`);
                updateParams.push(updateData[key]);
                paramIndex++;
            }
        });
        
        if (updateFields.length === 0) {
            return res.status(400).json({
                success: false,
                message: '没有提供有效的更新字段'
            });
        }
        
        updateFields.push('updated_at = NOW()');
        
        const result = await req.db.query(`
            UPDATE system_announcements 
            SET ${updateFields.join(', ')}
            WHERE id = $1
            RETURNING *
        `, updateParams);
        
        res.json({
            success: true,
            message: '系统公告更新成功',
            data: {
                id: result.rows[0].id,
                title: result.rows[0].title,
                status: result.rows[0].status,
                updatedAt: result.rows[0].updated_at
            }
        });
        
    } catch (error) {
        console.error('Update announcement error:', error);
        res.status(500).json({
            success: false,
            message: '更新系统公告失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route DELETE /api/admin/system/announcements/:id
 * @desc 删除系统公告
 * @access Admin (Content Write Permission)
 */
router.delete('/announcements/:id', [
    requirePermission(PERMISSIONS.CONTENT_WRITE),
    logAdminAction('delete_announcement', 'system')
], async (req, res) => {
    try {
        const { id } = req.params;
        
        const result = await req.db.query(`
            DELETE FROM system_announcements 
            WHERE id = $1
            RETURNING id, title
        `, [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: '公告不存在'
            });
        }
        
        res.json({
            success: true,
            message: '系统公告删除成功',
            data: {
                id: result.rows[0].id,
                title: result.rows[0].title
            }
        });
        
    } catch (error) {
        console.error('Delete announcement error:', error);
        res.status(500).json({
            success: false,
            message: '删除系统公告失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route GET /api/admin/system/versions
 * @desc 获取系统版本信息
 * @access Admin (System Config Read Permission)
 */
router.get('/versions', [
    requirePermission(PERMISSIONS.SYSTEM_CONFIG_READ),
    query('page').optional().isInt({ min: 1 }).withMessage('页码必须为正整数'),
    query('limit').optional().isInt({ min: 1, max: 50 }).withMessage('每页数量必须在1-50之间'),
    logAdminAction('view_versions', 'system')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const { page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        // 查询版本列表
        const versionsQuery = `
            SELECT 
                id,
                version_number,
                version_name,
                description,
                release_notes,
                release_date,
                is_current,
                is_required,
                download_url,
                file_size,
                created_by,
                created_at
            FROM app_versions 
            ORDER BY release_date DESC, version_number DESC
            LIMIT $1 OFFSET $2
        `;
        
        // 查询总数
        const countQuery = `
            SELECT COUNT(*) as total
            FROM app_versions
        `;
        
        const [versionsResult, countResult] = await Promise.all([
            req.db.query(versionsQuery, [limit, offset]),
            req.db.query(countQuery)
        ]);
        
        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);
        
        res.json({
            success: true,
            data: {
                versions: versionsResult.rows.map(row => ({
                    id: row.id,
                    versionNumber: row.version_number,
                    versionName: row.version_name,
                    description: row.description,
                    releaseNotes: row.release_notes,
                    releaseDate: row.release_date,
                    isCurrent: row.is_current,
                    isRequired: row.is_required,
                    downloadUrl: row.download_url,
                    fileSize: row.file_size,
                    createdBy: row.created_by,
                    createdAt: row.created_at
                })),
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    total,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });
        
    } catch (error) {
        console.error('Get versions error:', error);
        res.status(500).json({
            success: false,
            message: '获取版本信息失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route POST /api/admin/system/versions
 * @desc 创建新版本
 * @access Admin (System Config Write Permission)
 */
router.post('/versions', [
    requirePermission(PERMISSIONS.SYSTEM_CONFIG_WRITE),
    body('versionNumber').matches(/^\d+\.\d+\.\d+$/).withMessage('版本号格式无效（应为x.y.z格式）'),
    body('versionName').isLength({ min: 1, max: 100 }).withMessage('版本名称长度必须在1-100字符之间'),
    body('description').optional().isLength({ max: 500 }).withMessage('描述长度不能超过500字符'),
    body('releaseNotes').optional().isLength({ max: 5000 }).withMessage('发布说明长度不能超过5000字符'),
    body('releaseDate').isISO8601().withMessage('发布日期格式无效'),
    body('isRequired').optional().isBoolean().withMessage('是否必需更新必须为布尔值'),
    body('downloadUrl').optional().isURL().withMessage('下载链接格式无效'),
    body('fileSize').optional().isInt({ min: 0 }).withMessage('文件大小必须为非负整数'),
    logAdminAction('create_version', 'system')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: '请求参数无效',
                errors: errors.array()
            });
        }
        
        const {
            versionNumber,
            versionName,
            description,
            releaseNotes,
            releaseDate,
            isRequired = false,
            downloadUrl,
            fileSize
        } = req.body;
        
        const adminId = req.admin.id;
        
        // 检查版本号是否已存在
        const existingResult = await req.db.query(`
            SELECT id FROM app_versions WHERE version_number = $1
        `, [versionNumber]);
        
        if (existingResult.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: '版本号已存在'
            });
        }
        
        const result = await req.db.query(`
            INSERT INTO app_versions (
                version_number, version_name, description, 
                release_notes, release_date, is_required, 
                download_url, file_size, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
        `, [
            versionNumber, versionName, description,
            releaseNotes, releaseDate, isRequired,
            downloadUrl, fileSize, adminId
        ]);
        
        res.status(201).json({
            success: true,
            message: '版本创建成功',
            data: {
                id: result.rows[0].id,
                versionNumber: result.rows[0].version_number,
                versionName: result.rows[0].version_name,
                releaseDate: result.rows[0].release_date,
                createdAt: result.rows[0].created_at
            }
        });
        
    } catch (error) {
        console.error('Create version error:', error);
        res.status(500).json({
            success: false,
            message: '创建版本失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

/**
 * @route PUT /api/admin/system/versions/:id/current
 * @desc 设置当前版本
 * @access Admin (System Config Write Permission)
 */
router.put('/versions/:id/current', [
    requirePermission(PERMISSIONS.SYSTEM_CONFIG_WRITE),
    logAdminAction('set_current_version', 'system')
], async (req, res) => {
    try {
        const { id } = req.params;
        
        // 开始事务
        await req.db.query('BEGIN');
        
        try {
            // 检查版本是否存在
            const versionResult = await req.db.query(`
                SELECT id, version_number FROM app_versions WHERE id = $1
            `, [id]);
            
            if (versionResult.rows.length === 0) {
                await req.db.query('ROLLBACK');
                return res.status(404).json({
                    success: false,
                    message: '版本不存在'
                });
            }
            
            // 清除所有版本的当前标记
            await req.db.query(`
                UPDATE app_versions SET is_current = false
            `);
            
            // 设置新的当前版本
            await req.db.query(`
                UPDATE app_versions 
                SET is_current = true, updated_at = NOW()
                WHERE id = $1
            `, [id]);
            
            await req.db.query('COMMIT');
            
            res.json({
                success: true,
                message: '当前版本设置成功',
                data: {
                    id: versionResult.rows[0].id,
                    versionNumber: versionResult.rows[0].version_number
                }
            });
            
        } catch (error) {
            await req.db.query('ROLLBACK');
            throw error;
        }
        
    } catch (error) {
        console.error('Set current version error:', error);
        res.status(500).json({
            success: false,
            message: '设置当前版本失败',
            error: process.env.NODE_ENV === 'development' ? error.message : '服务器内部错误'
        });
    }
});

module.exports = router;