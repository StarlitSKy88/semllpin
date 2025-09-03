"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteMediaFile = exports.getMediaFile = exports.getUserMediaFiles = exports.uploadMedia = void 0;
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const uuid_1 = require("uuid");
const database_1 = require("@/config/database");
const errorHandler_1 = require("@/middleware/errorHandler");
const logger_1 = require("@/utils/logger");
const getFileType = (mimeType) => {
    if (mimeType.startsWith('image/')) {
        return 'image';
    }
    if (mimeType.startsWith('video/')) {
        return 'video';
    }
    if (mimeType.startsWith('audio/')) {
        return 'audio';
    }
    throw new errorHandler_1.AppError('不支持的文件类型', 400);
};
const generateFileUrl = (filePath) => {
    const baseUrl = process.env['BASE_URL'] || 'http://localhost:3000';
    return `${baseUrl}/uploads/${path_1.default.relative(path_1.default.join(process.cwd(), 'uploads'), filePath)}`;
};
const uploadMedia = async (req, res, next) => {
    try {
        const files = req.files;
        const userId = req.user?.id;
        if (!files || files.length === 0) {
            throw new errorHandler_1.AppError('没有上传文件', 400);
        }
        if (!userId) {
            throw new errorHandler_1.AppError('用户未认证', 401);
        }
        const uploadedFiles = [];
        for (const file of files) {
            const fileId = (0, uuid_1.v4)();
            const fileType = getFileType(file.mimetype);
            const fileUrl = generateFileUrl(file.path);
            const mediaFile = {
                id: fileId,
                user_id: userId,
                filename: file.filename,
                original_filename: file.originalname,
                file_path: file.path,
                file_url: fileUrl,
                file_size: file.size,
                mime_type: file.mimetype,
                file_type: fileType,
                metadata: {},
                status: 'active',
                created_at: new Date(),
                updated_at: new Date(),
            };
            const dbClient = process.env['DB_CLIENT'] || 'sqlite3';
            if (dbClient === 'postgresql') {
                await (0, database_1.db)('media_files').insert(mediaFile);
            }
            else {
                await (0, database_1.db)('media_files').insert({
                    id: fileId,
                    user_id: userId,
                    filename: file.filename,
                    original_name: file.originalname,
                    file_path: file.path,
                    file_url: fileUrl,
                    file_size: file.size,
                    mime_type: file.mimetype,
                    status: 'active',
                    created_at: new Date(),
                    updated_at: new Date(),
                });
            }
            uploadedFiles.push(mediaFile);
        }
        logger_1.logger.info(`用户 ${userId} 上传了 ${files.length} 个文件`);
        res.json({
            success: true,
            message: '文件上传成功',
            data: {
                files: uploadedFiles.map(file => ({
                    id: file.id,
                    filename: file.filename,
                    original_filename: file.original_filename,
                    file_url: file.file_url,
                    file_size: file.file_size,
                    mime_type: file.mime_type,
                    file_type: file.file_type,
                    created_at: file.created_at,
                })),
            },
        });
    }
    catch (error) {
        next(error);
    }
};
exports.uploadMedia = uploadMedia;
const getUserMediaFiles = async (req, res, next) => {
    try {
        const userId = req.user?.id;
        const { page = 1, limit = 20, fileType, sortBy = 'created_at', sortOrder = 'desc', } = req.query;
        if (!userId) {
            throw new errorHandler_1.AppError('用户未认证', 401);
        }
        let query = (0, database_1.db)('media_files')
            .where('user_id', userId)
            .where('status', 'active');
        const dbClient = process.env['DB_CLIENT'] || 'sqlite3';
        if (fileType && dbClient === 'postgresql') {
            query = query.where('file_type', fileType);
        }
        const totalResult = await query.clone().count('* as count').first();
        const total = Number(totalResult?.['count'] || 0);
        let selectFields;
        if (dbClient === 'postgresql') {
            selectFields = [
                'id',
                'filename',
                'original_filename',
                'file_url',
                'file_size',
                'mime_type',
                'file_type',
                'width',
                'height',
                'duration',
                'thumbnail_url',
                'created_at',
            ];
        }
        else {
            selectFields = [
                'id',
                'filename',
                'original_name as original_filename',
                'file_url',
                'file_size',
                'mime_type',
                'width',
                'height',
                'duration',
                'thumbnail_url',
                'created_at',
            ];
        }
        const files = await query
            .orderBy(sortBy, sortOrder)
            .limit(Number(limit))
            .offset((Number(page) - 1) * Number(limit))
            .select(selectFields);
        res.json({
            success: true,
            data: {
                files,
                pagination: {
                    page: Number(page),
                    limit: Number(limit),
                    total,
                    pages: Math.ceil(total / Number(limit)),
                },
            },
        });
    }
    catch (error) {
        next(error);
    }
};
exports.getUserMediaFiles = getUserMediaFiles;
const getMediaFile = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            throw new errorHandler_1.AppError('用户未认证', 401);
        }
        const file = await (0, database_1.db)('media_files')
            .where('id', id)
            .where('user_id', userId)
            .where('status', 'active')
            .first();
        if (!file) {
            throw new errorHandler_1.AppError('文件不存在', 404);
        }
        res.json({
            success: true,
            data: file,
        });
    }
    catch (error) {
        next(error);
    }
};
exports.getMediaFile = getMediaFile;
const deleteMediaFile = async (req, res, next) => {
    try {
        const { id } = req.params;
        const userId = req.user?.id;
        if (!userId) {
            throw new errorHandler_1.AppError('用户未认证', 401);
        }
        const file = await (0, database_1.db)('media_files')
            .where('id', id)
            .where('user_id', userId)
            .where('status', 'active')
            .first();
        if (!file) {
            throw new errorHandler_1.AppError('文件不存在', 404);
        }
        await (0, database_1.db)('media_files')
            .where('id', id)
            .update({
            status: 'deleted',
            updated_at: new Date(),
        });
        try {
            if (fs_1.default.existsSync(file.file_path)) {
                fs_1.default.unlinkSync(file.file_path);
            }
        }
        catch (fsError) {
            logger_1.logger.warn(`删除物理文件失败: ${file.file_path}`, fsError);
        }
        logger_1.logger.info(`用户 ${userId} 删除了文件 ${id}`);
        res.json({
            success: true,
            message: '文件删除成功',
        });
    }
    catch (error) {
        next(error);
    }
};
exports.deleteMediaFile = deleteMediaFile;
//# sourceMappingURL=mediaController.js.map