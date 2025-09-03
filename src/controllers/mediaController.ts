import { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import { v4 as uuidv4 } from 'uuid';
import { db } from '@/config/database';
import { AppError } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';

// 媒体文件接口
interface MediaFile {
  id: string;
  user_id: string;
  annotation_id?: string;
  filename: string;
  original_filename: string;
  file_path: string;
  file_url: string;
  file_size: number;
  mime_type: string;
  file_type: 'image' | 'video' | 'audio';
  width?: number;
  height?: number;
  duration?: number;
  thumbnail_url?: string;
  metadata: any;
  status: 'active' | 'deleted' | 'processing' | 'failed';
  upload_session_id?: string;
  created_at: Date;
  updated_at: Date;
}

// 获取文件类型
const getFileType = (mimeType: string): 'image' | 'video' | 'audio' => {
  if (mimeType.startsWith('image/')) {
    return 'image';
  }
  if (mimeType.startsWith('video/')) {
    return 'video';
  }
  if (mimeType.startsWith('audio/')) {
    return 'audio';
  }
  throw new AppError('不支持的文件类型', 400);
};

// 生成文件URL
const generateFileUrl = (filePath: string): string => {
  const baseUrl = process.env['BASE_URL'] || 'http://localhost:3000';
  return `${baseUrl}/uploads/${path.relative(path.join(process.cwd(), 'uploads'), filePath)}`;
};

// 上传媒体文件
export const uploadMedia = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const files = req.files as Express.Multer.File[];
    const userId = req.user?.id;

    if (!files || files.length === 0) {
      throw new AppError('没有上传文件', 400);
    }

    if (!userId) {
      throw new AppError('用户未认证', 401);
    }

    const uploadedFiles: MediaFile[] = [];

    for (const file of files) {
      const fileId = uuidv4();
      const fileType = getFileType(file.mimetype);
      const fileUrl = generateFileUrl(file.path);

      // 保存文件信息到数据库
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
        status: 'active' as const,
        created_at: new Date(),
        updated_at: new Date(),
      };

      // 根据数据库类型选择插入方式
      const dbClient = process.env['DB_CLIENT'] || 'sqlite3';

      if (dbClient === 'postgresql') {
        await db('media_files').insert(mediaFile);
      } else {
        // SQLite - 使用正确的字段名
        await db('media_files').insert({
          id: fileId,
          user_id: userId,
          filename: file.filename,
          original_name: file.originalname, // SQLite中的字段名
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

    logger.info(`用户 ${userId} 上传了 ${files.length} 个文件`);

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
  } catch (error) {
    next(error);
  }
};

// 获取用户的媒体文件列表
export const getUserMediaFiles = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const userId = req.user?.id;
    const {
      page = 1,
      limit = 20,
      fileType,
      sortBy = 'created_at',
      sortOrder = 'desc',
    } = req.query;

    if (!userId) {
      throw new AppError('用户未认证', 401);
    }

    let query = db('media_files')
      .where('user_id', userId)
      .where('status', 'active');

    // 根据数据库类型处理文件类型过滤
    const dbClient = process.env['DB_CLIENT'] || 'sqlite3';
    if (fileType && dbClient === 'postgresql') {
      query = query.where('file_type', fileType as string);
    }
    // SQLite中没有file_type字段，暂时跳过此过滤

    // 获取总数
    const totalResult = await query.clone().count('* as count').first();
    const total = Number(totalResult?.['count'] || 0);

    // 获取分页数据 - 根据数据库类型选择字段
    let selectFields: string[];

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
    } else {
      // SQLite字段
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
      .orderBy(sortBy as string, sortOrder as string)
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
  } catch (error) {
    next(error);
  }
};

// 获取单个媒体文件
export const getMediaFile = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      throw new AppError('用户未认证', 401);
    }

    const file = await db('media_files')
      .where('id', id)
      .where('user_id', userId)
      .where('status', 'active')
      .first();

    if (!file) {
      throw new AppError('文件不存在', 404);
    }

    res.json({
      success: true,
      data: file,
    });
  } catch (error) {
    next(error);
  }
};

// 删除媒体文件
export const deleteMediaFile = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  try {
    const { id } = req.params;
    const userId = req.user?.id;

    if (!userId) {
      throw new AppError('用户未认证', 401);
    }

    const file = await db('media_files')
      .where('id', id)
      .where('user_id', userId)
      .where('status', 'active')
      .first();

    if (!file) {
      throw new AppError('文件不存在', 404);
    }

    // 软删除 - 只更新状态
    await db('media_files')
      .where('id', id)
      .update({
        status: 'deleted',
        updated_at: new Date(),
      });

    // 可选：删除物理文件
    try {
      if (fs.existsSync(file.file_path)) {
        fs.unlinkSync(file.file_path);
      }
    } catch (fsError) {
      logger.warn(`删除物理文件失败: ${file.file_path}`, fsError);
    }

    logger.info(`用户 ${userId} 删除了文件 ${id}`);

    res.json({
      success: true,
      message: '文件删除成功',
    });
  } catch (error) {
    next(error);
  }
};
