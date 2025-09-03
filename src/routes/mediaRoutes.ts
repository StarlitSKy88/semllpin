import { Router } from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { authMiddleware } from '@/middleware/auth';
import { validateRequest, mediaSchemas } from '@/middleware/validation';
import {
  uploadMedia,
  getMediaFile,
  deleteMediaFile,
  getUserMediaFiles,
} from '@/controllers/mediaController';

const router = Router();

// 确保上传目录存在
const uploadDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 配置multer存储
const storage = multer.diskStorage({
  destination: (req, _file, cb) => {
    const userDir = path.join(uploadDir, req.user?.id || 'anonymous');
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: (_req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
  },
});

// 文件过滤器
const fileFilter = (_req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  // 允许的文件类型
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/webp',
    'video/mp4',
    'video/webm',
    'video/quicktime',
  ];

  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('不支持的文件类型'));
  }
};

// 配置multer
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
    files: 5, // 最多5个文件
  },
});

// 上传媒体文件
router.post('/upload',
  authMiddleware,
  upload.array('files', 5),
  uploadMedia,
);

// 获取用户的媒体文件列表
router.get('/my-files',
  authMiddleware,
  validateRequest(mediaSchemas.getList),
  getUserMediaFiles,
);

// 获取单个媒体文件
router.get('/:id',
  authMiddleware,
  validateRequest(mediaSchemas.getById),
  getMediaFile,
);

// 删除媒体文件
router.delete('/:id',
  authMiddleware,
  validateRequest(mediaSchemas.delete),
  deleteMediaFile,
);

export default router;
