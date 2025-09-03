"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const multer_1 = __importDefault(require("multer"));
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const auth_1 = require("@/middleware/auth");
const validation_1 = require("@/middleware/validation");
const mediaController_1 = require("@/controllers/mediaController");
const router = (0, express_1.Router)();
const uploadDir = path_1.default.join(process.cwd(), 'uploads');
if (!fs_1.default.existsSync(uploadDir)) {
    fs_1.default.mkdirSync(uploadDir, { recursive: true });
}
const storage = multer_1.default.diskStorage({
    destination: (req, _file, cb) => {
        const userDir = path_1.default.join(uploadDir, req.user?.id || 'anonymous');
        if (!fs_1.default.existsSync(userDir)) {
            fs_1.default.mkdirSync(userDir, { recursive: true });
        }
        cb(null, userDir);
    },
    filename: (_req, file, cb) => {
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        const ext = path_1.default.extname(file.originalname);
        cb(null, `${file.fieldname}-${uniqueSuffix}${ext}`);
    },
});
const fileFilter = (_req, file, cb) => {
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
    }
    else {
        cb(new Error('不支持的文件类型'));
    }
};
const upload = (0, multer_1.default)({
    storage,
    fileFilter,
    limits: {
        fileSize: 10 * 1024 * 1024,
        files: 5,
    },
});
router.post('/upload', auth_1.authMiddleware, upload.array('files', 5), mediaController_1.uploadMedia);
router.get('/my-files', auth_1.authMiddleware, (0, validation_1.validateRequest)(validation_1.mediaSchemas.getList), mediaController_1.getUserMediaFiles);
router.get('/:id', auth_1.authMiddleware, (0, validation_1.validateRequest)(validation_1.mediaSchemas.getById), mediaController_1.getMediaFile);
router.delete('/:id', auth_1.authMiddleware, (0, validation_1.validateRequest)(validation_1.mediaSchemas.delete), mediaController_1.deleteMediaFile);
exports.default = router;
//# sourceMappingURL=mediaRoutes.js.map