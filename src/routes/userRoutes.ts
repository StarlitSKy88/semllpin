import { Router } from 'express';
import userController from '@/controllers/userController';
import { authMiddleware, requireAdmin, optionalAuthMiddleware } from '@/middleware/auth';
import { validateRequest, userSchemas, adminSchemas } from '@/middleware/validation';
import { rateLimitByUser } from '@/middleware/auth';

const router = Router();

// Public routes
router.post('/register',
  validateRequest(userSchemas.register),
  rateLimitByUser(5, 15 * 60 * 1000), // 5 requests per 15 minutes
  userController.register,
);

router.post('/login',
  validateRequest(userSchemas.login),
  rateLimitByUser(10, 15 * 60 * 1000), // 10 requests per 15 minutes
  userController.login,
);

router.post('/refresh-token',
  rateLimitByUser(20, 60 * 1000), // 20 requests per minute
  userController.refreshToken,
);

router.post('/forgot-password',
  validateRequest(userSchemas.forgotPassword),
  rateLimitByUser(3, 60 * 60 * 1000), // 3 requests per hour
  userController.forgotPassword,
);

router.post('/reset-password',
  validateRequest(userSchemas.resetPassword),
  rateLimitByUser(5, 60 * 60 * 1000), // 5 requests per hour
  userController.resetPassword,
);

// Public profile (can be viewed without auth)
router.get('/:id',
  optionalAuthMiddleware,
  userController.getUserById,
);

// Protected routes
router.use(authMiddleware);

router.post('/logout', userController.logout);

router.get('/profile/me', userController.getProfile);

router.put('/profile',
  validateRequest(userSchemas.updateProfile),
  userController.updateProfile,
);

router.put('/password',
  validateRequest(userSchemas.changePassword),
  rateLimitByUser(5, 60 * 60 * 1000), // 5 requests per hour
  userController.changePassword,
);

// Admin routes
router.get('/',
  requireAdmin,
  userController.getUsersList,
);

router.put('/:id',
  requireAdmin,
  validateRequest(adminSchemas.updateUser),
  userController.updateUser,
);

router.delete('/:id',
  requireAdmin,
  userController.deleteUser,
);

export default router;
