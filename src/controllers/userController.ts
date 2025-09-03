import { Request, Response, NextFunction } from 'express';
import { UserModel, CreateUserData, UpdateUserData } from '@/models/User';
import {
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
  blacklistToken,
} from '@/middleware/auth';
import {
  AppError,
  createValidationError,
  createAuthError,
  createConflictError,
  createNotFoundError,
} from '@/middleware/errorHandler';
import { asyncHandler } from '@/middleware/errorHandler';
import { logger } from '@/utils/logger';
import { cacheService } from '@/config/redis';
import crypto from 'crypto';

// Register new user
export const register = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { email, password, username, displayName, university, graduation_year } = req.body;

  if (!email || !password || !username) {
    throw createValidationError('credentials', '邮箱、密码和用户名不能为空');
  }

  // Check if email already exists
  if (await UserModel.emailExists(email)) {
    throw createConflictError('邮箱已被注册');
  }

  // Check if username already exists
  if (await UserModel.usernameExists(username)) {
    throw createConflictError('用户名已被使用');
  }

  // Create user
  const userData: CreateUserData = {
    email,
    password,
    username,
    display_name: displayName || username,
    university,
    graduation_year,
  };

  const user = await UserModel.create(userData);

  // Generate tokens
  const accessToken = generateToken({
    sub: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
  });

  const refreshToken = generateRefreshToken(user.id);

  // Cache user data
  await cacheService.set(
    `user:${user.id}`,
    JSON.stringify({
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      status: user.status,
    }),
    3600, // 1 hour
  );

  // Store refresh token
  await cacheService.set(
    `refresh_token:${user.id}`,
    refreshToken,
    7 * 24 * 3600, // 7 days
  );

  logger.info('用户注册成功', { userId: user.id, email: user.email });

  res.status(201).json({
    success: true,
    message: '注册成功',
    data: {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.display_name,
        university: user.university,
        graduation_year: user.graduation_year,
        role: user.role,
        emailVerified: user.email_verified,
        createdAt: user.created_at,
      },
      tokens: {
        accessToken,
        refreshToken,
        expiresIn: '24h',
      },
    },
  });
});

// Login user
export const login = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw createValidationError('credentials', '邮箱和密码不能为空');
  }

  // Find user by email
  const user = await UserModel.findByEmail(email);
  if (!user) {
    throw createAuthError('邮箱或密码错误');
  }

  // Check if user is active
  if (user.status !== 'active') {
    throw createAuthError('账户已被禁用');
  }

  // Verify password
  const isValidPassword = await UserModel.verifyPassword(user, password);
  if (!isValidPassword) {
    throw createAuthError('邮箱或密码错误');
  }

  // Generate tokens
  const accessToken = generateToken({
    sub: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
  });

  const refreshToken = generateRefreshToken(user.id);

  // Cache user data
  await cacheService.set(
    `user:${user.id}`,
    JSON.stringify({
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      status: user.status,
    }),
    3600, // 1 hour
  );

  // Store refresh token
  await cacheService.set(
    `refresh_token:${user.id}`,
    refreshToken,
    7 * 24 * 3600, // 7 days
  );

  // Update last login
  await UserModel.updateLastLogin(user.id);

  logger.info('用户登录成功', { userId: user.id, email: user.email });

  res.json({
    success: true,
    message: '登录成功',
    data: {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.display_name,
        role: user.role,
        emailVerified: user.email_verified,
        lastLoginAt: user.last_login_at,
      },
      tokens: {
        accessToken,
        refreshToken,
        expiresIn: '24h',
      },
    },
  });
});

// Refresh access token
export const refreshToken = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { refreshToken: token } = req.body;

  if (!token) {
    throw createAuthError('刷新令牌缺失');
  }

  try {
    // Verify refresh token
    const payload = await verifyRefreshToken(token);

    // Check if refresh token exists in cache
    const cachedToken = await cacheService.get(`refresh_token:${payload.sub}`);
    if (cachedToken !== token) {
      throw createAuthError('刷新令牌无效');
    }

    // Get user
    const user = await UserModel.findById(payload.sub);
    if (!user || user.status !== 'active') {
      throw createAuthError('用户不存在或已被禁用');
    }

    // Generate new access token
    const accessToken = generateToken({
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    });

    res.json({
      success: true,
      message: '令牌刷新成功',
      data: {
        accessToken,
        expiresIn: '24h',
      },
    });
  } catch (error) {
    throw createAuthError('刷新令牌无效或已过期');
  }
});

// Logout user
export const logout = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const token = req.headers.authorization?.substring(7);
  const userId = req.user?.id;

  if (token) {
    // Blacklist the access token
    await blacklistToken(token);
  }

  if (userId) {
    // Remove refresh token from cache
    await cacheService.del(`refresh_token:${userId}`);

    // Remove user cache
    await cacheService.del(`user:${userId}`);

    logger.info('用户登出成功', { userId });
  }

  res.json({
    success: true,
    message: '登出成功',
  });
});

// Get current user profile
export const getProfile = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const user = await UserModel.findById(userId);
  if (!user) {
    throw createNotFoundError('用户不存在');
  }

  // Get user statistics
  const stats = await UserModel.getStats(userId);

  res.json({
    success: true,
    data: {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.display_name,
        bio: user.bio,
        avatarUrl: user.avatar_url,
        role: user.role,
        emailVerified: user.email_verified,
        createdAt: user.created_at,
        lastLoginAt: user.last_login_at,
      },
      stats,
    },
  });
});

// Update user profile
export const updateProfile = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const { displayName, bio } = req.body;

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const updateData: UpdateUserData = {};

  if (displayName !== undefined) {
    updateData.display_name = displayName;
  }

  if (bio !== undefined) {
    updateData.bio = bio;
  }

  const user = await UserModel.update(userId, updateData);
  if (!user) {
    throw createNotFoundError('用户不存在');
  }

  // Update user cache
  await cacheService.set(
    `user:${userId}`,
    JSON.stringify({
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      status: user.status,
    }),
    3600, // 1 hour
  );

  res.json({
    success: true,
    message: '个人资料更新成功',
    data: {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.display_name,
        bio: user.bio,
        avatarUrl: user.avatar_url,
        role: user.role,
        updatedAt: user.updated_at,
      },
    },
  });
});

// Change password
export const changePassword = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const userId = req.user?.id;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    throw createValidationError('password', '当前密码和新密码不能为空');
  }

  if (!userId) {
    throw createAuthError('用户未认证');
  }

  const user = await UserModel.findById(userId);
  if (!user) {
    throw createNotFoundError('用户不存在');
  }

  // Verify current password
  const isValidPassword = await UserModel.verifyPassword(user, currentPassword);
  if (!isValidPassword) {
    throw createAuthError('当前密码错误');
  }

  // Update password
  const success = await UserModel.updatePassword(userId, newPassword);
  if (!success) {
    throw new AppError('密码更新失败', 500);
  }

  logger.info('用户密码更新成功', { userId });

  res.json({
    success: true,
    message: '密码更新成功',
  });
});

// Forgot password
export const forgotPassword = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { email } = req.body;

  if (!email) {
    throw createValidationError('email', '邮箱不能为空');
  }

  const user = await UserModel.findByEmail(email);
  if (!user) {
    // Don't reveal if email exists or not
    res.json({
      success: true,
      message: '如果邮箱存在，重置链接已发送',
    });
    return;
  }

  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetExpires = new Date(Date.now() + 3600000); // 1 hour

  // Save reset token
  await UserModel.setPasswordResetToken(email, resetToken, resetExpires);

  // TODO: Send email with reset link
  // await emailService.sendPasswordResetEmail(user.email, resetToken);

  logger.info('密码重置令牌生成', { userId: user.id, email });

  res.json({
    success: true,
    message: '重置链接已发送到您的邮箱',
  });
});

// Reset password
export const resetPassword = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { token, password } = req.body;

  if (!token || !password) {
    throw createValidationError('token', '重置令牌和新密码不能为空');
  }

  const user = await UserModel.findByPasswordResetToken(token);
  if (!user) {
    throw createAuthError('重置令牌无效或已过期');
  }

  // Update password
  const success = await UserModel.updatePassword(user.id, password);
  if (!success) {
    throw new AppError('密码重置失败', 500);
  }

  logger.info('密码重置成功', { userId: user.id });

  res.json({
    success: true,
    message: '密码重置成功',
  });
});

// Get user by ID (public profile)
export const getUserById = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;

  if (!id) {
    throw createValidationError('id', '用户ID不能为空');
  }

  const user = await UserModel.findById(id);
  if (!user) {
    throw createNotFoundError('用户不存在');
  }

  // Get user statistics
  const stats = await UserModel.getStats(id);

  res.json({
    success: true,
    data: {
      user: {
        id: user.id,
        username: user.username,
        displayName: user.display_name,
        bio: user.bio,
        avatarUrl: user.avatar_url,
        createdAt: user.created_at,
      },
      stats,
    },
  });
});

// Admin: Get users list
export const getUsersList = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const {
    page = 1,
    limit = 20,
    sortBy = 'created_at',
    sortOrder = 'desc',
    search,
    role,
    status,
  } = req.query;

  const options: any = {
    page: parseInt(page as string, 10),
    limit: parseInt(limit as string, 10),
    sortBy: sortBy as string,
    sortOrder: sortOrder as 'asc' | 'desc',
  };

  if (search) {
    options.search = search as string;
  }

  if (role) {
    options.role = role as string;
  }

  if (status) {
    options.status = status as string;
  }

  const { users, total } = await UserModel.getList(options);

  res.json({
    success: true,
    data: {
      users: users.map(user => ({
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.display_name,
        role: user.role,
        status: user.status,
        emailVerified: user.email_verified,
        createdAt: user.created_at,
        lastLoginAt: user.last_login_at,
      })),
      pagination: {
        page: parseInt(page as string, 10),
        limit: parseInt(limit as string, 10),
        total,
        pages: Math.ceil(total / parseInt(limit as string, 10)),
      },
    },
  });
});

// Admin: Update user
export const updateUser = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;
  const { status, role } = req.body;

  if (!id) {
    throw createValidationError('id', '用户ID不能为空');
  }

  const updateData: UpdateUserData = {};

  if (status !== undefined) {
    updateData.status = status;
  }

  if (role !== undefined) {
    updateData.role = role;
  }

  const user = await UserModel.update(id, updateData);
  if (!user) {
    throw createNotFoundError('用户不存在');
  }

  // Clear user cache
  await cacheService.del(`user:${id}`);

  logger.info('管理员更新用户信息', {
    adminId: req.user?.id || 'unknown',
    targetUserId: id,
    changes: updateData,
  });

  res.json({
    success: true,
    message: '用户信息更新成功',
    data: {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        displayName: user.display_name,
        role: user.role,
        status: user.status,
        updatedAt: user.updated_at,
      },
    },
  });
});

// Admin: Delete user
export const deleteUser = asyncHandler(async (
  req: Request,
  res: Response,
  _next: NextFunction,
): Promise<void> => {
  const { id } = req.params;

  if (!id) {
    throw createValidationError('id', '用户ID不能为空');
  }

  const success = await UserModel.delete(id);
  if (!success) {
    throw createNotFoundError('用户不存在');
  }

  // Clear user cache
  await cacheService.del(`user:${id}`);
  await cacheService.del(`refresh_token:${id}`);

  logger.info('管理员删除用户', {
    adminId: req.user?.id || 'unknown',
    targetUserId: id,
  });

  res.json({
    success: true,
    message: '用户删除成功',
  });
});

export default {
  register,
  login,
  refreshToken,
  logout,
  getProfile,
  updateProfile,
  changePassword,
  forgotPassword,
  resetPassword,
  getUserById,
  getUsersList,
  updateUser,
  deleteUser,
};
