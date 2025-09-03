/**
 * JWT Authentication Middleware
 * Production-ready authentication with comprehensive security features
 */

import { Context } from '../context';
import { ApiError } from '../utils/errors';

// ==================== TYPES ====================

export interface JWTPayload {
  readonly sub: string; // User ID
  readonly email: string;
  readonly username: string;
  readonly role: 'user' | 'moderator' | 'admin';
  readonly permissions: string[];
  readonly iat: number; // Issued at
  readonly exp: number; // Expires at
  readonly aud: string; // Audience
  readonly iss: string; // Issuer
  readonly jti: string; // JWT ID for blacklisting
  readonly type: 'access' | 'refresh';
}

export interface RefreshTokenPayload {
  readonly sub: string;
  readonly jti: string;
  readonly type: 'refresh';
  readonly iat: number;
  readonly exp: number;
  readonly aud: string;
  readonly iss: string;
}

export interface TokenPair {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresIn: number;
  readonly tokenType: 'Bearer';
}

export interface AuthenticatedUser {
  readonly id: string;
  readonly email: string;
  readonly username: string;
  readonly role: 'user' | 'moderator' | 'admin';
  readonly permissions: string[];
  readonly tokenId: string;
}

// ==================== CONSTANTS ====================

const ACCESS_TOKEN_EXPIRY = 15 * 60; // 15 minutes
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days
const TOKEN_ISSUER = 'smellpin-api';
const TOKEN_AUDIENCE = 'smellpin-users';

// Algorithm for JWT signing
const ALGORITHM = 'HS256';

// ==================== JWT UTILITIES ====================

/**
 * Generate a cryptographically secure random string
 */
async function generateSecureToken(length: number = 32): Promise<string> {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Create JWT header
 */
function createJWTHeader(): string {
  const header = {
    alg: ALGORITHM,
    typ: 'JWT'
  };
  return base64UrlEncode(JSON.stringify(header));
}

/**
 * Base64URL encode (without padding)
 */
function base64UrlEncode(str: string): string {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Base64URL decode
 */
function base64UrlDecode(str: string): string {
  // Add padding if necessary
  const paddedStr = str + '='.repeat((4 - str.length % 4) % 4);
  const base64 = paddedStr.replace(/-/g, '+').replace(/_/g, '/');
  
  const decoder = new TextDecoder();
  const data = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  return decoder.decode(data);
}

/**
 * Create HMAC-SHA256 signature
 */
async function createSignature(message: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', key, messageData);
  const signatureArray = new Uint8Array(signature);
  
  return base64UrlEncode(String.fromCharCode(...signatureArray));
}

/**
 * Verify HMAC-SHA256 signature
 */
async function verifySignature(
  message: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const expectedSignature = await createSignature(message, secret);
  return expectedSignature === signature;
}

// ==================== TOKEN GENERATION ====================

/**
 * Generate access token
 */
export async function generateAccessToken(
  user: {
    id: string;
    email: string;
    username: string;
    role: 'user' | 'moderator' | 'admin';
    permissions?: string[];
  },
  env: any
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jti = await generateSecureToken();

  const payload: JWTPayload = {
    sub: user.id,
    email: user.email,
    username: user.username,
    role: user.role,
    permissions: user.permissions || [],
    iat: now,
    exp: now + ACCESS_TOKEN_EXPIRY,
    aud: TOKEN_AUDIENCE,
    iss: TOKEN_ISSUER,
    jti,
    type: 'access'
  };

  const header = createJWTHeader();
  const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
  const message = `${header}.${payloadEncoded}`;
  const signature = await createSignature(message, env.JWT_SECRET);

  return `${message}.${signature}`;
}

/**
 * Generate refresh token
 */
export async function generateRefreshToken(
  userId: string,
  env: any
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jti = await generateSecureToken();

  const payload: RefreshTokenPayload = {
    sub: userId,
    jti,
    type: 'refresh',
    iat: now,
    exp: now + REFRESH_TOKEN_EXPIRY,
    aud: TOKEN_AUDIENCE,
    iss: TOKEN_ISSUER
  };

  const header = createJWTHeader();
  const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
  const message = `${header}.${payloadEncoded}`;
  const signature = await createSignature(message, env.REFRESH_TOKEN_SECRET || env.JWT_SECRET);

  // Store refresh token in KV for revocation tracking
  await env.SESSIONS?.put(`refresh_token:${jti}`, JSON.stringify({
    userId,
    createdAt: now,
    expiresAt: now + REFRESH_TOKEN_EXPIRY,
    active: true
  }), { expirationTtl: REFRESH_TOKEN_EXPIRY });

  return `${message}.${signature}`;
}

/**
 * Generate token pair
 */
export async function generateTokenPair(
  user: {
    id: string;
    email: string;
    username: string;
    role: 'user' | 'moderator' | 'admin';
    permissions?: string[];
  },
  env: any
): Promise<TokenPair> {
  const [accessToken, refreshToken] = await Promise.all([
    generateAccessToken(user, env),
    generateRefreshToken(user.id, env)
  ]);

  return {
    accessToken,
    refreshToken,
    expiresIn: ACCESS_TOKEN_EXPIRY,
    tokenType: 'Bearer'
  };
}

// ==================== TOKEN VERIFICATION ====================

/**
 * Verify JWT token
 */
export async function verifyToken<T extends JWTPayload | RefreshTokenPayload>(
  token: string,
  secret: string,
  options: {
    type?: 'access' | 'refresh';
    checkBlacklist?: boolean;
    env?: any;
  } = {}
): Promise<T> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new ApiError('Invalid token format', 'INVALID_TOKEN', 401);
  }

  const [header, payload, signature] = parts;

  // Verify signature
  const message = `${header}.${payload}`;
  const isValid = await verifySignature(message, signature, secret);
  if (!isValid) {
    throw new ApiError('Invalid token signature', 'INVALID_TOKEN', 401);
  }

  // Parse payload
  let decodedPayload: T;
  try {
    decodedPayload = JSON.parse(base64UrlDecode(payload)) as T;
  } catch {
    throw new ApiError('Invalid token payload', 'INVALID_TOKEN', 401);
  }

  // Verify token type
  if (options.type && (decodedPayload as any).type !== options.type) {
    throw new ApiError('Invalid token type', 'INVALID_TOKEN_TYPE', 401);
  }

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (decodedPayload.exp <= now) {
    throw new ApiError('Token has expired', 'TOKEN_EXPIRED', 401);
  }

  // Check not before (if present)
  if ('nbf' in decodedPayload && (decodedPayload as any).nbf > now) {
    throw new ApiError('Token not yet valid', 'TOKEN_NOT_ACTIVE', 401);
  }

  // Verify issuer and audience
  if (decodedPayload.iss !== TOKEN_ISSUER) {
    throw new ApiError('Invalid token issuer', 'INVALID_TOKEN', 401);
  }

  if (decodedPayload.aud !== TOKEN_AUDIENCE) {
    throw new ApiError('Invalid token audience', 'INVALID_TOKEN', 401);
  }

  // Check blacklist for access tokens
  if (options.checkBlacklist && options.env?.SESSIONS && (decodedPayload as any).type === 'access') {
    const blacklisted = await options.env.SESSIONS.get(`blacklist:${(decodedPayload as any).jti}`);
    if (blacklisted) {
      throw new ApiError('Token has been revoked', 'TOKEN_REVOKED', 401);
    }
  }

  return decodedPayload;
}

/**
 * Verify access token
 */
export async function verifyAccessToken(token: string, env: any): Promise<JWTPayload> {
  return verifyToken<JWTPayload>(token, env.JWT_SECRET, {
    type: 'access',
    checkBlacklist: true,
    env
  });
}

/**
 * Verify refresh token
 */
export async function verifyRefreshToken(token: string, env: any): Promise<RefreshTokenPayload> {
  const payload = await verifyToken<RefreshTokenPayload>(
    token,
    env.REFRESH_TOKEN_SECRET || env.JWT_SECRET,
    { type: 'refresh' }
  );

  // Check if refresh token is still active
  if (env.SESSIONS) {
    const tokenData = await env.SESSIONS.get(`refresh_token:${payload.jti}`);
    if (!tokenData) {
      throw new ApiError('Refresh token not found', 'TOKEN_REVOKED', 401);
    }

    const session = JSON.parse(tokenData);
    if (!session.active) {
      throw new ApiError('Refresh token has been revoked', 'TOKEN_REVOKED', 401);
    }
  }

  return payload;
}

// ==================== TOKEN REVOCATION ====================

/**
 * Revoke access token (add to blacklist)
 */
export async function revokeAccessToken(tokenId: string, env: any): Promise<void> {
  if (env.SESSIONS) {
    // Add to blacklist until token would naturally expire
    await env.SESSIONS.put(`blacklist:${tokenId}`, 'true', {
      expirationTtl: ACCESS_TOKEN_EXPIRY
    });
  }
}

/**
 * Revoke refresh token
 */
export async function revokeRefreshToken(tokenId: string, env: any): Promise<void> {
  if (env.SESSIONS) {
    const tokenData = await env.SESSIONS.get(`refresh_token:${tokenId}`);
    if (tokenData) {
      const session = JSON.parse(tokenData);
      session.active = false;
      session.revokedAt = Math.floor(Date.now() / 1000);
      
      await env.SESSIONS.put(`refresh_token:${tokenId}`, JSON.stringify(session), {
        expirationTtl: REFRESH_TOKEN_EXPIRY
      });
    }
  }
}

/**
 * Revoke all user tokens
 */
export async function revokeAllUserTokens(userId: string, env: any): Promise<void> {
  if (!env.SESSIONS) return;

  // List all refresh tokens for this user
  const listResponse = await env.SESSIONS.list({ prefix: 'refresh_token:' });
  
  for (const key of listResponse.keys) {
    const tokenData = await env.SESSIONS.get(key.name);
    if (tokenData) {
      const session = JSON.parse(tokenData);
      if (session.userId === userId && session.active) {
        session.active = false;
        session.revokedAt = Math.floor(Date.now() / 1000);
        await env.SESSIONS.put(key.name, JSON.stringify(session));
      }
    }
  }
}

// ==================== MIDDLEWARE ====================

/**
 * Extract token from Authorization header
 */
function extractTokenFromHeader(request: Request): string | null {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) return null;

  const match = authHeader.match(/^Bearer\s+(.+)$/);
  return match ? match[1] : null;
}

/**
 * Authentication middleware
 */
export async function authMiddleware(
  context: Context,
  next: () => Promise<Response>
): Promise<Response> {
  try {
    const token = extractTokenFromHeader(context.request);
    
    if (!token) {
      throw new ApiError('Authentication required', 'MISSING_TOKEN', 401);
    }

    const payload = await verifyAccessToken(token, context.env);
    
    // Add user info to context
    context.user = {
      id: payload.sub,
      email: payload.email,
      username: payload.username,
      role: payload.role,
      permissions: payload.permissions,
      tokenId: payload.jti
    };

    return next();
  } catch (error) {
    if (error instanceof ApiError) {
      throw error;
    }
    
    throw new ApiError('Authentication failed', 'AUTH_ERROR', 401);
  }
}

/**
 * Optional authentication middleware (doesn't throw on missing token)
 */
export async function optionalAuthMiddleware(
  context: Context,
  next: () => Promise<Response>
): Promise<Response> {
  try {
    const token = extractTokenFromHeader(context.request);
    
    if (token) {
      const payload = await verifyAccessToken(token, context.env);
      
      context.user = {
        id: payload.sub,
        email: payload.email,
        username: payload.username,
        role: payload.role,
        permissions: payload.permissions,
        tokenId: payload.jti
      };
    }
  } catch (error) {
    // Ignore authentication errors for optional auth
    console.warn('Optional auth failed:', error);
  }

  return next();
}

/**
 * Role-based authorization middleware
 */
export function requireRole(role: 'user' | 'moderator' | 'admin') {
  return async (context: Context, next: () => Promise<Response>): Promise<Response> => {
    if (!context.user) {
      throw new ApiError('Authentication required', 'MISSING_TOKEN', 401);
    }

    const roleHierarchy = { user: 0, moderator: 1, admin: 2 };
    const userRoleLevel = roleHierarchy[context.user.role];
    const requiredRoleLevel = roleHierarchy[role];

    if (userRoleLevel < requiredRoleLevel) {
      throw new ApiError('Insufficient permissions', 'INSUFFICIENT_PERMISSIONS', 403);
    }

    return next();
  };
}

/**
 * Permission-based authorization middleware
 */
export function requirePermission(permission: string) {
  return async (context: Context, next: () => Promise<Response>): Promise<Response> => {
    if (!context.user) {
      throw new ApiError('Authentication required', 'MISSING_TOKEN', 401);
    }

    if (!context.user.permissions.includes(permission)) {
      throw new ApiError('Insufficient permissions', 'INSUFFICIENT_PERMISSIONS', 403);
    }

    return next();
  };
}

/**
 * Require multiple permissions (all must be present)
 */
export function requirePermissions(permissions: string[]) {
  return async (context: Context, next: () => Promise<Response>): Promise<Response> => {
    if (!context.user) {
      throw new ApiError('Authentication required', 'MISSING_TOKEN', 401);
    }

    const hasAllPermissions = permissions.every(permission =>
      context.user!.permissions.includes(permission)
    );

    if (!hasAllPermissions) {
      throw new ApiError('Insufficient permissions', 'INSUFFICIENT_PERMISSIONS', 403);
    }

    return next();
  };
}

/**
 * Require any of the specified permissions
 */
export function requireAnyPermission(permissions: string[]) {
  return async (context: Context, next: () => Promise<Response>): Promise<Response> => {
    if (!context.user) {
      throw new ApiError('Authentication required', 'MISSING_TOKEN', 401);
    }

    const hasAnyPermission = permissions.some(permission =>
      context.user!.permissions.includes(permission)
    );

    if (!hasAnyPermission) {
      throw new ApiError('Insufficient permissions', 'INSUFFICIENT_PERMISSIONS', 403);
    }

    return next();
  };
}

// ==================== REFRESH TOKEN HANDLING ====================

/**
 * Refresh access token using refresh token
 */
export async function refreshAccessToken(
  refreshToken: string,
  env: any
): Promise<{
  accessToken: string;
  expiresIn: number;
}> {
  const payload = await verifyRefreshToken(refreshToken, env);

  // TODO: Fetch user data from database to ensure user still exists and get current role/permissions
  // For now, we'll create a minimal user object
  const user = {
    id: payload.sub,
    email: '', // Would be fetched from DB
    username: '', // Would be fetched from DB
    role: 'user' as const, // Would be fetched from DB
    permissions: [] as string[] // Would be fetched from DB
  };

  const accessToken = await generateAccessToken(user, env);

  return {
    accessToken,
    expiresIn: ACCESS_TOKEN_EXPIRY
  };
}