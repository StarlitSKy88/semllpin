import { RouteHandler } from '../utils/router';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { sign, verify } from '@tsndr/cloudflare-worker-jwt';
import { createNeonDatabase } from '../utils/neon-database';
import { Env } from '../index';

// Validation schemas
const signUpSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  username: z.string().min(3).max(50),
  full_name: z.string().min(1).max(100).optional()
});

const signInSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1)
});

const resetPasswordSchema = z.object({
  email: z.string().email()
});

const updatePasswordSchema = z.object({
  password: z.string().min(6),
  new_password: z.string().min(6)
});

// Generate JWT token
async function generateToken(userId: string, email: string, env: Env): Promise<string> {
  const payload = {
    sub: userId,
    email: email,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
  };
  
  return await sign(payload, env.JWT_SECRET || 'fallback-secret');
}

// Verify JWT token
export async function verifyToken(token: string, env: Env): Promise<any> {
  try {
    const isValid = await verify(token, env.JWT_SECRET || 'fallback-secret');
    if (!isValid) return null;
    
    const payload = JSON.parse(atob(token.split('.')[1]));
    return payload;
  } catch (error) {
    return null;
  }
}

// Generate UUID
function generateUUID(): string {
  return globalThis.crypto.randomUUID();
}

// Sign up handler
export const signUp: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const { email, password, username, full_name } = signUpSchema.parse(body);

    const db = createNeonDatabase(env);

    // Check if email already exists
    const existingUser = await db.getUserByEmail(email);
    if (existingUser) {
      return new Response(JSON.stringify({
        error: 'Email already exists',
        message: 'Please use a different email address'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if username already exists
    const existingUsername = await db.getUserByUsername(username);
    if (existingUsername) {
      return new Response(JSON.stringify({
        error: 'Username already exists',
        message: 'Please choose a different username'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const userId = generateUUID();
    const newUser = await db.createUser({
      id: userId,
      email,
      username,
      full_name: full_name || username,
      password_hash: passwordHash
    });

    if (!newUser) {
      console.error('User creation failed');
      return new Response(JSON.stringify({
        error: 'Failed to create user',
        message: 'Database error occurred'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Generate JWT token
    const token = await generateToken(userId, email, env);

    return new Response(JSON.stringify({
      success: true,
      data: {
        user: newUser,
        token: token
      },
      message: 'Account created successfully'
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Sign up error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to create account'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Sign in handler
export const signIn: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const { email, password } = signInSchema.parse(body);

    const db = createNeonDatabase(env);

    // Get user by email
    const user = await db.getUserByEmail(email);

    if (!user) {
      return new Response(JSON.stringify({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    console.log('Password valid:', isValidPassword);
    if (!isValidPassword) {
      return new Response(JSON.stringify({
        error: 'Invalid credentials',
        message: 'Email or password is incorrect'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Generate JWT token
    const token = await generateToken(user.id, user.email, env);

    // Return user profile (without password)
    const { password_hash, ...userProfile } = user;

    return new Response(JSON.stringify({
      success: true,
      data: {
        user: userProfile,
        token: token
      },
      message: 'Signed in successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Sign in error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to sign in'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Sign out handler (JWT is stateless, so this is mainly for client-side cleanup)
export const signOut: RouteHandler = async (request, env) => {
  return new Response(JSON.stringify({
    success: true,
    message: 'Signed out successfully'
  }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
};

// Reset password handler
export const resetPassword: RouteHandler = async (request, env) => {
  try {
    const body = await request.json();
    const { email } = resetPasswordSchema.parse(body);

    const db = createNeonDatabase(env);

    // Check if user exists
    const user = await db.getUserByEmail(email);
    
    if (!user) {
      // Don't reveal if email exists or not for security
      return new Response(JSON.stringify({
        success: true,
        message: 'If the email exists, a password reset link has been sent'
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // TODO: Implement email sending logic here
    // For now, just return success message
    return new Response(JSON.stringify({
      success: true,
      message: 'Password reset email sent successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Reset password error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to process password reset'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Update password handler
export const updatePassword: RouteHandler = async (request, env) => {
  try {
    // Get user from JWT token
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyToken(token, env);
    
    if (!payload) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Invalid or expired token'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const { password, new_password } = updatePasswordSchema.parse(body);

    const db = createNeonDatabase(env);

    // Get current user with password hash
    const user = await db.getUserById(payload.sub);

    if (!user) {
      return new Response(JSON.stringify({
        error: 'User not found',
        message: 'User account no longer exists'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify current password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return new Response(JSON.stringify({
        error: 'Invalid password',
        message: 'Current password is incorrect'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Hash new password
    const saltRounds = 10;
    const newPasswordHash = await bcrypt.hash(new_password, saltRounds);

    // Update password
    const updateResult = await db.query(
      'UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3',
      [newPasswordHash, new Date().toISOString(), user.id]
    );

    if (!updateResult) {
      return new Response(JSON.stringify({
        error: 'Failed to update password',
        message: 'Database error occurred'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      success: true,
      message: 'Password updated successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Update password error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update password'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get current user handler
export const getCurrentUser: RouteHandler = async (request, env) => {
  try {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Missing or invalid authorization header'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const token = authHeader.replace('Bearer ', '');
    const payload = await verifyToken(token, env);
    
    if (!payload) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'Invalid or expired token'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const db = createNeonDatabase(env);
    const user = await db.getUserById(payload.sub);
    
    if (!user) {
      return new Response(JSON.stringify({
        error: 'User not found',
        message: 'User account no longer exists'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Remove password_hash from response
    const { password_hash, ...userProfile } = user;

    return new Response(JSON.stringify({
      success: true,
      data: {
        user: userProfile
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get current user error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to get user information'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};