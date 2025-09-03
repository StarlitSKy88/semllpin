import { createNeonDatabase } from '../utils/neon-database';
import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { z } from 'zod';
import bcrypt from 'bcryptjs';
import { sign, verify } from '@tsndr/cloudflare-worker-jwt';

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
    
    // Check if token is expired
    const currentTime = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < currentTime) {
      console.log('Token expired:', { exp: payload.exp, current: currentTime });
      return null;
    }
    
    return payload;
  } catch (error) {
    console.error('Token verification error:', error);
    return null;
  }
}

// Generate UUID
function generateUUID(): string {
  // Use Web Crypto API available in Cloudflare Workers
  return globalThis.crypto.randomUUID();
}

// Sign up handler
export const signUp: RouteHandler = async (request, env) => {
  console.log('🚀 SignUp handler called');
  try {
    console.log('📝 Parsing request body...');
    const body = await request.json();
    console.log('📋 Request body:', { ...body, password: '[HIDDEN]' });
    const { email, password, username, full_name } = signUpSchema.parse(body);
    console.log('✅ Schema validation passed');
    console.log('🔍 Parsed data:', { email, username, full_name, password: '[HIDDEN]' });

    const db = createNeonDatabase(env);

    // Check if email already exists
    const existingEmail = await db.getUserByEmail(email);
    if (existingEmail) {
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
    const userResult = await db.createUser({
      id: userId,
      email,
      username,
      full_name: full_name || username,
      password_hash: passwordHash
    });

    if (userResult.error) {
      console.error('User creation error:', userResult.error);
      console.error('User data:', { userId, email, username, full_name });
      return new Response(JSON.stringify({
        error: 'Failed to create user',
        message: 'Database error occurred',
        debug: userResult.error
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Generate JWT token
    const token = await generateToken(userId, email, env);

    // Get created user data (without password)
    const userData = await db.getUserById(userId);

    return new Response(JSON.stringify({
      success: true,
      data: {
        user: userData,
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
    console.log('Looking for user with email:', email);
    const user = await db.getUserByEmail(email);
    console.log('Found user:', user ? 'Yes' : 'No');
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
    console.log('Verifying password for user:', user.email);
    console.log('Password hash from DB:', user.password_hash);
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

    // Get user profile (without password)
    const userProfile = await db.getUserById(user.id);

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

    return new Response(JSON.stringify({
      success: true,
      data: {
        user: user
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