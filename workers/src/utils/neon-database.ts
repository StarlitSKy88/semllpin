import { neon } from '@neondatabase/serverless';
import bcrypt from 'bcryptjs';
import { z } from 'zod';

export interface DatabaseResult<T = any> {
  data: T[] | null;
  error: string | null;
}

// Validation schemas
const userDataSchema = z.object({
  id: z.string().uuid('Invalid user ID format'),
  email: z.string().email('Invalid email format'),
  username: z.string().min(3, 'Username must be at least 3 characters').max(50, 'Username must be at most 50 characters').regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'),
  full_name: z.string().min(1, 'Full name cannot be empty').max(100, 'Full name must be at most 100 characters').optional(),
  password_hash: z.string().min(1, 'Password hash cannot be empty')
});

const annotationDataSchema = z.object({
  user_id: z.string().uuid('Invalid user ID format'),
  content: z.string().min(1, 'Content cannot be empty').max(1000, 'Content must be at most 1000 characters'),
  latitude: z.number().min(-90, 'Latitude must be between -90 and 90').max(90, 'Latitude must be between -90 and 90'),
  longitude: z.number().min(-180, 'Longitude must be between -180 and 180').max(180, 'Longitude must be between -180 and 180'),
  smell_intensity: z.number().min(1, 'Smell intensity must be between 1 and 10').max(10, 'Smell intensity must be between 1 and 10').optional(),
  smell_category: z.string().max(50, 'Smell category must be at most 50 characters').optional(),
  media_urls: z.array(z.string().url('Invalid URL format')).optional(),
  tags: z.array(z.string().max(30, 'Tag must be at most 30 characters')).optional(),
  visibility: z.enum(['public', 'friends', 'private']).optional()
});

const transactionDataSchema = z.object({
  user_id: z.string().uuid('Invalid user ID format'),
  type: z.enum(['payment', 'reward', 'refund', 'withdrawal'], { errorMap: () => ({ message: 'Invalid transaction type' }) }),
  amount: z.number().positive('Amount must be positive').max(10000, 'Amount cannot exceed 10000'),
  currency: z.string().length(3, 'Currency must be 3 characters').optional(),
  payment_intent_id: z.string().optional(),
  payment_method_id: z.string().optional(),
  description: z.string().max(500, 'Description must be at most 500 characters').optional(),
  metadata: z.any().optional()
});

const commentDataSchema = z.object({
  user_id: z.string().uuid('Invalid user ID format'),
  annotation_id: z.string().uuid('Invalid annotation ID format'),
  content: z.string().min(1, 'Content cannot be empty').max(500, 'Content must be at most 500 characters')
});

export class NeonDatabase {
  private _sql: any;

  constructor(databaseUrl?: string) {
    const dbUrl = databaseUrl || process.env.DATABASE_URL;
    if (!dbUrl) {
      throw new Error('DATABASE_URL environment variable is required');
    }
    this._sql = neon(dbUrl);
  }

  // Getter for sql template literal usage
  get sql() {
    return this._sql;
  }

  async query(text: string, params?: any[]): Promise<{ rows: any[]; rowCount: number }> {
    try {
      // Use the serverless driver's safe parameterized API directly
      let result;
      if (params && params.length > 0) {
        result = await this._sql.query(text, params);
      } else {
        result = await this._sql.query(text);
      }
      
      // Return in the expected format for compatibility with existing code
      return {
        rows: Array.isArray(result) ? result : [],
        rowCount: Array.isArray(result) ? result.length : 0
      };
    } catch (error) {
      console.error('Database query error:', error);
      throw error; // Re-throw to maintain existing error handling patterns
    }
  }

  // User operations
  async createUser(userData: {
    id: string;
    email: string;
    username: string;
    full_name?: string;
    password_hash: string;
  }): Promise<DatabaseResult> {
    try {
      // Validate input data
      const validatedData = userDataSchema.parse(userData);
      
      const result = await this._sql`
        INSERT INTO users (id, email, username, full_name, password_hash, role, status, email_verified, is_verified, created_at, updated_at)
        VALUES (${validatedData.id}, ${validatedData.email}, ${validatedData.username}, ${validatedData.full_name || validatedData.username}, ${validatedData.password_hash}, 'user', 'active', false, false, NOW(), NOW())
        RETURNING id, email, username, full_name, created_at
      `;
      return { data: result, error: null };
    } catch (error) {
      console.error('createUser error:', error);
      if (error instanceof z.ZodError) {
        return { data: null, error: `Validation error: ${error.errors.map(e => e.message).join(', ')}` };
      }
      return { data: null, error: error instanceof Error ? error.message : String(error) };
    }
  }

  async getUserByEmail(email: string) {
    try {
      // Validate email format
      const validEmail = z.string().email('Invalid email format').parse(email);
      
      const result = await this._sql`SELECT id, email, username, password_hash, created_at FROM users WHERE email = ${validEmail}`;
      return result[0] || null;
    } catch (error) {
      console.error('getUserByEmail error:', error);
      if (error instanceof z.ZodError) {
        console.error('Email validation failed:', error.errors);
      }
      return null;
    }
  }

  async getUserByUsername(username: string) {
    try {
      // Validate username format
      const validUsername = z.string().min(3).max(50).regex(/^[a-zA-Z0-9_]+$/, 'Invalid username format').parse(username);
      
      const result = await this._sql`SELECT id, email, username, password_hash, created_at FROM users WHERE username = ${validUsername}`;
      return result[0] || null;
    } catch (error) {
      console.error('getUserByUsername error:', error);
      if (error instanceof z.ZodError) {
        console.error('Username validation failed:', error.errors);
      }
      return null;
    }
  }

  async getUserById(id: string) {
    try {
      // Validate UUID format
      const validId = z.string().uuid('Invalid user ID format').parse(id);
      
      const result = await this._sql`SELECT id, email, username, created_at FROM users WHERE id = ${validId}`;
      return result[0] || null;
    } catch (error) {
      console.error('getUserById error:', error);
      if (error instanceof z.ZodError) {
        console.error('User ID validation failed:', error.errors);
      }
      return null;
    }
  }

  // Annotation operations
  async getAnnotations(limit = 50, offset = 0) {
    try {
      const result = await this._sql`
        SELECT a.*, u.username 
        FROM annotations a 
        JOIN users u ON a.user_id = u.id 
        ORDER BY a.created_at DESC 
        LIMIT ${limit} OFFSET ${offset}
      `;
      return result || [];
    } catch (error) {
      console.error('getAnnotations error:', error);
      return [];
    }
  }

  async createAnnotation(data: {
    user_id: string;
    content: string;
    latitude: number;
    longitude: number;
    smell_intensity?: number;
    smell_category?: string;
    media_urls?: string[];
    tags?: string[];
    visibility?: string;
  }) {
    try {
      console.log('Creating annotation with data:', data);
      
      // Validate input data
      const validatedData = annotationDataSchema.parse(data);
      
      // Prepare location object
      const location = {
        latitude: validatedData.latitude,
        longitude: validatedData.longitude
      };
      
      // Prepare arrays
      const mediaUrls = validatedData.media_urls || [];
      const tags = validatedData.tags || [];
      const visibility = validatedData.visibility || 'public';
      
      const result = await this._sql`
        INSERT INTO annotations (
          user_id, 
          content, 
          location, 
          smell_intensity, 
          smell_category, 
          media_urls, 
          tags, 
          visibility,
          status,
          created_at, 
          updated_at
        )
        VALUES (
          ${validatedData.user_id}, 
          ${validatedData.content}, 
          ${JSON.stringify(location)}, 
          ${validatedData.smell_intensity || null}, 
          ${validatedData.smell_category || null}, 
          ${JSON.stringify(mediaUrls)}, 
          ${JSON.stringify(tags)},
          ${visibility},
          'active',
          NOW(),
          NOW()
        )
        RETURNING *
      `;
      
      console.log('SQL result:', result);
      console.log('Result length:', result.length);
      console.log('First result:', result[0]);
      
      return result[0] || null;
    } catch (error) {
      console.error('createAnnotation error:', error);
      if (error instanceof z.ZodError) {
        console.error('Validation error:', error.errors);
        return null;
      }
      console.error('Error details:', error instanceof Error ? error.message : String(error), error instanceof Error ? error.stack : '');
      return null;
    }
  }

  async getAnnotationById(id: string) {
    try {
      console.log('Getting annotation by ID:', id);
      
      // Validate annotation ID format
      const validId = z.string().uuid('Invalid annotation ID format').parse(id);
      
      const result = await this._sql`
        SELECT a.*, u.username, u.full_name, u.avatar_url, u.is_verified
        FROM annotations a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.id = ${validId}
      `;
      
      console.log('getAnnotationById SQL result:', result);
      console.log('Result length:', result.length);
      
      return result[0] || null;
    } catch (error) {
      console.error('getAnnotationById error:', error);
      if (error instanceof z.ZodError) {
        console.error('Annotation ID validation failed:', error.errors);
      }
      console.error('Error details:', error instanceof Error ? error.message : String(error), error instanceof Error ? error.stack : '');
      return null;
    }
  }

  // LBS operations
  async getNearbyRewards(latitude: number, longitude: number, radiusKm = 5) {
    try {
      // Validate input coordinates
      const validLatitude = z.number().min(-90, 'Latitude must be between -90 and 90').max(90, 'Latitude must be between -90 and 90').parse(latitude);
      const validLongitude = z.number().min(-180, 'Longitude must be between -180 and 180').max(180, 'Longitude must be between -180 and 180').parse(longitude);
      const validRadius = z.number().positive('Radius must be positive').max(100, 'Radius cannot exceed 100km').parse(radiusKm);
      
      // Convert radius from km to degrees (approximate)
      const radiusDegrees = validRadius / 111.0; // 1 degree ≈ 111 km
      
      const result = await this.sql`
        SELECT lr.*, 
               u.username,
               a.content as annotation_content,
               a.smell_category,
               (
                 6371 * acos(
                   cos(radians(${validLatitude})) * cos(radians((a.location->>'latitude')::float)) *
                   cos(radians((a.location->>'longitude')::float) - radians(${validLongitude})) +
                   sin(radians(${validLatitude})) * sin(radians((a.location->>'latitude')::float))
                 )
               ) as distance
         FROM lbs_rewards lr
         JOIN users u ON lr.user_id = u.id
         JOIN annotations a ON lr.annotation_id = a.id
         WHERE (a.location->>'latitude')::float BETWEEN ${validLatitude - radiusDegrees} AND ${validLatitude + radiusDegrees}
           AND (a.location->>'longitude')::float BETWEEN ${validLongitude - radiusDegrees} AND ${validLongitude + radiusDegrees}
           AND lr.created_at >= NOW() - INTERVAL '7 days'
         HAVING (
           6371 * acos(
             cos(radians(${validLatitude})) * cos(radians((a.location->>'latitude')::float)) *
             cos(radians((a.location->>'longitude')::float) - radians(${validLongitude})) +
             sin(radians(${validLatitude})) * sin(radians((a.location->>'latitude')::float))
           )
         ) <= ${validRadius}
         ORDER BY distance
         LIMIT 20
      `;
      return result || [];
    } catch (error) {
      console.error('getNearbyRewards error:', error);
      if (error instanceof z.ZodError) {
        console.error('LBS coordinates validation failed:', error.errors);
      }
      return [];
    }
  }

  // Payment operations
  async createTransaction(data: {
    user_id: string;
    type: string;
    amount: number;
    currency?: string;
    payment_intent_id?: string;
    payment_method_id?: string;
    description?: string;
    metadata?: any;
  }) {
    try {
      // Validate input data
      const validatedData = transactionDataSchema.parse(data);
      
      const result = await this._sql`
        INSERT INTO transactions (
          user_id, type, amount, currency, payment_intent_id, 
          payment_method_id, description, metadata, status, created_at, updated_at
        )
        VALUES (
          ${validatedData.user_id}, ${validatedData.type}, ${validatedData.amount}, ${validatedData.currency || 'usd'},
          ${validatedData.payment_intent_id || null}, ${validatedData.payment_method_id || null},
          ${validatedData.description || null}, ${JSON.stringify(validatedData.metadata || {})},
          'pending', NOW(), NOW()
        )
        RETURNING *
      `;
      return result[0] || null;
    } catch (error) {
      console.error('createTransaction error:', error);
      if (error instanceof z.ZodError) {
        console.error('Transaction validation failed:', error.errors);
      }
      return null;
    }
  }

  async updateTransactionStatus(id: string, status: string, completedAt?: Date) {
    try {
      const result = await this._sql`
        UPDATE transactions 
        SET status = ${status}, 
            completed_at = ${completedAt ? completedAt.toISOString() : null},
            updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;
      return result[0] || null;
    } catch (error) {
      console.error('updateTransactionStatus error:', error);
      return null;
    }
  }

  async getTransactionById(id: string) {
    try {
      const result = await this._sql`
        SELECT t.*, u.username, u.email
        FROM transactions t
        JOIN users u ON t.user_id = u.id
        WHERE t.id = ${id}
      `;
      return result[0] || null;
    } catch (error) {
      console.error('getTransactionById error:', error);
      return null;
    }
  }

  async getTransactionByPaymentIntent(paymentIntentId: string) {
    try {
      const result = await this._sql`
        SELECT * FROM transactions WHERE payment_intent_id = ${paymentIntentId}
      `;
      return result[0] || null;
    } catch (error) {
      console.error('getTransactionByPaymentIntent error:', error);
      return null;
    }
  }

  async getUserTransactions(userId: string, limit = 20, offset = 0) {
    try {
      const result = await this._sql`
        SELECT * FROM transactions 
        WHERE user_id = ${userId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      return result || [];
    } catch (error) {
      console.error('getUserTransactions error:', error);
      return [];
    }
  }

  async getOrCreateWallet(userId: string, currency = 'usd') {
    try {
      // Try to get existing wallet
      let result = await this._sql`
        SELECT * FROM wallets WHERE user_id = ${userId} AND currency = ${currency}
      `;
      
      if (result.length > 0) {
        return result[0];
      }
      
      // Create new wallet if doesn't exist
      result = await this._sql`
        INSERT INTO wallets (user_id, currency, balance, created_at, updated_at)
        VALUES (${userId}, ${currency}, 0, NOW(), NOW())
        RETURNING *
      `;
      return result[0] || null;
    } catch (error) {
      console.error('getOrCreateWallet error:', error);
      return null;
    }
  }

  async updateWalletBalance(userId: string, amount: number, currency = 'usd') {
    try {
      const result = await this._sql`
        UPDATE wallets 
        SET balance = balance + ${amount}, updated_at = NOW()
        WHERE user_id = ${userId} AND currency = ${currency}
        RETURNING *
      `;
      return result[0] || null;
    } catch (error) {
      console.error('updateWalletBalance error:', error);
      return null;
    }
  }

  // Initialize payment tables if they don't exist
  async initializePaymentTables() {
    try {
      // Drop existing tables to avoid column conflicts
      await this._sql`DROP TABLE IF EXISTS transactions CASCADE`;
      await this._sql`DROP TABLE IF EXISTS wallets CASCADE`;
      
      // Create transactions table
      await this._sql`
        CREATE TABLE transactions (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          type VARCHAR(50) NOT NULL,
          amount INTEGER NOT NULL,
          currency VARCHAR(3) NOT NULL DEFAULT 'usd',
          status VARCHAR(20) NOT NULL DEFAULT 'pending',
          payment_intent_id VARCHAR(255),
          payment_method_id VARCHAR(255),
          description TEXT,
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          completed_at TIMESTAMP WITH TIME ZONE,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `;
      
      // Create wallets table
      await this._sql`
        CREATE TABLE wallets (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          currency VARCHAR(3) NOT NULL DEFAULT 'usd',
          balance INTEGER NOT NULL DEFAULT 0,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          UNIQUE(user_id, currency)
        )
      `;
      
      // Create indexes
      await this._sql`CREATE INDEX idx_transactions_user_id ON transactions(user_id)`;
      await this._sql`CREATE INDEX idx_transactions_payment_intent_id ON transactions(payment_intent_id)`;
      await this._sql`CREATE INDEX idx_transactions_status ON transactions(status)`;
      await this._sql`CREATE INDEX idx_wallets_user_id ON wallets(user_id)`;
      
      console.log('Payment tables initialized successfully');
      return true;
    } catch (error) {
      console.error('initializePaymentTables error:', error);
      return false;
    }
  }

  // User relationship operations
  async areUsersFriends(userId1: string, userId2: string): Promise<boolean> {
    try {
      const result = await this._sql`
        SELECT COUNT(*) as count FROM user_follows 
        WHERE (follower_id = ${userId1} AND following_id = ${userId2}) 
        OR (follower_id = ${userId2} AND following_id = ${userId1})
      `;
      return parseInt(result[0].count) >= 2; // Both users follow each other
    } catch (error) {
      console.error('areUsersFriends error:', error);
      return false;
    }
  }

  // Comment operations
  async createComment(data: {
    user_id: string;
    annotation_id: string;
    content: string;
  }) {
    try {
      // Validate input data
      const validatedData = commentDataSchema.parse(data);
      
      const result = await this._sql`
        INSERT INTO comments (user_id, annotation_id, content, created_at, updated_at)
        VALUES (${validatedData.user_id}, ${validatedData.annotation_id}, ${validatedData.content}, NOW(), NOW())
        RETURNING *
      `;
      return result[0] || null;
    } catch (error) {
      console.error('createComment error:', error);
      if (error instanceof z.ZodError) {
        console.error('Comment validation failed:', error.errors);
      }
      return null;
    }
  }

  async incrementAnnotationCommentsCount(annotationId: string) {
    try {
      const result = await this._sql`
        UPDATE annotations 
        SET comments_count = comments_count + 1, updated_at = NOW()
        WHERE id = ${annotationId}
        RETURNING *
      `;
      return result[0] || null;
    } catch (error) {
      console.error('incrementAnnotationCommentsCount error:', error);
      return null;
    }
  }

  async getCommentsByAnnotation(annotationId: string, limit = 20, offset = 0) {
    try {
      const result = await this._sql`
        SELECT c.*, u.username, u.full_name, u.avatar_url, u.is_verified
        FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.annotation_id = ${annotationId}
        ORDER BY c.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
      return result || [];
    } catch (error) {
      console.error('getCommentsByAnnotation error:', error);
      return [];
    }
  }

  async close(): Promise<void> {
    // Neon serverless doesn't require explicit connection closing
  }
}

// Utility function to create database instance
export function createNeonDatabase(env: any): NeonDatabase {
  if (!env.DATABASE_URL) {
    throw new Error('DATABASE_URL environment variable is required');
  }
  return new NeonDatabase(env.DATABASE_URL);
}