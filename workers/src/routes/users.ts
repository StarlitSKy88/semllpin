import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { AuthenticatedRequest } from '../middleware/auth';
import { createDatabaseClient } from '../utils/database';
import { z } from 'zod';

// Validation schemas
const updateProfileSchema = z.object({
  username: z.string().min(3).max(50).optional(),
  full_name: z.string().min(1).max(100).optional(),
  bio: z.string().max(500).optional(),
  location: z.string().max(100).optional(),
  website: z.string().url().optional().or(z.literal('')),
  avatar_url: z.string().url().optional().or(z.literal(''))
});

const updatePrivacySchema = z.object({
  profile_visibility: z.enum(['public', 'friends', 'private']).optional(),
  location_sharing: z.boolean().optional(),
  annotation_visibility: z.enum(['public', 'friends', 'private']).optional()
});

// Get current user profile
export const getCurrentUser: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const db = createDatabaseClient(env);

    // Get user profile with counts
    const userProfileQuery = `
      SELECT 
        u.*,
        w.id as wallet_id, w.balance, w.currency,
        (SELECT COUNT(*) FROM annotations WHERE user_id = u.id) as annotation_count,
        (SELECT COUNT(*) FROM user_follows WHERE following_id = u.id) as followers_count,
        (SELECT COUNT(*) FROM user_follows WHERE follower_id = u.id) as following_count
      FROM users u
      LEFT JOIN wallets w ON u.id = w.user_id
      WHERE u.id = $1
    `;

    const result = await db.query(userProfileQuery, [user.id]);
    
    if (result.rows.length === 0) {
      return new Response(JSON.stringify({
        error: 'User not found',
        message: 'User profile not found'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const userProfile = result.rows[0];
    
    // Format response to match expected structure
    const responseData = {
      ...userProfile,
      wallets: userProfile.wallet_id ? [{
        id: userProfile.wallet_id,
        balance: userProfile.balance,
        currency: userProfile.currency
      }] : [],
      _count_annotations: [{ count: userProfile.annotation_count }],
      _count_followers: [{ count: userProfile.followers_count }],
      _count_following: [{ count: userProfile.following_count }]
    };

    // Remove wallet fields from main object
    delete responseData.wallet_id;
    delete responseData.balance;
    delete responseData.currency;
    delete responseData.annotation_count;
    delete responseData.followers_count;
    delete responseData.following_count;

    return new Response(JSON.stringify({
      success: true,
      data: responseData
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get current user error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch user profile'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get user profile by ID
export const getUserById: RouteHandler = async (request, env, ctx, params) => {
  try {
    const userId = params?.id;
    if (!userId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'User ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const currentUser = (request as AuthenticatedRequest).user;
    const db = createDatabaseClient(env);

    // Get user profile with counts
    const userProfileQuery = `
      SELECT 
        u.id, u.username, u.full_name, u.avatar_url, u.bio, u.location, 
        u.website, u.is_verified, u.privacy_settings, u.created_at,
        (SELECT COUNT(*) FROM annotations WHERE user_id = u.id) as annotation_count,
        (SELECT COUNT(*) FROM user_follows WHERE following_id = u.id) as followers_count,
        (SELECT COUNT(*) FROM user_follows WHERE follower_id = u.id) as following_count
      FROM users u
      WHERE u.id = $1
    `;

    const result = await db.query(userProfileQuery, [userId]);
    
    if (result.rows.length === 0) {
      return new Response(JSON.stringify({
        error: 'User not found',
        message: 'The requested user does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const userProfile = result.rows[0];
    
    // Apply privacy settings
    const privacySettings = userProfile.privacy_settings || {};
    const isOwnProfile = currentUser?.id === userId;
    const isPublic = privacySettings.profile_visibility === 'public';

    if (!isOwnProfile && !isPublic) {
      // Check if users are friends (following each other)
      if (privacySettings.profile_visibility === 'friends' && currentUser) {
        const friendshipQuery = `
          SELECT COUNT(*) as mutual_follows
          FROM (
            SELECT 1 FROM user_follows WHERE follower_id = $1 AND following_id = $2
            UNION ALL
            SELECT 1 FROM user_follows WHERE follower_id = $2 AND following_id = $1
          ) as follows
        `;
        
        const friendshipResult = await db.query(friendshipQuery, [currentUser.id, userId]);
        const mutualFollows = parseInt(friendshipResult.rows[0].mutual_follows);

        if (mutualFollows < 2) {
          return new Response(JSON.stringify({
            error: 'Private Profile',
            message: 'This profile is private'
          }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      } else {
        return new Response(JSON.stringify({
          error: 'Private Profile',
          message: 'This profile is private'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // Remove sensitive information for non-own profiles
    if (!isOwnProfile) {
      delete userProfile.privacy_settings;
    }

    // Check if current user follows this user
    let isFollowing = false;
    if (currentUser && currentUser.id !== userId) {
      const followQuery = `
        SELECT id FROM user_follows 
        WHERE follower_id = $1 AND following_id = $2
      `;
      const followResult = await db.query(followQuery, [currentUser.id, userId]);
      isFollowing = followResult.rows.length > 0;
    }

    // Format response
    const responseData = {
      ...userProfile,
      _count_annotations: [{ count: userProfile.annotation_count }],
      _count_followers: [{ count: userProfile.followers_count }],
      _count_following: [{ count: userProfile.following_count }],
      is_following: isFollowing
    };

    // Remove count fields from main object
    delete responseData.annotation_count;
    delete responseData.followers_count;
    delete responseData.following_count;

    return new Response(JSON.stringify({
      success: true,
      data: responseData
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get user by ID error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch user profile'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Update user profile
export const updateProfile: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const updateData = updateProfileSchema.parse(body);

    const db = createDatabaseClient(env);

    // Check if username is being updated and if it's available
    if (updateData.username) {
      const usernameCheckQuery = `
        SELECT id FROM users 
        WHERE username = $1 AND id != $2
      `;
      const usernameResult = await db.query(usernameCheckQuery, [updateData.username, user.id]);
      
      if (usernameResult.rows.length > 0) {
        return new Response(JSON.stringify({
          error: 'Username already exists',
          message: 'Please choose a different username'
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // Build update query dynamically
    const updateFields = [];
    const updateValues = [];
    let paramIndex = 1;

    for (const [key, value] of Object.entries(updateData)) {
      updateFields.push(`${key} = $${paramIndex}`);
      updateValues.push(value);
      paramIndex++;
    }

    updateFields.push(`updated_at = $${paramIndex}`);
    updateValues.push(new Date().toISOString());
    paramIndex++;

    updateValues.push(user.id); // for WHERE clause

    const updateQuery = `
      UPDATE users 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramIndex}
      RETURNING *
    `;

    const result = await db.query(updateQuery, updateValues);
    
    if (result.rows.length === 0) {
      return new Response(JSON.stringify({
        error: 'Failed to update profile',
        message: 'User not found'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      success: true,
      data: result.rows[0],
      message: 'Profile updated successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Update profile error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update profile'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Update privacy settings
export const updatePrivacySettings: RouteHandler = async (request, env) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const privacyData = updatePrivacySchema.parse(body);

    const db = createDatabaseClient(env);

    // Get current privacy settings
    const currentUserQuery = `
      SELECT privacy_settings FROM users WHERE id = $1
    `;
    const currentResult = await db.query(currentUserQuery, [user.id]);
    
    if (currentResult.rows.length === 0) {
      return new Response(JSON.stringify({
        error: 'User not found',
        message: 'User not found'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const currentPrivacySettings = currentResult.rows[0].privacy_settings || {};
    const updatedPrivacySettings = {
      ...currentPrivacySettings,
      ...privacyData
    };

    const updateQuery = `
      UPDATE users 
      SET privacy_settings = $1, updated_at = $2
      WHERE id = $3
      RETURNING privacy_settings
    `;

    const result = await db.query(updateQuery, [
      JSON.stringify(updatedPrivacySettings),
      new Date().toISOString(),
      user.id
    ]);

    if (result.rows.length === 0) {
      return new Response(JSON.stringify({
        error: 'Failed to update privacy settings',
        message: 'Update failed'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      success: true,
      data: result.rows[0].privacy_settings,
      message: 'Privacy settings updated successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Update privacy settings error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update privacy settings'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Follow/Unfollow user
export const toggleFollow: RouteHandler = async (request, env, ctx, params) => {
  try {
    const user = (request as AuthenticatedRequest).user;
    if (!user) {
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const targetUserId = params?.id;
    if (!targetUserId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'User ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (user.id === targetUserId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Cannot follow yourself'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const db = createDatabaseClient(env);

    // Check if target user exists
    const targetUserQuery = `SELECT id FROM users WHERE id = $1`;
    const targetUserResult = await db.query(targetUserQuery, [targetUserId]);
    
    if (targetUserResult.rows.length === 0) {
      return new Response(JSON.stringify({
        error: 'User not found',
        message: 'The target user does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if already following
    const existingFollowQuery = `
      SELECT id FROM user_follows 
      WHERE follower_id = $1 AND following_id = $2
    `;
    const existingFollowResult = await db.query(existingFollowQuery, [user.id, targetUserId]);

    let isFollowing = false;
    let message = '';

    if (existingFollowResult.rows.length > 0) {
      // Unfollow
      const unfollowQuery = `
        DELETE FROM user_follows 
        WHERE follower_id = $1 AND following_id = $2
      `;
      await db.query(unfollowQuery, [user.id, targetUserId]);

      isFollowing = false;
      message = 'User unfollowed successfully';
    } else {
      // Follow
      const followQuery = `
        INSERT INTO user_follows (follower_id, following_id, created_at)
        VALUES ($1, $2, $3)
      `;
      await db.query(followQuery, [user.id, targetUserId, new Date().toISOString()]);

      isFollowing = true;
      message = 'User followed successfully';
    }

    return new Response(JSON.stringify({
      success: true,
      data: {
        is_following: isFollowing
      },
      message
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Toggle follow error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update follow status'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get user's followers
export const getFollowers: RouteHandler = async (request, env, ctx, params) => {
  try {
    const userId = params?.id;
    if (!userId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'User ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
    const offset = (page - 1) * limit;

    const db = createDatabaseClient(env);

    const followersQuery = `
      SELECT 
        u.id, u.username, u.full_name, u.avatar_url, u.is_verified,
        uf.created_at as followed_at
      FROM user_follows uf
      JOIN users u ON uf.follower_id = u.id
      WHERE uf.following_id = $1
      ORDER BY uf.created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const result = await db.query(followersQuery, [userId, limit, offset]);
    const followers = result.rows;

    return new Response(JSON.stringify({
      success: true,
      data: followers,
      pagination: {
        page,
        limit,
        has_more: followers.length === limit
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get followers error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch followers'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get user's following
export const getFollowing: RouteHandler = async (request, env, ctx, params) => {
  try {
    const userId = params?.id;
    if (!userId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'User ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
    const offset = (page - 1) * limit;

    const db = createDatabaseClient(env);

    const followingQuery = `
      SELECT 
        u.id, u.username, u.full_name, u.avatar_url, u.is_verified,
        uf.created_at as followed_at
      FROM user_follows uf
      JOIN users u ON uf.following_id = u.id
      WHERE uf.follower_id = $1
      ORDER BY uf.created_at DESC
      LIMIT $2 OFFSET $3
    `;

    const result = await db.query(followingQuery, [userId, limit, offset]);
    const following = result.rows;

    return new Response(JSON.stringify({
      success: true,
      data: following,
      pagination: {
        page,
        limit,
        has_more: following.length === limit
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get following error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch following'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};