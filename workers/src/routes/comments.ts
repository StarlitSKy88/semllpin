import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { AuthenticatedRequest } from '../middleware/auth';
import { createNeonDatabase } from '../utils/neon-database';
import { z } from 'zod';

// Validation schemas
const createCommentSchema = z.object({
  content: z.string().min(1).max(500),
  annotation_id: z.string().uuid()
});

const updateCommentSchema = z.object({
  content: z.string().min(1).max(500)
});

// Create comment
export const createComment: RouteHandler = async (request, env) => {
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
    const { content, annotation_id } = createCommentSchema.parse(body);

    const db = createNeonDatabase(env);

    // Check if annotation exists and is accessible
    const annotation = await db.getAnnotationById(annotation_id);

    if (!annotation) {
      return new Response(JSON.stringify({
        error: 'Annotation not found',
        message: 'The annotation does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if user can comment on this annotation
    const isOwner = annotation.user_id === user.id;
    const isPublic = annotation.visibility === 'public';
    
    if (!isOwner && !isPublic) {
      if (annotation.visibility === 'friends') {
        // Check if users are friends (following each other)
        const areFriends = await db.areUsersFriends(user.id, annotation.user_id);

        if (!areFriends) {
          return new Response(JSON.stringify({
            error: 'Access Denied',
            message: 'You cannot comment on this private annotation'
          }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      } else {
        return new Response(JSON.stringify({
          error: 'Access Denied',
          message: 'You cannot comment on this private annotation'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // Create comment
    const comment = await db.createComment({
      user_id: user.id,
      annotation_id,
      content
    });

    if (!comment) {
      return new Response(JSON.stringify({
        error: 'Failed to create comment',
        message: 'Database error occurred'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Get user information for the comment
    const userInfo = await db.getUserById(user.id);

    const commentWithUser = {
      ...comment,
      user: userInfo
    };

    // Update annotation comments count
    await db.incrementAnnotationCommentsCount(annotation_id);

    return new Response(JSON.stringify({
      success: true,
      data: commentWithUser,
      message: 'Comment created successfully'
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Create comment error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to create comment'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get comments for an annotation
export const getCommentsByAnnotation: RouteHandler = async (request, env, ctx, params) => {
  try {
    const annotationId = params?.annotation_id;
    if (!annotationId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Annotation ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
    const offset = (page - 1) * limit;

    const currentUser = (request as AuthenticatedRequest).user;
    const db = createNeonDatabase(env);

    // Check if annotation exists and is accessible
    const annotation = await db.getAnnotationById(annotationId);

    if (!annotation) {
      return new Response(JSON.stringify({
        error: 'Annotation not found',
        message: 'The annotation does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if user can view this annotation's comments
    const isOwner = currentUser?.id === annotation.user_id;
    const isPublic = annotation.visibility === 'public';
    
    if (!isOwner && !isPublic) {
      if (annotation.visibility === 'friends' && currentUser) {
        // Check if users are friends (following each other)
        const areFriends = await db.areUsersFriends(currentUser.id, annotation.user_id);

        if (!areFriends) {
          return new Response(JSON.stringify({
            error: 'Access Denied',
            message: 'You cannot view comments on this private annotation'
          }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      } else {
        return new Response(JSON.stringify({
          error: 'Access Denied',
          message: 'You cannot view comments on this private annotation'
        }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // Get comments with pagination
    const comments = await db.getCommentsByAnnotation(annotationId, limit, offset);

    return new Response(JSON.stringify({
      success: true,
      data: comments,
      pagination: {
        page,
        limit,
        has_more: comments.length === limit
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get comments error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch comments'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Update comment
export const updateComment: RouteHandler = async (request, env, ctx, params) => {
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

    const commentId = params?.id;
    if (!commentId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Comment ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const { content } = updateCommentSchema.parse(body);

    const db = createNeonDatabase(env);

    // Check if comment exists and user owns it
    const commentResult = await db.query(
      `SELECT * FROM comments WHERE id = '${commentId}' AND user_id = '${user.id}'`
    );

    if (!commentResult.data || commentResult.data.length === 0) {
      return new Response(JSON.stringify({
        error: 'Comment not found',
        message: 'Comment not found or you do not have permission to update it'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Update the comment
    const updateResult = await db.query(
      `UPDATE comments SET content = '${content}', updated_at = NOW() WHERE id = '${commentId}' RETURNING *`
    );

    const updatedComment = updateResult.data?.[0];

    // Get user information for the comment
    const userInfo = await db.getUserById(user.id);

    const commentWithUser = {
      ...updatedComment,
      user: userInfo
    };

    return new Response(JSON.stringify({
      success: true,
      data: commentWithUser,
      message: 'Comment updated successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Update comment error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update comment'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Delete comment
export const deleteComment: RouteHandler = async (request, env, ctx, params) => {
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

    const commentId = params?.id;
    if (!commentId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Comment ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const db = createNeonDatabase(env);

    // Check if comment exists and user owns it
    const existingCommentResult = await db.query(
      `SELECT user_id, annotation_id FROM comments WHERE id = '${commentId}'`
    );

    if (!existingCommentResult.data || existingCommentResult.data.length === 0) {
      return new Response(JSON.stringify({
        error: 'Comment not found',
        message: 'The requested comment does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const existingComment = existingCommentResult.data[0];

    if (existingComment.user_id !== user.id && user.role !== 'admin') {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'You can only delete your own comments'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Delete comment
    const deleteResult = await db.query(
      `DELETE FROM comments WHERE id = '${commentId}'`
    );

    if (!deleteResult.data) {
      return new Response(JSON.stringify({
        error: 'Failed to delete comment',
        message: 'Database error occurred'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Update annotation comments count
    await db.query(
      `UPDATE annotations SET comments_count = comments_count - 1 WHERE id = '${existingComment.annotation_id}'`
    );

    return new Response(JSON.stringify({
      success: true,
      message: 'Comment deleted successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Delete comment error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to delete comment'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};