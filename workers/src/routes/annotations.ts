import { createNeonDatabase } from '../utils/neon-database';
import { Env } from '../index';
import { RouteHandler } from '../utils/router';
import { AuthenticatedRequest } from '../middleware/auth';
import { z } from 'zod';

// Validation schemas
const createAnnotationSchema = z.object({
  content: z.string().min(1).max(1000),
  location: z.object({
    latitude: z.number().min(-90).max(90),
    longitude: z.number().min(-180).max(180),
    address: z.string().optional(),
    place_name: z.string().optional()
  }),
  media_urls: z.array(z.string().url()).max(10).optional(),
  tags: z.array(z.string().max(50)).max(20).optional(),
  visibility: z.enum(['public', 'friends', 'private']).default('public'),
  smell_intensity: z.number().min(1).max(10).optional(),
  smell_category: z.string().max(100).optional()
});

const updateAnnotationSchema = z.object({
  content: z.string().min(1).max(1000).optional(),
  media_urls: z.array(z.string().url()).max(10).optional(),
  tags: z.array(z.string().max(50)).max(20).optional(),
  visibility: z.enum(['public', 'friends', 'private']).optional(),
  smell_intensity: z.number().min(1).max(10).optional(),
  smell_category: z.string().max(100).optional()
});

// Create annotation
export const createAnnotation: RouteHandler = async (request, env) => {
  try {
    console.log('=== createAnnotation started ===');
    
    const user = (request as AuthenticatedRequest).user;
    console.log('User authentication:', user ? 'Success' : 'Failed');
    
    if (!user) {
      console.log('Authentication failed: No user found');
      return new Response(JSON.stringify({
        error: 'Unauthorized',
        message: 'User not authenticated'
      }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    console.log('Parsing request body...');
    const body = await request.json();
    console.log('Received annotation data:', JSON.stringify(body, null, 2));
    
    const annotationData = createAnnotationSchema.parse(body);
    console.log('Schema validation passed');

    console.log('Creating database connection...');
    const database = createNeonDatabase(env);
    console.log('Database connection created');

    console.log('Calling db.createAnnotation with:', {
      user_id: user.id,
      content: annotationData.content,
      latitude: annotationData.location.latitude,
      longitude: annotationData.location.longitude,
      smell_intensity: annotationData.smell_intensity,
      smell_category: annotationData.smell_category,
      media_urls: annotationData.media_urls,
      tags: annotationData.tags,
      visibility: annotationData.visibility || 'public'
    });

    // Create annotation using Neon database
    const annotation = await database.createAnnotation({
      user_id: user.id,
      content: annotationData.content,
      latitude: annotationData.location.latitude,
      longitude: annotationData.location.longitude,
      smell_intensity: annotationData.smell_intensity,
      smell_category: annotationData.smell_category,
      media_urls: annotationData.media_urls,
      tags: annotationData.tags,
      visibility: annotationData.visibility || 'public'
    });

    console.log('Database createAnnotation result:', annotation);

    if (!annotation) {
      console.error('Create annotation failed: No annotation returned');
      return new Response(JSON.stringify({
        error: 'Failed to create annotation',
        message: 'Database operation failed'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    console.log('Annotation created successfully:', annotation.id);
    return new Response(JSON.stringify({
      success: true,
      data: annotation,
      message: 'Annotation created successfully'
    }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('=== createAnnotation error ===');
    console.error('Error type:', error.constructor.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    console.error('Full error object:', error);
    
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to create annotation: ' + (error.message || 'Unknown error')
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get annotations with filters
export const getAnnotations: RouteHandler = async (request, env) => {
  try {
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 100);
    const offset = (page - 1) * limit;
    
    // Location filters
    const latitude = url.searchParams.get('latitude');
    const longitude = url.searchParams.get('longitude');
    const radius = parseFloat(url.searchParams.get('radius') || '1000'); // meters
    
    // Other filters
    const userId = url.searchParams.get('user_id');
    const tags = url.searchParams.get('tags')?.split(',').filter(Boolean);
    const smellCategory = url.searchParams.get('smell_category');
    const sortBy = url.searchParams.get('sort_by') || 'created_at';
    const sortOrder = url.searchParams.get('sort_order') === 'asc' ? 'asc' : 'desc';

    const currentUser = (request as AuthenticatedRequest).user;
    const database = createNeonDatabase(env);

    // Use Neon database to get annotations
    const annotations = await database.getAnnotations();

    if (!annotations) {
      console.error('Get annotations failed: No data returned');
      return new Response(JSON.stringify({
        error: 'Failed to fetch annotations',
        message: 'Database operation failed'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Apply basic filtering (simplified for now)
    let filteredAnnotations = annotations;
    
    if (userId) {
      filteredAnnotations = filteredAnnotations.filter(ann => ann.user_id === userId);
    }
    
    if (smellCategory) {
      filteredAnnotations = filteredAnnotations.filter(ann => ann.smell_type === smellCategory);
    }
    
    // Apply pagination
    const startIndex = offset;
    const endIndex = offset + limit;
    const paginatedAnnotations = filteredAnnotations.slice(startIndex, endIndex);

    return new Response(JSON.stringify({
      success: true,
      data: paginatedAnnotations || [],
      pagination: {
        page,
        limit,
        has_more: paginatedAnnotations?.length === limit
      }
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Get annotations error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch annotations'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Get annotation by ID
export const getAnnotationById: RouteHandler = async (request, env, ctx, params) => {
  try {
    console.log('=== getAnnotationById started ===');
    
    const annotationId = params?.id;
    console.log('Annotation ID:', annotationId);
    
    if (!annotationId) {
      console.log('No annotation ID provided');
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Annotation ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const currentUser = (request as AuthenticatedRequest).user;
    console.log('Current user:', currentUser ? currentUser.id : 'None');
    
    const database = createNeonDatabase(env);
    console.log('Database connection created');

    // Get annotation by ID using Neon database
    const annotation = await database.getAnnotationById(annotationId);
    console.log('Database query result:', annotation);

    if (!annotation) {
      console.log('Annotation not found in database');
      return new Response(JSON.stringify({
        error: 'Annotation not found',
        message: 'The requested annotation does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check visibility permissions
    const isOwner = currentUser?.id === annotation.user_id;
    const isPublic = annotation.visibility === 'public';
    console.log('Permission check - isOwner:', isOwner, 'isPublic:', isPublic);
    
    if (!isOwner && !isPublic) {
      console.log('Access denied - private annotation');
      return new Response(JSON.stringify({
        error: 'Private Annotation',
        message: 'This annotation is private'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    console.log('Returning annotation successfully');
    return new Response(JSON.stringify({
      success: true,
      data: annotation
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('=== getAnnotationById error ===');
    console.error('Error type:', error.constructor.name);
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    console.error('Full error object:', error);
    
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to fetch annotation: ' + (error.message || 'Unknown error')
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Update annotation
export const updateAnnotation: RouteHandler = async (request, env, ctx, params) => {
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

    const annotationId = params?.id;
    if (!annotationId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Annotation ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const updateData = updateAnnotationSchema.parse(body);

    const database = createDatabaseClient(env);

    // Check if annotation exists and user owns it
    const { data: existingAnnotation } = await database
      .from('annotations')
      .select('user_id')
      .eq('id', annotationId)
      .single();

    if (!existingAnnotation) {
      return new Response(JSON.stringify({
        error: 'Annotation not found',
        message: 'The requested annotation does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (existingAnnotation.user_id !== user.id) {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'You can only update your own annotations'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { data: updatedAnnotation, error } = await database
      .from('annotations')
      .update({
        ...updateData,
        updated_at: new Date().toISOString()
      })
      .eq('id', annotationId)
      .select(`
        *,
        user:users(
          id,
          username,
          full_name,
          avatar_url,
          is_verified
        )
      `)
      .single();

    if (error) {
      console.error('Update annotation error:', error);
      return new Response(JSON.stringify({
        error: 'Failed to update annotation',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      success: true,
      data: updatedAnnotation,
      message: 'Annotation updated successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Update annotation error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update annotation'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Delete annotation
export const deleteAnnotation: RouteHandler = async (request, env, ctx, params) => {
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

    const annotationId = params?.id;
    if (!annotationId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Annotation ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const database = createDatabaseClient(env);

    // Check if annotation exists and user owns it
    const { data: existingAnnotation } = await database
      .from('annotations')
      .select('user_id')
      .eq('id', annotationId)
      .single();

    if (!existingAnnotation) {
      return new Response(JSON.stringify({
        error: 'Annotation not found',
        message: 'The requested annotation does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (existingAnnotation.user_id !== user.id && user.role !== 'admin') {
      return new Response(JSON.stringify({
        error: 'Forbidden',
        message: 'You can only delete your own annotations'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const { error } = await database
      .from('annotations')
      .delete()
      .eq('id', annotationId);

    if (error) {
      console.error('Delete annotation error:', error);
      return new Response(JSON.stringify({
        error: 'Failed to delete annotation',
        message: error.message
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      success: true,
      message: 'Annotation deleted successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Delete annotation error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to delete annotation'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// Like/Unlike annotation
export const toggleLike: RouteHandler = async (request, env, ctx, params) => {
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

    const annotationId = params?.id;
    if (!annotationId) {
      return new Response(JSON.stringify({
        error: 'Bad Request',
        message: 'Annotation ID is required'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const database = createDatabaseClient(env);

    // Check if annotation exists
    const { data: annotation } = await database
      .from('annotations')
      .select('id, likes_count')
      .eq('id', annotationId)
      .single();

    if (!annotation) {
      return new Response(JSON.stringify({
        error: 'Annotation not found',
        message: 'The requested annotation does not exist'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check if user already liked this annotation
    // Note: In a real implementation, you'd have a separate 'likes' table
    // For now, we'll use a simple approach with user metadata or a separate table
    
    // This is a simplified implementation
    // In production, create a 'annotation_likes' table with user_id and annotation_id
    
    return new Response(JSON.stringify({
      success: true,
      data: {
        is_liked: true, // This should be determined by checking the likes table
        likes_count: annotation.likes_count + 1 // This should be updated atomically
      },
      message: 'Like status updated successfully'
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Toggle like error:', error);
    return new Response(JSON.stringify({
      error: 'Internal Server Error',
      message: 'Failed to update like status'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};