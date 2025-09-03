/**
 * Performance optimization indexes migration
 * Adds indexes to improve query performance and reduce response times
 */

exports.up = async function(knex) {
  console.log('Adding performance optimization indexes...');

  // Annotations table indexes
  await knex.schema.alterTable('annotations', function(table) {
    // Status and timestamp for filtering
    table.index(['status', 'created_at'], 'idx_annotations_status_created');
    
    // Geographic queries (lat/lng for SQLite, spatial for PostgreSQL)
    table.index(['latitude', 'longitude'], 'idx_annotations_location');
    
    // Smell intensity for filtering
    table.index('smell_intensity', 'idx_annotations_intensity');
    
    // User annotations
    table.index(['user_id', 'created_at'], 'idx_annotations_user_created');
    
    // Most recent approved annotations
    table.index(['status', 'created_at', 'id'], 'idx_annotations_status_created_id');
    
    // Location-based queries with status
    table.index(['status', 'latitude', 'longitude'], 'idx_annotations_status_location');
  });

  // Users table indexes
  await knex.schema.alterTable('users', function(table) {
    // Email lookup (if not already indexed)
    if (!table._indexExists || !table._indexExists('email')) {
      table.unique('email', 'idx_users_email_unique');
    }
    
    // Username lookup
    if (!table._indexExists || !table._indexExists('username')) {
      table.index('username', 'idx_users_username');
    }
    
    // Active users
    table.index(['status', 'created_at'], 'idx_users_status_created');
  });

  // Annotation likes table indexes
  await knex.schema.alterTable('annotation_likes', function(table) {
    // Composite index for like counting
    table.index(['annotation_id', 'created_at'], 'idx_likes_annotation_created');
    
    // User likes lookup
    table.index(['user_id', 'created_at'], 'idx_likes_user_created');
    
    // Unique constraint to prevent duplicate likes
    table.unique(['annotation_id', 'user_id'], 'idx_likes_annotation_user_unique');
  });

  // Media files table indexes
  await knex.schema.alterTable('media_files', function(table) {
    // Annotation media lookup
    table.index(['annotation_id', 'created_at'], 'idx_media_annotation_created');
    
    // File type filtering
    table.index('file_type', 'idx_media_file_type');
    
    // Active media files
    table.index(['deleted_at', 'annotation_id'], 'idx_media_active_annotation');
  });

  // Payments table indexes
  await knex.schema.alterTable('payments', function(table) {
    // User payments
    table.index(['user_id', 'created_at'], 'idx_payments_user_created');
    
    // Payment status
    table.index(['status', 'created_at'], 'idx_payments_status_created');
    
    // Annotation payments
    table.index('annotation_id', 'idx_payments_annotation');
    
    // Stripe payment ID lookup
    table.index('stripe_payment_intent_id', 'idx_payments_stripe_id');
  });

  // Comments table indexes (if exists)
  const hasCommentsTable = await knex.schema.hasTable('annotation_comments');
  if (hasCommentsTable) {
    await knex.schema.alterTable('annotation_comments', function(table) {
      // Annotation comments
      table.index(['annotation_id', 'created_at'], 'idx_comments_annotation_created');
      
      // User comments
      table.index(['user_id', 'created_at'], 'idx_comments_user_created');
      
      // Active comments
      table.index(['deleted_at', 'annotation_id'], 'idx_comments_active_annotation');
      
      // Parent-child comment relationships
      table.index('parent_id', 'idx_comments_parent');
    });
  }

  // Sessions table indexes (if exists)
  const hasSessionsTable = await knex.schema.hasTable('user_sessions');
  if (hasSessionsTable) {
    await knex.schema.alterTable('user_sessions', function(table) {
      // Session token lookup
      table.index('token', 'idx_sessions_token');
      
      // User sessions
      table.index(['user_id', 'expires_at'], 'idx_sessions_user_expires');
      
      // Session cleanup
      table.index('expires_at', 'idx_sessions_expires');
    });
  }

  // Notifications table indexes (if exists)
  const hasNotificationsTable = await knex.schema.hasTable('notifications');
  if (hasNotificationsTable) {
    await knex.schema.alterTable('notifications', function(table) {
      // User notifications
      table.index(['user_id', 'created_at'], 'idx_notifications_user_created');
      
      // Unread notifications
      table.index(['user_id', 'read', 'created_at'], 'idx_notifications_user_unread');
      
      // Notification type
      table.index('type', 'idx_notifications_type');
    });
  }

  // Add PostGIS spatial indexes for PostgreSQL
  const dbConfig = knex.client.config;
  if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
    console.log('Adding PostGIS spatial indexes...');
    
    // Create spatial index on location_point
    await knex.raw(`
      CREATE INDEX IF NOT EXISTS idx_annotations_location_point_gist 
      ON annotations USING GIST (location_point)
    `);
    
    // Create compound spatial index for status + location
    await knex.raw(`
      CREATE INDEX IF NOT EXISTS idx_annotations_status_location_gist 
      ON annotations USING GIST (location_point) 
      WHERE status = 'approved'
    `);
  }

  console.log('Performance indexes added successfully!');
};

exports.down = async function(knex) {
  console.log('Removing performance optimization indexes...');

  // Remove annotations indexes
  await knex.schema.alterTable('annotations', function(table) {
    table.dropIndex(['status', 'created_at'], 'idx_annotations_status_created');
    table.dropIndex(['latitude', 'longitude'], 'idx_annotations_location');
    table.dropIndex('smell_intensity', 'idx_annotations_intensity');
    table.dropIndex(['user_id', 'created_at'], 'idx_annotations_user_created');
    table.dropIndex(['status', 'created_at', 'id'], 'idx_annotations_status_created_id');
    table.dropIndex(['status', 'latitude', 'longitude'], 'idx_annotations_status_location');
  });

  // Remove users indexes
  await knex.schema.alterTable('users', function(table) {
    table.dropIndex('username', 'idx_users_username');
    table.dropIndex(['status', 'created_at'], 'idx_users_status_created');
  });

  // Remove annotation likes indexes
  await knex.schema.alterTable('annotation_likes', function(table) {
    table.dropIndex(['annotation_id', 'created_at'], 'idx_likes_annotation_created');
    table.dropIndex(['user_id', 'created_at'], 'idx_likes_user_created');
    table.dropUnique(['annotation_id', 'user_id'], 'idx_likes_annotation_user_unique');
  });

  // Remove media files indexes
  await knex.schema.alterTable('media_files', function(table) {
    table.dropIndex(['annotation_id', 'created_at'], 'idx_media_annotation_created');
    table.dropIndex('file_type', 'idx_media_file_type');
    table.dropIndex(['deleted_at', 'annotation_id'], 'idx_media_active_annotation');
  });

  // Remove payments indexes
  await knex.schema.alterTable('payments', function(table) {
    table.dropIndex(['user_id', 'created_at'], 'idx_payments_user_created');
    table.dropIndex(['status', 'created_at'], 'idx_payments_status_created');
    table.dropIndex('annotation_id', 'idx_payments_annotation');
    table.dropIndex('stripe_payment_intent_id', 'idx_payments_stripe_id');
  });

  // Remove comments indexes (if exists)
  const hasCommentsTable = await knex.schema.hasTable('annotation_comments');
  if (hasCommentsTable) {
    await knex.schema.alterTable('annotation_comments', function(table) {
      table.dropIndex(['annotation_id', 'created_at'], 'idx_comments_annotation_created');
      table.dropIndex(['user_id', 'created_at'], 'idx_comments_user_created');
      table.dropIndex(['deleted_at', 'annotation_id'], 'idx_comments_active_annotation');
      table.dropIndex('parent_id', 'idx_comments_parent');
    });
  }

  // Remove PostGIS spatial indexes
  const dbConfig = knex.client.config;
  if (dbConfig.client === 'postgresql' || dbConfig.client === 'pg') {
    await knex.raw('DROP INDEX IF EXISTS idx_annotations_location_point_gist');
    await knex.raw('DROP INDEX IF EXISTS idx_annotations_status_location_gist');
  }

  console.log('Performance indexes removed successfully!');
};