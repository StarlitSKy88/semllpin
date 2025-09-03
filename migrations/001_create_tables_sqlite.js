/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = async function(knex) {
  // Create users table
  await knex.schema.createTable('users', function(table) {
    table.string('id', 36).primary(); // UUID will be generated in application
    table.string('email', 255).notNullable().unique();
    table.string('username', 50).notNullable().unique();
    table.string('password_hash', 255).notNullable();
    table.string('display_name', 100);
    table.text('bio');
    table.string('avatar_url', 500);
    table.string('role', 20).defaultTo('user').checkIn(['user', 'moderator', 'admin']);
    table.string('status', 20).defaultTo('active').checkIn(['active', 'suspended', 'deleted']);
    table.boolean('email_verified').defaultTo(false);
    table.string('email_verification_token', 255);
    table.string('password_reset_token', 255);
    table.timestamp('password_reset_expires');
    table.timestamp('last_login_at');
    table.timestamps(true, true);
    
    // Indexes
    table.index('email');
    table.index('username');
    table.index('status');
    table.index('role');
    table.index('created_at');
    table.index('email_verification_token');
    table.index('password_reset_token');
  });

  // Create annotations table
  await knex.schema.createTable('annotations', function(table) {
    table.string('id', 36).primary(); // UUID will be generated in application
    table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.decimal('latitude', 10, 8).notNullable();
    table.decimal('longitude', 11, 8).notNullable();
    table.integer('smell_intensity').notNullable().checkBetween([1, 10]);
    table.text('description');
    table.string('country', 2); // ISO country code
    table.string('region', 100);
    table.string('city', 100);
    table.text('address');
    table.string('status', 20).defaultTo('pending').checkIn(['pending', 'approved', 'rejected']);
    table.text('moderation_reason');
    table.string('moderated_by', 36).references('id').inTable('users');
    table.timestamp('moderated_at');
    table.string('payment_id', 36); // Reference to payment record
    table.json('media_files'); // Array of media file IDs
    table.integer('view_count').defaultTo(0);
    table.integer('like_count').defaultTo(0);
    table.integer('comment_count').defaultTo(0);
    table.timestamps(true, true);
    
    // Indexes
    table.index('user_id');
    table.index(['latitude', 'longitude']);
    table.index('smell_intensity');
    table.index('status');
    table.index('country');
    table.index('city');
    table.index('created_at');
    table.index('payment_id');
  });

  // Create comments table
  await knex.schema.createTable('comments', function(table) {
    table.string('id', 36).primary(); // UUID will be generated in application
    table.string('annotation_id', 36).notNullable().references('id').inTable('annotations').onDelete('CASCADE');
    table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('parent_id', 36).references('id').inTable('comments').onDelete('CASCADE'); // For nested comments
    table.text('content').notNullable();
    table.string('status', 20).defaultTo('active').checkIn(['active', 'hidden', 'deleted']);
    table.text('moderation_reason');
    table.string('moderated_by', 36).references('id').inTable('users');
    table.timestamp('moderated_at');
    table.integer('like_count').defaultTo(0);
    table.timestamps(true, true);
    
    // Indexes
    table.index('annotation_id');
    table.index('user_id');
    table.index('parent_id');
    table.index('status');
    table.index('created_at');
  });

  // Create payments table
  await knex.schema.createTable('payments', function(table) {
    table.string('id', 36).primary(); // UUID will be generated in application
    table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('annotation_id', 36).references('id').inTable('annotations').onDelete('SET NULL');
    table.string('stripe_session_id', 255).unique();
    table.string('stripe_payment_intent_id', 255);
    table.decimal('amount', 10, 2).notNullable(); // Amount in USD
    table.string('currency', 3).defaultTo('USD');
    table.string('status', 20).defaultTo('pending').checkIn(['pending', 'completed', 'failed', 'cancelled', 'refunded']);
    table.text('description');
    table.json('metadata'); // Additional payment metadata
    table.timestamp('paid_at');
    table.timestamp('expires_at');
    table.timestamps(true, true);
    
    // Indexes
    table.index('user_id');
    table.index('annotation_id');
    table.index('stripe_session_id');
    table.index('stripe_payment_intent_id');
    table.index('status');
    table.index('created_at');
  });

  // Create media_files table
  await knex.schema.createTable('media_files', function(table) {
    table.string('id', 36).primary(); // UUID will be generated in application
    table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.string('annotation_id', 36).references('id').inTable('annotations').onDelete('CASCADE');
    table.string('filename', 255).notNullable();
    table.string('original_name', 255).notNullable();
    table.string('mime_type', 100).notNullable();
    table.integer('file_size').notNullable(); // Size in bytes
    table.string('file_path', 500).notNullable();
    table.string('file_url', 500);
    table.string('thumbnail_url', 500);
    table.integer('width'); // For images
    table.integer('height'); // For images
    table.integer('duration'); // For videos in seconds
    table.string('status', 20).defaultTo('active').checkIn(['active', 'deleted']);
    table.timestamps(true, true);
    
    // Indexes
    table.index('user_id');
    table.index('annotation_id');
    table.index('mime_type');
    table.index('status');
    table.index('created_at');
  });



  console.log('✅ SQLite 数据库表创建完成');
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = async function(knex) {
  await knex.schema.dropTableIfExists('media_files');
  await knex.schema.dropTableIfExists('payments');
  await knex.schema.dropTableIfExists('comments');
  await knex.schema.dropTableIfExists('annotations');
  await knex.schema.dropTableIfExists('users');
};