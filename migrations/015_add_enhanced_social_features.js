/**
 * 增强社交功能表结构
 * 包括：用户动态流、隐私设置、用户统计等
 */

exports.up = function(knex) {
  return Promise.all([
    // 用户动态流表
    knex.schema.createTable('user_feeds', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.uuid('actor_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.enum('action_type', ['annotation', 'like', 'comment', 'follow', 'share', 'favorite']).notNullable();
      table.enum('target_type', ['annotation', 'user', 'comment']).notNullable();
      table.string('target_id', 36).notNullable();
      table.text('metadata'); // JSON格式存储额外信息
      table.enum('privacy_level', ['public', 'followers', 'private']).defaultTo('public');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 索引
      table.index(['user_id', 'created_at']);
      table.index(['actor_id', 'created_at']);
      table.index(['action_type']);
      table.index(['target_type', 'target_id']);
      table.index(['privacy_level']);
    }),

    // 用户隐私设置表
    knex.schema.createTable('user_privacy_settings', function(table) {
      table.uuid('user_id').primary().references('id').inTable('users').onDelete('CASCADE');
      table.enum('profile_visibility', ['public', 'followers', 'private']).defaultTo('public');
      table.enum('activity_visibility', ['public', 'followers', 'private']).defaultTo('public');
      table.enum('location_visibility', ['public', 'followers', 'private']).defaultTo('followers');
      table.boolean('email_notifications').defaultTo(true);
      table.boolean('push_notifications').defaultTo(true);
      table.boolean('sms_notifications').defaultTo(false);
      table.timestamp('created_at').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // 索引
      table.index(['profile_visibility']);
      table.index(['activity_visibility']);
    }),

    // 用户兴趣标签表
    knex.schema.createTable('user_interest_tags', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.string('tag_name').notNullable(); // 兴趣标签名称
      table.string('tag_category').nullable(); // 标签分类
      table.decimal('confidence_score', 3, 2).defaultTo(0.5); // 置信度分数 0-1
      table.integer('interaction_count').defaultTo(1); // 交互次数
      table.timestamp('last_updated').defaultTo(knex.fn.now());
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 确保用户-标签唯一
      table.unique(['user_id', 'tag_name']);
      table.index(['user_id']);
      table.index(['tag_name']);
      table.index(['confidence_score']);
    }),

    // 内容审核表
    knex.schema.createTable('content_moderation', function(table) {
      table.string('id', 36).primary();
      table.enum('content_type', ['annotation', 'comment', 'user_profile']).notNullable();
      table.string('content_id', 36).notNullable();
      table.uuid('reported_by').nullable().references('id').inTable('users').onDelete('SET NULL');
      table.uuid('moderator_id').nullable().references('id').inTable('users').onDelete('SET NULL');
      table.enum('reason', ['spam', 'inappropriate', 'harassment', 'fake_info', 'other']).notNullable();
      table.text('description').nullable();
      table.enum('status', ['pending', 'approved', 'rejected', 'needs_review']).defaultTo('pending');
      table.text('moderator_notes').nullable();
      table.timestamp('reported_at').defaultTo(knex.fn.now());
      table.timestamp('moderated_at').nullable();
      
      // 索引
      table.index(['content_type', 'content_id']);
      table.index(['status']);
      table.index(['reported_by']);
      table.index(['moderator_id']);
      table.index(['reported_at']);
    }),

    // 用户活动统计表（用于缓存复杂的统计查询）
    knex.schema.createTable('user_activity_stats', function(table) {
      table.uuid('user_id').primary().references('id').inTable('users').onDelete('CASCADE');
      table.integer('total_annotations').defaultTo(0);
      table.integer('total_comments').defaultTo(0);
      table.integer('total_likes_given').defaultTo(0);
      table.integer('total_likes_received').defaultTo(0);
      table.integer('total_shares').defaultTo(0);
      table.integer('followers_count').defaultTo(0);
      table.integer('following_count').defaultTo(0);
      table.integer('favorites_count').defaultTo(0);
      table.decimal('reputation_score', 10, 2).defaultTo(0);
      table.integer('weekly_posts').defaultTo(0);
      table.integer('monthly_posts').defaultTo(0);
      table.timestamp('last_calculated').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // 索引
      table.index(['reputation_score']);
      table.index(['followers_count']);
      table.index(['total_annotations']);
    })
  ]);
};

exports.down = function(knex) {
  return Promise.all([
    knex.schema.dropTableIfExists('user_activity_stats'),
    knex.schema.dropTableIfExists('content_moderation'),
    knex.schema.dropTableIfExists('user_interest_tags'),
    knex.schema.dropTableIfExists('user_privacy_settings'),
    knex.schema.dropTableIfExists('user_feeds')
  ]);
};