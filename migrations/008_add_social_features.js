/**
 * 添加社交互动功能表
 * 包括：用户关注、点赞、收藏、通知、分享等功能
 */

exports.up = function(knex) {
  return Promise.all([
    // 用户关注表
    knex.schema.createTable('user_follows', function(table) {
      table.string('id', 36).primary();
      table.uuid('follower_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.uuid('following_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 确保同一用户不能重复关注
      table.unique(['follower_id', 'following_id']);
      // 创建索引提高查询性能
      table.index(['follower_id']);
      table.index(['following_id']);
    }),

    // 评论点赞表
    knex.schema.createTable('comment_likes', function(table) {
      table.string('id', 36).primary();
      table.uuid('comment_id').notNullable().references('id').inTable('comments').onDelete('CASCADE');
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 确保同一用户不能重复点赞同一评论
      table.unique(['comment_id', 'user_id']);
      table.index(['comment_id']);
      table.index(['user_id']);
    }),

    // 标注点赞表（扩展现有功能）
    knex.schema.createTable('annotation_likes', function(table) {
      table.string('id', 36).primary();
      table.uuid('annotation_id').notNullable().references('id').inTable('annotations').onDelete('CASCADE');
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 确保同一用户不能重复点赞同一标注
      table.unique(['annotation_id', 'user_id']);
      table.index(['annotation_id']);
      table.index(['user_id']);
    }),

    // 用户收藏表
    knex.schema.createTable('user_favorites', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.uuid('annotation_id').notNullable().references('id').inTable('annotations').onDelete('CASCADE');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 确保同一用户不能重复收藏同一标注
      table.unique(['user_id', 'annotation_id']);
      table.index(['user_id']);
      table.index(['annotation_id']);
    }),

    // 通知表
    knex.schema.createTable('notifications', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE'); // 接收通知的用户
      table.uuid('from_user_id').nullable().references('id').inTable('users').onDelete('CASCADE'); // 触发通知的用户
      table.string('type').notNullable(); // 通知类型：follow, like, comment, reply等
      table.string('title').notNullable(); // 通知标题
      table.text('content').notNullable(); // 通知内容
      table.string('related_id', 36).nullable(); // 相关对象ID（标注ID、评论ID等）
      table.string('related_type').nullable(); // 相关对象类型
      table.boolean('is_read').defaultTo(false); // 是否已读
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 创建索引
      table.index(['user_id']);
      table.index(['from_user_id']);
      table.index(['type']);
      table.index(['is_read']);
      table.index(['created_at']);
    }),

    // 分享记录表
    knex.schema.createTable('share_records', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.uuid('annotation_id').notNullable().references('id').inTable('annotations').onDelete('CASCADE');
      table.string('platform').notNullable(); // 分享平台：twitter, instagram, tiktok, wechat等
      table.string('share_url').nullable(); // 分享链接
      table.text('share_data').nullable(); // 分享相关数据（SQLite使用text代替json）
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // 创建索引
      table.index(['user_id']);
      table.index(['annotation_id']);
      table.index(['platform']);
      table.index(['created_at']);
    })
  ]);
};

exports.down = function(knex) {
  return Promise.all([
    knex.schema.dropTableIfExists('share_records'),
    knex.schema.dropTableIfExists('notifications'),
    knex.schema.dropTableIfExists('user_favorites'),
    knex.schema.dropTableIfExists('annotation_likes'),
    knex.schema.dropTableIfExists('comment_likes'),
    knex.schema.dropTableIfExists('user_follows')
  ]);
};