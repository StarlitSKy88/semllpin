/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  return knex.schema.hasTable('user_follows')
    .then(exists => {
      if (!exists) {
        return knex.schema
          .createTable('user_follows', function (table) {
            table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
            table.uuid('follower_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
            table.uuid('following_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
            table.timestamp('created_at').defaultTo(knex.fn.now());
            
            // 确保不能关注自己
            table.check('follower_id != following_id', [], 'check_not_self_follow');
            
            // 确保同一对用户只能有一个关注关系
            table.unique(['follower_id', 'following_id']);
            
            // 创建索引
            table.index('follower_id');
            table.index('following_id');
            table.index('created_at');
          })
          .then(() => {
            // 检查用户表是否已有关注数字段
            return knex.schema.hasColumn('users', 'followers_count')
              .then(hasFollowersCount => {
                if (!hasFollowersCount) {
                  return knex.schema.alterTable('users', function (table) {
                    table.integer('followers_count').defaultTo(0);
                    table.integer('following_count').defaultTo(0);
                  });
                }
              });
          });
      }
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema.hasColumn('users', 'followers_count')
    .then(hasFollowersCount => {
      if (hasFollowersCount) {
        return knex.schema.alterTable('users', function (table) {
          table.dropColumn('followers_count');
          table.dropColumn('following_count');
        });
      }
    })
    .then(() => knex.schema.dropTableIfExists('user_follows'));
};
