/**
 * 创建钱包和交易系统表
 * 包括：用户钱包、交易记录、LBS奖励等
 */

exports.up = function(knex) {
  return Promise.all([
    // 用户钱包表
    knex.schema.createTable('wallets', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.decimal('balance', 10, 2).defaultTo(0.00); // 余额
      table.decimal('frozen_balance', 10, 2).defaultTo(0.00); // 冻结余额
      table.string('currency', 3).defaultTo('CNY'); // 货币类型
      table.string('status').defaultTo('active'); // 钱包状态：active, frozen, closed
      table.timestamp('created_at').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // 确保每个用户只有一个钱包
      table.unique(['user_id']);
      table.index(['user_id']);
      table.index(['status']);
    }),

    // 交易记录表
    knex.schema.createTable('transactions', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.string('wallet_id', 36).notNullable().references('id').inTable('wallets').onDelete('CASCADE');
      table.string('type').notNullable(); // 交易类型：deposit, withdraw, payment, reward, refund
      table.decimal('amount', 10, 2).notNullable(); // 交易金额
      table.decimal('balance_before', 10, 2).notNullable(); // 交易前余额
      table.decimal('balance_after', 10, 2).notNullable(); // 交易后余额
      table.string('status').defaultTo('pending'); // 交易状态：pending, completed, failed, cancelled
      table.string('description').nullable(); // 交易描述
      table.string('reference_id', 36).nullable(); // 关联ID（标注ID、订单ID等）
      table.string('reference_type').nullable(); // 关联类型
      table.string('payment_method').nullable(); // 支付方式：alipay, wechat, paypal等
      table.string('external_transaction_id').nullable(); // 外部交易ID
      table.text('metadata').nullable(); // 额外元数据（SQLite使用text代替json）
      table.timestamp('created_at').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // 创建索引
      table.index(['user_id']);
      table.index(['wallet_id']);
      table.index(['type']);
      table.index(['status']);
      table.index(['reference_id']);
      table.index(['created_at']);
    }),

    // LBS奖励记录表
    knex.schema.createTable('lbs_rewards', function(table) {
      table.string('id', 36).primary();
      table.uuid('user_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.uuid('annotation_id').notNullable().references('id').inTable('annotations').onDelete('CASCADE');
      table.string('transaction_id', 36).nullable().references('id').inTable('transactions').onDelete('SET NULL');
      table.decimal('reward_amount', 10, 2).notNullable(); // 奖励金额
      table.decimal('latitude', 10, 8).notNullable(); // 用户获得奖励时的纬度
      table.decimal('longitude', 11, 8).notNullable(); // 用户获得奖励时的经度
      table.decimal('distance_to_annotation', 8, 2).nullable(); // 距离标注的距离（米）
      table.string('reward_type').defaultTo('proximity'); // 奖励类型：proximity, interaction, bonus
      table.string('status').defaultTo('pending'); // 状态：pending, paid, expired
      table.timestamp('discovered_at').defaultTo(knex.fn.now()); // 发现时间
      table.timestamp('paid_at').nullable(); // 支付时间
      table.timestamp('expires_at').nullable(); // 过期时间
      
      // 创建索引
      table.index(['user_id']);
      table.index(['annotation_id']);
      table.index(['status']);
      table.index(['discovered_at']);
      table.index(['expires_at']);
      
      // 确保同一用户不能重复获得同一标注的奖励
      table.unique(['user_id', 'annotation_id']);
    })
  ]);
};

exports.down = function(knex) {
  return Promise.all([
    knex.schema.dropTableIfExists('lbs_rewards'),
    knex.schema.dropTableIfExists('transactions'),
    knex.schema.dropTableIfExists('wallets')
  ]);
};