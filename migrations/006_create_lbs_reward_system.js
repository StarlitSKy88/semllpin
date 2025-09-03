/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
  const { v4: uuidv4 } = require('uuid');
  
  return knex.schema
    // 1. User Locations Table (用户位置表)
    .createTable('user_locations', function(table) {
      table.string('id', 36).primary().defaultTo(uuidv4());
      table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.float('latitude').notNullable();
      table.float('longitude').notNullable();
      table.string('location_name', 255);
      table.text('address');
      table.float('accuracy');
      table.float('altitude');
      table.float('speed');
      table.float('heading');
      table.string('location_type', 20).defaultTo('manual');
      table.boolean('is_current').defaultTo(false);
      table.timestamp('created_at').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // Indexes
      table.index('user_id');
      table.index(['latitude', 'longitude']);
      table.index(['user_id', 'is_current']);
      table.index('created_at');
      table.index('location_type');
    })
    
    // 2. Check-in Records Table (签到记录表)
    .createTable('checkin_records', function(table) {
      table.string('id', 36).primary().defaultTo(uuidv4());
      table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.string('location_id', 36).references('id').inTable('user_locations').onDelete('SET NULL');
      table.float('latitude').notNullable();
      table.float('longitude').notNullable();
      table.string('location_name', 255);
      table.text('address');
      table.string('checkin_type', 20).defaultTo('manual');
      table.integer('points_earned').defaultTo(0);
      table.float('bonus_multiplier').defaultTo(1.0);
      table.integer('consecutive_days').defaultTo(1);
      table.boolean('is_first_time').defaultTo(false);
      table.string('weather_condition', 50);
      table.float('temperature');
      table.text('notes');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      // Indexes
      table.index('user_id');
      table.index(['latitude', 'longitude']);
      table.index('created_at');
      table.index(['user_id', 'created_at']);
      table.index('location_id');
    })
    
    // 3. Reward Records Table (奖励记录表)
    .createTable('reward_records', function(table) {
      table.string('id', 36).primary().defaultTo(uuidv4());
      table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.string('reward_type', 50).notNullable();
      table.string('reward_category', 50).notNullable();
      table.integer('points').notNullable().defaultTo(0);
      table.float('coins').defaultTo(0);
      table.float('cash_value').defaultTo(0);
      table.text('description').notNullable();
      table.string('source_id', 36);
      table.string('source_type', 50);
      table.string('location_id', 36).references('id').inTable('user_locations').onDelete('SET NULL');
      table.float('latitude');
      table.float('longitude');
      table.float('multiplier').defaultTo(1.0);
      table.timestamp('expires_at');
      table.timestamp('claimed_at');
      table.string('status', 20).defaultTo('pending');
      table.text('metadata').defaultTo('{}');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // Indexes
      table.index('user_id');
      table.index('reward_type');
      table.index('status');
      table.index('created_at');
      table.index(['source_type', 'source_id']);
      table.index(['latitude', 'longitude']);
    })
    
    // 4. User Stats Table (用户统计表)
    .createTable('user_stats', function(table) {
      table.string('id', 36).primary().defaultTo(uuidv4());
      table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE').unique();
      table.integer('total_points').defaultTo(0);
      table.integer('available_points').defaultTo(0);
      table.float('total_coins').defaultTo(0);
      table.float('available_coins').defaultTo(0);
      table.integer('total_checkins').defaultTo(0);
      table.integer('consecutive_checkins').defaultTo(0);
      table.integer('max_consecutive_checkins').defaultTo(0);
      table.float('total_distance').defaultTo(0);
      table.integer('unique_locations').defaultTo(0);
      table.integer('exploration_score').defaultTo(0);
      table.integer('social_score').defaultTo(0);
      table.integer('level_id').defaultTo(1);
      table.integer('experience_points').defaultTo(0);
      table.timestamp('last_checkin_at');
      table.timestamp('last_location_update');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // Indexes
      table.index('total_points');
      table.index('level_id');
      table.index('consecutive_checkins');
    })
    
    // 5. Nearby Users Table (附近用户表)
    .createTable('nearby_users', function(table) {
      table.string('id', 36).primary().defaultTo(uuidv4());
      table.string('user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.string('nearby_user_id', 36).notNullable().references('id').inTable('users').onDelete('CASCADE');
      table.float('distance').notNullable();
      table.float('latitude').notNullable();
      table.float('longitude').notNullable();
      table.float('nearby_latitude').notNullable();
      table.float('nearby_longitude').notNullable();
      table.string('interaction_type', 50);
      table.integer('interaction_count').defaultTo(0);
      table.timestamp('last_seen_at').defaultTo(knex.fn.now());
      table.timestamp('created_at').defaultTo(knex.fn.now());
      
      table.unique(['user_id', 'nearby_user_id']);
      
      // Indexes
      table.index('user_id');
      table.index('nearby_user_id');
      table.index('distance');
      table.index('last_seen_at');
    })
    
    // 6. Location Hotspots Table (热点位置表)
    .createTable('location_hotspots', function(table) {
      table.string('id', 36).primary().defaultTo(uuidv4());
      table.string('name', 255).notNullable();
      table.text('description');
      table.float('latitude').notNullable();
      table.float('longitude').notNullable();
      table.float('radius').defaultTo(100);
      table.string('category', 50).notNullable();
      table.integer('popularity_score').defaultTo(0);
      table.integer('checkin_count').defaultTo(0);
      table.integer('annotation_count').defaultTo(0);
      table.float('reward_multiplier').defaultTo(1.0);
      table.boolean('is_active').defaultTo(true);
      table.string('created_by', 36).references('id').inTable('users').onDelete('SET NULL');
      table.timestamp('created_at').defaultTo(knex.fn.now());
      table.timestamp('updated_at').defaultTo(knex.fn.now());
      
      // Indexes
      table.index(['latitude', 'longitude']);
      table.index('category');
      table.index('popularity_score');
      table.index('is_active');
    })
    
    // Add some initial hotspots data
    .then(() => {
      return knex('location_hotspots').insert([
        {
          id: uuidv4(),
          name: 'University Campus',
          description: 'Main university campus area',
          latitude: 40.7589,
          longitude: -73.9851,
          category: 'education',
          reward_multiplier: 1.5
        },
        {
          id: uuidv4(),
          name: 'Central Park',
          description: 'Popular park for recreation',
          latitude: 40.7812,
          longitude: -73.9665,
          category: 'recreation',
          reward_multiplier: 1.2
        },
        {
          id: uuidv4(),
          name: 'Times Square',
          description: 'Busy commercial area',
          latitude: 40.7580,
          longitude: -73.9855,
          category: 'commercial',
          reward_multiplier: 2.0
        },
        {
          id: uuidv4(),
          name: 'Brooklyn Bridge',
          description: 'Historic landmark',
          latitude: 40.7061,
          longitude: -73.9969,
          category: 'landmark',
          reward_multiplier: 1.8
        },
        {
          id: uuidv4(),
          name: 'Coffee Shop District',
          description: 'Popular coffee shop area',
          latitude: 40.7505,
          longitude: -73.9934,
          category: 'food',
          reward_multiplier: 1.3
        }
      ]);
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
  return knex.schema
    .dropTableIfExists('nearby_users')
    .dropTableIfExists('location_hotspots')
    .dropTableIfExists('user_stats')
    .dropTableIfExists('reward_records')
    .dropTableIfExists('checkin_records')
    .dropTableIfExists('user_locations');
};