const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.seed = async function(knex) {
  // 清空现有数据
  await knex('comments').del();
  await knex('annotations').del();
  await knex('users').del();
  
  console.log('开始插入种子数据...');

  // Sample users data
  const sampleUsers = [
    {
      email: 'john.doe@example.com',
      username: 'johndoe',
      password: 'password123!',
      display_name: 'John Doe',
      bio: '环境保护爱好者，关注城市空气质量',
      role: 'user'
    },
    {
      email: 'jane.smith@example.com',
      username: 'janesmith',
      password: 'password123!',
      display_name: 'Jane Smith',
      bio: '城市规划师，致力于改善城市环境',
      role: 'user'
    },
    {
      email: 'moderator@smellpin.com',
      username: 'moderator',
      password: 'moderator123!',
      display_name: 'Content Moderator',
      bio: '内容审核员',
      role: 'moderator'
    },
    {
      email: 'admin@smellpin.com',
      username: 'admin',
      password: 'admin123!',
      display_name: 'System Administrator',
      bio: '系统管理员',
      role: 'admin'
    }
  ];

  // 插入用户数据
  console.log('插入用户数据...');
  const saltRounds = 12;
  
  for (const userData of sampleUsers) {
    const password_hash = await bcrypt.hash(userData.password, saltRounds);
    
    await knex('users').insert({
      id: uuidv4(),
      email: userData.email.toLowerCase(),
      username: userData.username,
      password_hash,
      display_name: userData.display_name,
      bio: userData.bio,
      role: userData.role,
      status: 'active',
      email_verified: true,
    });
  }

  console.log(`✅ 插入了 ${sampleUsers.length} 个用户`);

  // 获取插入的用户ID
  const users = await knex('users').select('id', 'username');
  const userMap = {};
  users.forEach(user => {
    userMap[user.username] = user.id;
  });

  // Sample annotations data
  const sampleAnnotations = [
    {
      id: uuidv4(),
      latitude: 39.9042,
      longitude: 116.4074,
      smell_intensity: 8,
      description: '北京天安门附近检测到强烈的汽车尾气味道',
      country: 'CN',
      region: 'Beijing',
      city: 'Beijing',
      user_id: userMap['johndoe']
    },
    {
      id: uuidv4(),
      latitude: 31.2304,
      longitude: 121.4737,
      smell_intensity: 6,
      description: '上海外滩附近有轻微的工业异味',
      country: 'CN',
      region: 'Shanghai',
      city: 'Shanghai',
      user_id: userMap['janesmith']
    },
    {
      id: uuidv4(),
      latitude: 40.7128,
      longitude: -74.0060,
      smell_intensity: 7,
      description: 'Strong sewage smell near Times Square subway station',
      country: 'US',
      region: 'New York',
      city: 'New York',
      user_id: userMap['johndoe']
    },
    {
      id: uuidv4(),
      latitude: 51.5074,
      longitude: -0.1278,
      smell_intensity: 5,
      description: 'Mild chemical odor detected near Thames River',
      country: 'GB',
      region: 'England',
      city: 'London',
      user_id: userMap['janesmith']
    },
    {
      id: uuidv4(),
      latitude: 35.6762,
      longitude: 139.6503,
      smell_intensity: 4,
      description: '東京駅周辺で軽微な排気ガスの臭い',
      country: 'JP',
      region: 'Tokyo',
      city: 'Tokyo',
      user_id: userMap['johndoe']
    }
  ];

  // 插入标注数据
  console.log('插入标注数据...');
  const insertedAnnotations = await knex('annotations').insert(sampleAnnotations).returning('*');
  console.log(`✅ 插入了 ${insertedAnnotations.length} 个标注`);

  // Sample comments data
  const sampleComments = [
    {
      id: uuidv4(),
      annotation_id: insertedAnnotations[0].id,
      user_id: userMap['janesmith'],
      content: '我也在这个地方闻到了类似的味道，确实很刺鼻'
    },
    {
      id: uuidv4(),
      annotation_id: insertedAnnotations[1].id,
      user_id: userMap['johndoe'],
      content: 'Thanks for reporting this. I will avoid this area.'
    },
    {
      id: uuidv4(),
      annotation_id: insertedAnnotations[0].id,
      user_id: userMap['moderator'],
      content: '建议相关部门尽快处理这个问题'
    },
    {
      id: uuidv4(),
      annotation_id: insertedAnnotations[2].id,
      user_id: userMap['janesmith'],
      content: 'Is this a regular occurrence or just today?'
    },
    {
      id: uuidv4(),
      annotation_id: insertedAnnotations[1].id,
      user_id: userMap['johndoe'],
      content: '我住在附近，最近几天都有这个味道'
    }
  ];

  // 插入评论数据
  console.log('插入评论数据...');
  await knex('comments').insert(sampleComments);
  console.log(`✅ 插入了 ${sampleComments.length} 个评论`);

  console.log('🎉 种子数据插入完成！');
  console.log('');
  console.log('📋 测试账户信息:');
  console.log('   管理员: admin@smellpin.com / admin123!');
  console.log('   审核员: moderator@smellpin.com / moderator123!');
  console.log('   用户1: john.doe@example.com / password123!');
  console.log('   用户2: jane.smith@example.com / password123!');
};