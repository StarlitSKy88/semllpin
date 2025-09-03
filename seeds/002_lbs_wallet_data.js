const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.seed = async function(knex) {
  console.log('开始插入LBS和钱包种子数据...');

  // 获取现有用户
  const users = await knex('users').select('id', 'username');
  if (users.length === 0) {
    console.log('⚠️  请先运行基础用户种子数据');
    return;
  }

  const userMap = {};
  users.forEach(user => {
    userMap[user.username] = user.id;
  });

  // 清空相关表数据
  await knex('lbs_rewards').del().catch(() => {});
  await knex('wallets').del().catch(() => {});
  await knex('transactions').del().catch(() => {});
  await knex('user_locations').del().catch(() => {});
  await knex('checkin_records').del().catch(() => {});
  await knex('reward_records').del().catch(() => {});

  // 创建钱包数据
  console.log('插入钱包数据...');
  const walletData = [];
  for (const user of users) {
    walletData.push({
      id: uuidv4(),
      user_id: user.id,
      balance: Math.random() * 1000, // 随机余额 0-1000
      frozen_balance: 0.00,
      currency: 'USD',
      status: 'active'
    });
  }
  await knex('wallets').insert(walletData);
  console.log(`✅ 插入了 ${walletData.length} 个钱包`);

  // 创建用户位置数据
  console.log('插入用户位置数据...');
  const locationData = [
    {
      id: uuidv4(),
      user_id: userMap['johndoe'],
      latitude: 39.9042,
      longitude: 116.4074,
      address: '北京市东城区天安门广场',
      place_name: '天安门广场',
      location_type: 'checkin',
      accuracy: 5.0,
      is_current: true
    },
    {
      id: uuidv4(),
      user_id: userMap['janesmith'],
      latitude: 31.2304,
      longitude: 121.4737,
      address: '上海市黄浦区外滩',
      place_name: '外滩',
      location_type: 'checkin',
      accuracy: 3.0,
      is_current: true
    },
    {
      id: uuidv4(),
      user_id: userMap['johndoe'],
      latitude: 40.7128,
      longitude: -74.0060,
      address: 'Times Square, New York, NY',
      place_name: 'Times Square',
      location_type: 'manual',
      accuracy: 10.0,
      is_current: false
    }
  ];
  await knex('user_locations').insert(locationData).catch(() => {});
  console.log(`✅ 插入了 ${locationData.length} 个用户位置`);

  // 创建签到记录
  console.log('插入签到记录...');
  const checkinData = [
    {
      id: uuidv4(),
      user_id: userMap['johndoe'],
      latitude: 39.9042,
      longitude: 116.4074,
      location_id: locationData[0].id,
      accuracy: 5.0,
      stay_duration: 1800, // 30分钟
      consecutive_days: 3,
      is_first_time: false,
      weather_condition: 'sunny',
      temperature: 25.5,
      notes: '天气不错，空气质量一般'
    },
    {
      id: uuidv4(),
      user_id: userMap['janesmith'],
      latitude: 31.2304,
      longitude: 121.4737,
      location_id: locationData[1].id,
      accuracy: 3.0,
      stay_duration: 2400, // 40分钟
      consecutive_days: 1,
      is_first_time: true,
      weather_condition: 'cloudy',
      temperature: 22.0,
      notes: '第一次在这里签到'
    }
  ];
  await knex('checkin_records').insert(checkinData).catch(() => {});
  console.log(`✅ 插入了 ${checkinData.length} 个签到记录`);

  // 创建奖励记录
  console.log('插入奖励记录...');
  const rewardData = [
    {
      id: uuidv4(),
      user_id: parseInt(userMap['johndoe'].replace(/-/g, '').substring(0, 8), 16), // 转换为整数
      reward_type: 'checkin',
      reward_category: 'daily_checkin',
      points: 100,
      coins: 10.0,
      cash_value: 1.0,
      description: '每日签到奖励',
      source_id: checkinData[0].id,
      source_type: 'checkin',
      location_id: locationData[0].id
    },
    {
      id: uuidv4(),
      user_id: parseInt(userMap['janesmith'].replace(/-/g, '').substring(0, 8), 16),
      reward_type: 'exploration',
      reward_category: 'first_visit',
      points: 200,
      coins: 25.0,
      cash_value: 2.5,
      description: '首次探索奖励',
      source_id: checkinData[1].id,
      source_type: 'checkin',
      location_id: locationData[1].id
    },
    {
      id: uuidv4(),
      user_id: parseInt(userMap['johndoe'].replace(/-/g, '').substring(0, 8), 16),
      reward_type: 'annotation',
      reward_category: 'create_annotation',
      points: 150,
      coins: 15.0,
      cash_value: 1.5,
      description: '创建标注奖励',
      source_type: 'annotation'
    }
  ];
  await knex('reward_records').insert(rewardData).catch(() => {});
  console.log(`✅ 插入了 ${rewardData.length} 个奖励记录`);

  // 创建交易记录
  console.log('插入交易记录...');
  const wallets = await knex('wallets').select('id', 'user_id');
  const walletMap = {};
  wallets.forEach(wallet => {
    walletMap[wallet.user_id] = wallet.id;
  });

  const transactionData = [
    {
      id: uuidv4(),
      user_id: userMap['johndoe'],
      wallet_id: walletMap[userMap['johndoe']],
      type: 'reward',
      amount: 1.0,
      balance_before: 100.0,
      balance_after: 101.0,
      status: 'completed',
      description: '签到奖励',
      reference_type: 'reward',
      metadata: JSON.stringify({
        reward_id: rewardData[0].id,
        reward_type: 'checkin'
      })
    },
    {
      id: uuidv4(),
      user_id: userMap['janesmith'],
      wallet_id: walletMap[userMap['janesmith']],
      type: 'reward',
      amount: 2.5,
      balance_before: 200.0,
      balance_after: 202.5,
      status: 'completed',
      description: '首次探索奖励',
      reference_type: 'reward',
      metadata: JSON.stringify({
        reward_id: rewardData[1].id,
        reward_type: 'exploration'
      })
    },
    {
      id: uuidv4(),
      user_id: userMap['johndoe'],
      wallet_id: walletMap[userMap['johndoe']],
      type: 'payment',
      amount: -5.0,
      balance_before: 101.0,
      balance_after: 96.0,
      status: 'completed',
      description: '创建付费标注',
      reference_type: 'annotation',
      metadata: JSON.stringify({
        annotation_fee: true
      })
    }
  ];
  await knex('transactions').insert(transactionData);
  console.log(`✅ 插入了 ${transactionData.length} 个交易记录`);

  // 创建LBS奖励记录（如果表存在）
  try {
    const lbsRewardData = [
      {
        id: uuidv4(),
        user_id: userMap['johndoe'],
        annotation_id: null, // 需要从annotations表获取
        reward_amount: 1.0,
        latitude: 39.9042,
        longitude: 116.4074,
        distance_to_annotation: 50.0,
        reward_type: 'proximity',
        status: 'paid',
        discovered_at: new Date(),
        paid_at: new Date()
      },
      {
        id: uuidv4(),
        user_id: userMap['janesmith'],
        annotation_id: null,
        reward_amount: 2.0,
        latitude: 31.2304,
        longitude: 121.4737,
        distance_to_annotation: 25.0,
        reward_type: 'proximity',
        status: 'paid',
        discovered_at: new Date(),
        paid_at: new Date()
      }
    ];
    
    // 获取标注ID
    const annotations = await knex('annotations').select('id').limit(2);
    if (annotations.length >= 2) {
      lbsRewardData[0].annotation_id = annotations[0].id;
      lbsRewardData[1].annotation_id = annotations[1].id;
    }
    
    await knex('lbs_rewards').insert(lbsRewardData);
    console.log(`✅ 插入了 ${lbsRewardData.length} 个LBS奖励记录`);
  } catch (error) {
    console.log('⚠️  LBS奖励表不存在，跳过插入');
  }

  console.log('🎉 LBS和钱包种子数据插入完成！');
  console.log('');
  console.log('📊 数据统计:');
  console.log(`   钱包: ${walletData.length} 个`);
  console.log(`   用户位置: ${locationData.length} 个`);
  console.log(`   签到记录: ${checkinData.length} 个`);
  console.log(`   奖励记录: ${rewardData.length} 个`);
  console.log(`   交易记录: ${transactionData.length} 个`);
};