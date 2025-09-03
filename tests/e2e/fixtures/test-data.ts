export const TestUsers = {
  newUser: {
    username: 'new_user_test',
    email: 'newuser@smellpin.test',
    password: 'NewUser123!',
    profile: {
      firstName: '新用户',
      lastName: '测试',
      bio: '我是一个新注册的测试用户'
    }
  },

  annotationCreator: {
    username: 'creator_pro',
    email: 'creator@smellpin.test',
    password: 'Creator123!',
    profile: {
      firstName: '创作者',
      lastName: '专业版',
      bio: '专业的气味标注创建者，致力于改善城市空气质量'
    }
  },

  rewardDiscoverer: {
    username: 'explorer_hunter',
    email: 'explorer@smellpin.test',
    password: 'Explorer123!',
    profile: {
      firstName: '探索者',
      lastName: '猎人',
      bio: '热爱探索城市中的各种气味，寻找隐藏的奖励'
    }
  },

  socialUser: {
    username: 'social_butterfly',
    email: 'social@smellpin.test',
    password: 'Social123!',
    profile: {
      firstName: '社交达人',
      lastName: '蝴蝶',
      bio: '活跃的社区成员，喜欢分享和互动'
    }
  },

  admin: {
    username: 'admin_test',
    email: 'admin@smellpin.test',
    password: 'Admin123!',
    role: 'admin'
  }
};

export const TestAnnotations = {
  pleasant: [
    {
      title: '星巴克咖啡香味',
      description: '路过星巴克时闻到的浓郁咖啡豆香味，让人精神一振',
      category: 'pleasant',
      intensity: 4,
      rewardAmount: 20,
      location: {
        name: '时代广场星巴克',
        latitude: 40.7589,
        longitude: -73.9851,
        address: '纽约时代广场1号'
      },
      tags: ['咖啡', '香味', '商业区'],
      expectedInteractions: {
        likes: 15,
        comments: 5,
        shares: 3
      }
    },
    {
      title: '中央公园花香',
      description: '春季中央公园樱花盛开时的淡雅花香',
      category: 'pleasant',
      intensity: 3,
      rewardAmount: 25,
      location: {
        name: '中央公园樱花大道',
        latitude: 40.7829,
        longitude: -73.9654,
        address: '纽约中央公园东侧'
      },
      tags: ['花香', '自然', '公园'],
      expectedInteractions: {
        likes: 25,
        comments: 8,
        shares: 6
      }
    },
    {
      title: '面包店烘焙香味',
      description: '清晨路过面包店时新鲜出炉面包的香味',
      category: 'pleasant',
      intensity: 5,
      rewardAmount: 18,
      location: {
        name: '布鲁克林面包工坊',
        latitude: 40.6892,
        longitude: -73.9442,
        address: '布鲁克林威廉堡'
      },
      tags: ['面包', '烘焙', '食物'],
      expectedInteractions: {
        likes: 20,
        comments: 7,
        shares: 4
      }
    }
  ],

  unpleasant: [
    {
      title: '地铁站异味',
      description: '地铁站内混合了汗味、尿味等多种不愉快气味',
      category: 'unpleasant',
      intensity: 4,
      rewardAmount: 30,
      location: {
        name: '时代广场地铁站',
        latitude: 40.7580,
        longitude: -73.9855,
        address: '纽约地铁N/Q/R/W线时代广场站'
      },
      tags: ['地铁', '异味', '公共交通'],
      expectedInteractions: {
        likes: 10,
        comments: 12,
        shares: 2
      }
    },
    {
      title: '垃圾处理站臭味',
      description: '垃圾处理站周围强烈的腐臭味，建议避开此区域',
      category: 'unpleasant',
      intensity: 5,
      rewardAmount: 40,
      location: {
        name: '布朗克斯垃圾处理中心',
        latitude: 40.8176,
        longitude: -73.8782,
        address: '布朗克斯垃圾处理中心附近'
      },
      tags: ['垃圾', '臭味', '环境污染'],
      expectedInteractions: {
        likes: 5,
        comments: 15,
        shares: 1
      }
    },
    {
      title: '工业区化学异味',
      description: '工业区飘出的刺鼻化学味道，疑似有害气体',
      category: 'unpleasant',
      intensity: 5,
      rewardAmount: 50,
      location: {
        name: '皇后区工业园',
        latitude: 40.7282,
        longitude: -73.7949,
        address: '皇后区长岛市工业园区'
      },
      tags: ['化学', '工业', '有害气体'],
      expectedInteractions: {
        likes: 3,
        comments: 20,
        shares: 8
      }
    }
  ],

  neutral: [
    {
      title: '汽车尾气味',
      description: '繁忙街道上常见的汽车尾气味道',
      category: 'neutral',
      intensity: 3,
      rewardAmount: 15,
      location: {
        name: '第五大道',
        latitude: 40.7614,
        longitude: -73.9776,
        address: '纽约第五大道'
      },
      tags: ['汽车', '尾气', '城市'],
      expectedInteractions: {
        likes: 8,
        comments: 4,
        shares: 1
      }
    }
  ]
};

export const TestLocations = {
  newYork: {
    city: 'New York',
    country: 'USA',
    coordinates: [
      { name: '时代广场', lat: 40.7589, lng: -73.9851 },
      { name: '中央公园', lat: 40.7829, lng: -73.9654 },
      { name: '布鲁克林大桥', lat: 40.7061, lng: -73.9969 },
      { name: '华尔街', lat: 40.7074, lng: -74.0113 },
      { name: '唐人街', lat: 40.7158, lng: -73.9970 }
    ]
  },
  beijing: {
    city: 'Beijing',
    country: 'China',
    coordinates: [
      { name: '天安门广场', lat: 39.9042, lng: 116.4074 },
      { name: '故宫', lat: 39.9163, lng: 116.3972 },
      { name: '三里屯', lat: 39.9364, lng: 116.4477 },
      { name: '王府井', lat: 39.9097, lng: 116.4167 },
      { name: '颐和园', lat: 39.9991, lng: 116.2751 }
    ]
  }
};

export const TestScenarios = {
  userJourneys: {
    newUserOnboarding: {
      name: '新用户引导流程',
      steps: [
        '访问首页',
        '注册账户',
        '邮箱验证',
        '完善资料',
        '观看新手教程',
        '创建首个标注',
        '获得首次奖励'
      ],
      expectedDuration: 180000, // 3分钟
      successCriteria: [
        '成功注册并验证邮箱',
        '完成新手教程',
        '创建至少1个标注',
        '理解奖励机制'
      ]
    },

    annotationCreation: {
      name: '标注创建流程',
      steps: [
        '登录账户',
        '进入地图页面',
        '选择位置',
        '填写标注信息',
        '上传媒体文件',
        '设置奖励金额',
        '确认支付',
        '发布标注'
      ],
      expectedDuration: 120000, // 2分钟
      successCriteria: [
        '成功创建标注',
        '支付流程完成',
        '标注在地图上显示',
        '其他用户可以发现'
      ]
    },

    rewardDiscovery: {
      name: '奖励发现流程',
      steps: [
        '登录账户',
        '开启定位',
        '浏览地图',
        '移动到标注位置',
        '进入地理围栏',
        '收到发现通知',
        '领取奖励',
        '查看钱包更新'
      ],
      expectedDuration: 90000, // 1.5分钟
      successCriteria: [
        '成功发现标注',
        '领取到奖励',
        '钱包余额正确更新',
        '防止重复领取'
      ]
    },

    socialInteraction: {
      name: '社交互动流程',
      steps: [
        '浏览他人标注',
        '点赞标注',
        '添加评论',
        '分享内容',
        '关注用户',
        '参与社区讨论',
        '查看动态流'
      ],
      expectedDuration: 150000, // 2.5分钟
      successCriteria: [
        '成功互动',
        '建立社交连接',
        '参与社区活动',
        '获得社交反馈'
      ]
    }
  },

  performanceTests: {
    loadTesting: {
      concurrent_users: [10, 50, 100, 200, 500],
      test_duration: 300, // 5分钟
      ramp_up_time: 60, // 1分钟
      endpoints: [
        '/api/annotations',
        '/api/users/profile',
        '/api/rewards/claim',
        '/api/auth/login'
      ]
    },

    stressTestScenarios: [
      {
        name: '地图高并发访问',
        concurrent_users: 1000,
        test_endpoint: '/map',
        expected_response_time: 2000
      },
      {
        name: '标注批量创建',
        concurrent_users: 100,
        test_endpoint: '/api/annotations',
        operations_per_user: 10
      },
      {
        name: '奖励批量领取',
        concurrent_users: 200,
        test_endpoint: '/api/rewards/claim',
        operations_per_user: 5
      }
    ]
  },

  errorScenarios: [
    {
      name: '网络连接中断',
      trigger: 'setOffline',
      expectedBehavior: '显示离线提示，缓存用户操作'
    },
    {
      name: '定位权限被拒绝',
      trigger: 'denyGeolocation',
      expectedBehavior: '显示权限提示，提供手动定位选项'
    },
    {
      name: '支付失败',
      trigger: 'mockPaymentFailure',
      expectedBehavior: '显示错误信息，保留用户输入的数据'
    },
    {
      name: '服务器错误',
      trigger: 'mock500Error',
      expectedBehavior: '显示友好错误页面，提供重试选项'
    }
  ]
};

export const TestData = {
  users: TestUsers,
  annotations: TestAnnotations,
  locations: TestLocations,
  scenarios: TestScenarios
};

export default TestData;