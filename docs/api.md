# SmellPin API 文档

## 目录
- [API 概览](#api-概览)
- [认证授权](#认证授权)
- [用户管理](#用户管理)
- [标注管理](#标注管理)
- [LBS 服务](#lbs-服务)
- [支付系统](#支付系统)
- [文件上传](#文件上传)
- [系统接口](#系统接口)
- [错误处理](#错误处理)

## API 概览

### 基础信息
- **Base URL**: `https://api.smellpin.com/api/v1`
- **协议**: HTTPS
- **数据格式**: JSON
- **字符编码**: UTF-8
- **时区**: UTC

### 通用响应格式
```json
{
  "code": 200,
  "message": "Success",
  "data": {},
  "timestamp": "2024-12-20T10:30:00Z",
  "requestId": "req_123456789"
}
```

### HTTP 状态码
- `200` - 成功
- `201` - 创建成功
- `400` - 请求参数错误
- `401` - 未授权
- `403` - 禁止访问
- `404` - 资源不存在
- `429` - 请求过于频繁
- `500` - 服务器内部错误

## 认证授权

### 1. 发送验证码

**POST** `/auth/send-code`

发送手机验证码用于登录或注册。

**请求参数**:
```json
{
  "phone": "13800138000",
  "type": "login"
}
```

**参数说明**:
- `phone` (string, required): 手机号码
- `type` (string, required): 验证码类型，可选值: `login`, `register`, `reset`

**响应示例**:
```json
{
  "code": 200,
  "message": "验证码发送成功",
  "data": {
    "expires_in": 300,
    "retry_after": 60
  }
}
```

### 2. 用户登录

**POST** `/auth/login`

使用手机号和验证码登录。

**请求参数**:
```json
{
  "phone": "13800138000",
  "code": "123456"
}
```

**响应示例**:
```json
{
  "code": 200,
  "message": "登录成功",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 604800,
    "user": {
      "id": "user_123",
      "phone": "13800138000",
      "nickname": "用户123",
      "avatar": "https://cdn.smellpin.com/avatars/default.png",
      "level": 1,
      "balance": 0.00,
      "created_at": "2024-01-01T00:00:00Z"
    }
  }
}
```

### 3. 刷新令牌

**POST** `/auth/refresh`

使用刷新令牌获取新的访问令牌。

**请求头**:
```
Authorization: Bearer <refresh_token>
```

**响应示例**:
```json
{
  "code": 200,
  "message": "令牌刷新成功",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 604800
  }
}
```

### 4. 用户登出

**POST** `/auth/logout`

登出当前用户，使令牌失效。

**请求头**:
```
Authorization: Bearer <access_token>
```

**响应示例**:
```json
{
  "code": 200,
  "message": "登出成功"
}
```

## 用户管理

### 1. 获取用户信息

**GET** `/users/profile`

获取当前用户的详细信息。

**请求头**:
```
Authorization: Bearer <access_token>
```

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "id": "user_123",
    "phone": "13800138000",
    "nickname": "用户123",
    "avatar": "https://cdn.smellpin.com/avatars/user_123.jpg",
    "gender": "male",
    "birthday": "1990-01-01",
    "level": 3,
    "experience": 1500,
    "balance": 128.50,
    "total_earnings": 256.80,
    "total_spent": 128.30,
    "annotations_count": 25,
    "discoveries_count": 48,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-12-20T10:30:00Z"
  }
}
```

### 2. 更新用户信息

**PUT** `/users/profile`

更新用户资料信息。

**请求参数**:
```json
{
  "nickname": "新昵称",
  "gender": "female",
  "birthday": "1995-06-15",
  "avatar": "https://cdn.smellpin.com/avatars/new_avatar.jpg"
}
```

**响应示例**:
```json
{
  "code": 200,
  "message": "更新成功",
  "data": {
    "id": "user_123",
    "nickname": "新昵称",
    "gender": "female",
    "birthday": "1995-06-15",
    "avatar": "https://cdn.smellpin.com/avatars/new_avatar.jpg",
    "updated_at": "2024-12-20T10:35:00Z"
  }
}
```

### 3. 获取用户统计

**GET** `/users/stats`

获取用户的统计数据。

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "today": {
      "annotations": 3,
      "discoveries": 5,
      "earnings": 12.50
    },
    "this_week": {
      "annotations": 15,
      "discoveries": 28,
      "earnings": 68.20
    },
    "this_month": {
      "annotations": 45,
      "discoveries": 89,
      "earnings": 256.80
    },
    "rank": {
      "level": 3,
      "current_exp": 1500,
      "next_level_exp": 2000,
      "progress": 0.75
    }
  }
}
```

## 标注管理

### 1. 创建标注

**POST** `/annotations`

在指定位置创建新的恶搞标注。

**请求参数**:
```json
{
  "title": "搞笑标注标题",
  "content": "这里有个很有趣的地方...",
  "location": {
    "latitude": 39.9042,
    "longitude": 116.4074,
    "address": "北京市朝阳区"
  },
  "amount": 10.00,
  "category": "funny",
  "tags": ["搞笑", "有趣"],
  "images": [
    "https://cdn.smellpin.com/images/img1.jpg",
    "https://cdn.smellpin.com/images/img2.jpg"
  ],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

**参数说明**:
- `title` (string, required): 标注标题，最长50字符
- `content` (string, required): 标注内容，最长500字符
- `location` (object, required): 位置信息
  - `latitude` (number, required): 纬度
  - `longitude` (number, required): 经度
  - `address` (string, optional): 地址描述
- `amount` (number, required): 奖励金额，最小0.01，最大1000
- `category` (string, required): 分类，可选值: `funny`, `weird`, `scary`, `romantic`
- `tags` (array, optional): 标签数组，最多5个
- `images` (array, optional): 图片URL数组，最多9张
- `expires_at` (string, optional): 过期时间，默认30天后

**响应示例**:
```json
{
  "code": 201,
  "message": "标注创建成功",
  "data": {
    "id": "ann_123456",
    "title": "搞笑标注标题",
    "content": "这里有个很有趣的地方...",
    "location": {
      "latitude": 39.9042,
      "longitude": 116.4074,
      "address": "北京市朝阳区"
    },
    "amount": 10.00,
    "remaining_amount": 10.00,
    "category": "funny",
    "tags": ["搞笑", "有趣"],
    "images": [
      "https://cdn.smellpin.com/images/img1.jpg",
      "https://cdn.smellpin.com/images/img2.jpg"
    ],
    "status": "active",
    "creator": {
      "id": "user_123",
      "nickname": "用户123",
      "avatar": "https://cdn.smellpin.com/avatars/user_123.jpg"
    },
    "discovery_count": 0,
    "like_count": 0,
    "created_at": "2024-12-20T10:30:00Z",
    "expires_at": "2024-12-31T23:59:59Z"
  }
}
```

### 2. 获取标注列表

**GET** `/annotations`

获取标注列表，支持分页和筛选。

**查询参数**:
- `page` (number, optional): 页码，默认1
- `limit` (number, optional): 每页数量，默认20，最大100
- `category` (string, optional): 分类筛选
- `status` (string, optional): 状态筛选，可选值: `active`, `expired`, `completed`
- `creator_id` (string, optional): 创建者ID筛选
- `sort` (string, optional): 排序方式，可选值: `created_at`, `amount`, `discovery_count`
- `order` (string, optional): 排序顺序，可选值: `asc`, `desc`

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "items": [
      {
        "id": "ann_123456",
        "title": "搞笑标注标题",
        "content": "这里有个很有趣的地方...",
        "location": {
          "latitude": 39.9042,
          "longitude": 116.4074,
          "address": "北京市朝阳区"
        },
        "amount": 10.00,
        "remaining_amount": 7.50,
        "category": "funny",
        "tags": ["搞笑", "有趣"],
        "images": ["https://cdn.smellpin.com/images/img1.jpg"],
        "status": "active",
        "creator": {
          "id": "user_123",
          "nickname": "用户123",
          "avatar": "https://cdn.smellpin.com/avatars/user_123.jpg"
        },
        "discovery_count": 3,
        "like_count": 15,
        "created_at": "2024-12-20T10:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 156,
      "pages": 8
    }
  }
}
```

### 3. 获取标注详情

**GET** `/annotations/{id}`

获取指定标注的详细信息。

**路径参数**:
- `id` (string, required): 标注ID

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "id": "ann_123456",
    "title": "搞笑标注标题",
    "content": "这里有个很有趣的地方...",
    "location": {
      "latitude": 39.9042,
      "longitude": 116.4074,
      "address": "北京市朝阳区"
    },
    "amount": 10.00,
    "remaining_amount": 7.50,
    "category": "funny",
    "tags": ["搞笑", "有趣"],
    "images": [
      "https://cdn.smellpin.com/images/img1.jpg",
      "https://cdn.smellpin.com/images/img2.jpg"
    ],
    "status": "active",
    "creator": {
      "id": "user_123",
      "nickname": "用户123",
      "avatar": "https://cdn.smellpin.com/avatars/user_123.jpg",
      "level": 3
    },
    "discovery_count": 3,
    "like_count": 15,
    "comment_count": 8,
    "created_at": "2024-12-20T10:30:00Z",
    "updated_at": "2024-12-20T15:20:00Z",
    "expires_at": "2024-12-31T23:59:59Z",
    "recent_discoveries": [
      {
        "user": {
          "id": "user_456",
          "nickname": "发现者1",
          "avatar": "https://cdn.smellpin.com/avatars/user_456.jpg"
        },
        "reward": 2.50,
        "discovered_at": "2024-12-20T14:30:00Z"
      }
    ]
  }
}
```

### 4. 点赞标注

**POST** `/annotations/{id}/like`

对标注进行点赞或取消点赞。

**响应示例**:
```json
{
  "code": 200,
  "message": "点赞成功",
  "data": {
    "liked": true,
    "like_count": 16
  }
}
```

### 5. 举报标注

**POST** `/annotations/{id}/report`

举报不当标注。

**请求参数**:
```json
{
  "reason": "inappropriate_content",
  "description": "内容不当，包含违规信息"
}
```

**参数说明**:
- `reason` (string, required): 举报原因，可选值: `inappropriate_content`, `spam`, `fake_location`, `harassment`
- `description` (string, optional): 详细描述

**响应示例**:
```json
{
  "code": 200,
  "message": "举报提交成功，我们会尽快处理"
}
```

## LBS 服务

### 1. 发现附近标注

**GET** `/lbs/nearby`

根据当前位置发现附近的标注。

**查询参数**:
- `latitude` (number, required): 当前纬度
- `longitude` (number, required): 当前经度
- `radius` (number, optional): 搜索半径（米），默认1000，最大5000
- `limit` (number, optional): 返回数量，默认20，最大50

**响应示例**:
```json
{
  "code": 200,
  "message": "发现成功",
  "data": {
    "items": [
      {
        "id": "ann_123456",
        "title": "搞笑标注标题",
        "category": "funny",
        "amount": 10.00,
        "remaining_amount": 7.50,
        "distance": 150.5,
        "location": {
          "latitude": 39.9042,
          "longitude": 116.4074
        },
        "creator": {
          "nickname": "用户123",
          "avatar": "https://cdn.smellpin.com/avatars/user_123.jpg"
        },
        "created_at": "2024-12-20T10:30:00Z"
      }
    ],
    "total": 5
  }
}
```

### 2. 领取奖励

**POST** `/lbs/claim`

在指定位置领取标注奖励。

**请求参数**:
```json
{
  "annotation_id": "ann_123456",
  "location": {
    "latitude": 39.9042,
    "longitude": 116.4074,
    "accuracy": 10.5
  }
}
```

**参数说明**:
- `annotation_id` (string, required): 标注ID
- `location` (object, required): 当前位置
  - `latitude` (number, required): 纬度
  - `longitude` (number, required): 经度
  - `accuracy` (number, optional): GPS精度（米）

**响应示例**:
```json
{
  "code": 200,
  "message": "奖励领取成功",
  "data": {
    "reward_id": "reward_789",
    "annotation_id": "ann_123456",
    "amount": 2.50,
    "balance": 131.00,
    "experience": 10,
    "claimed_at": "2024-12-20T15:30:00Z"
  }
}
```

### 3. 获取发现历史

**GET** `/lbs/discoveries`

获取用户的发现历史记录。

**查询参数**:
- `page` (number, optional): 页码，默认1
- `limit` (number, optional): 每页数量，默认20
- `start_date` (string, optional): 开始日期，格式: YYYY-MM-DD
- `end_date` (string, optional): 结束日期，格式: YYYY-MM-DD

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "items": [
      {
        "id": "discovery_456",
        "annotation": {
          "id": "ann_123456",
          "title": "搞笑标注标题",
          "category": "funny"
        },
        "reward": 2.50,
        "location": {
          "latitude": 39.9042,
          "longitude": 116.4074,
          "address": "北京市朝阳区"
        },
        "discovered_at": "2024-12-20T15:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 48,
      "pages": 3
    },
    "summary": {
      "total_discoveries": 48,
      "total_rewards": 128.50,
      "this_month": {
        "discoveries": 15,
        "rewards": 42.30
      }
    }
  }
}
```

## 支付系统

### 1. 创建充值订单

**POST** `/payments/recharge`

创建充值订单。

**请求参数**:
```json
{
  "amount": 100.00,
  "payment_method": "alipay"
}
```

**参数说明**:
- `amount` (number, required): 充值金额，最小1元，最大10000元
- `payment_method` (string, required): 支付方式，可选值: `alipay`, `wechat`, `paypal`

**响应示例**:
```json
{
  "code": 200,
  "message": "订单创建成功",
  "data": {
    "order_id": "order_123456",
    "amount": 100.00,
    "payment_method": "alipay",
    "payment_url": "https://openapi.alipay.com/gateway.do?...",
    "qr_code": "https://api.smellpin.com/payments/qr/order_123456",
    "expires_at": "2024-12-20T16:30:00Z",
    "created_at": "2024-12-20T15:30:00Z"
  }
}
```

### 2. 查询订单状态

**GET** `/payments/orders/{order_id}`

查询支付订单状态。

**响应示例**:
```json
{
  "code": 200,
  "message": "查询成功",
  "data": {
    "order_id": "order_123456",
    "type": "recharge",
    "amount": 100.00,
    "status": "paid",
    "payment_method": "alipay",
    "transaction_id": "2024122015300012345",
    "created_at": "2024-12-20T15:30:00Z",
    "paid_at": "2024-12-20T15:32:15Z"
  }
}
```

### 3. 申请提现

**POST** `/payments/withdraw`

申请提现到支付宝或银行卡。

**请求参数**:
```json
{
  "amount": 50.00,
  "method": "alipay",
  "account": "user@example.com",
  "real_name": "张三"
}
```

**参数说明**:
- `amount` (number, required): 提现金额，最小10元
- `method` (string, required): 提现方式，可选值: `alipay`, `bank_card`
- `account` (string, required): 账户信息（支付宝账号或银行卡号）
- `real_name` (string, required): 真实姓名

**响应示例**:
```json
{
  "code": 200,
  "message": "提现申请提交成功",
  "data": {
    "withdraw_id": "withdraw_789",
    "amount": 50.00,
    "fee": 2.00,
    "actual_amount": 48.00,
    "method": "alipay",
    "status": "pending",
    "estimated_arrival": "2024-12-21T15:30:00Z",
    "created_at": "2024-12-20T15:30:00Z"
  }
}
```

### 4. 获取交易记录

**GET** `/payments/transactions`

获取用户的交易记录。

**查询参数**:
- `page` (number, optional): 页码，默认1
- `limit` (number, optional): 每页数量，默认20
- `type` (string, optional): 交易类型，可选值: `recharge`, `withdraw`, `reward`, `payment`
- `status` (string, optional): 状态筛选
- `start_date` (string, optional): 开始日期
- `end_date` (string, optional): 结束日期

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "items": [
      {
        "id": "txn_123456",
        "type": "reward",
        "amount": 2.50,
        "balance_after": 131.00,
        "description": "发现标注奖励",
        "status": "completed",
        "related_id": "ann_123456",
        "created_at": "2024-12-20T15:30:00Z"
      },
      {
        "id": "txn_123455",
        "type": "payment",
        "amount": -10.00,
        "balance_after": 128.50,
        "description": "创建标注支付",
        "status": "completed",
        "related_id": "ann_123456",
        "created_at": "2024-12-20T10:30:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 156,
      "pages": 8
    },
    "summary": {
      "total_income": 256.80,
      "total_expense": 128.30,
      "current_balance": 131.00
    }
  }
}
```

## 文件上传

### 1. 获取上传凭证

**POST** `/upload/token`

获取文件上传凭证。

**请求参数**:
```json
{
  "file_type": "image",
  "file_size": 1024000,
  "file_name": "photo.jpg"
}
```

**参数说明**:
- `file_type` (string, required): 文件类型，可选值: `image`, `video`, `audio`
- `file_size` (number, required): 文件大小（字节）
- `file_name` (string, required): 文件名

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "upload_url": "https://oss.aliyuncs.com/smellpin-files",
    "file_key": "images/2024/12/20/uuid_photo.jpg",
    "access_url": "https://cdn.smellpin.com/images/2024/12/20/uuid_photo.jpg",
    "policy": "eyJleHBpcmF0aW9uIjoiMjAyNC0xMi0yMFQxNjozMDowMFoiLCJjb25kaXRpb25zIjpbWyJjb250ZW50LWxlbmd0aC1yYW5nZSIsMCwxMDQ4NTc2XV19",
    "signature": "signature_string",
    "expires_at": "2024-12-20T16:30:00Z"
  }
}
```

### 2. 上传完成通知

**POST** `/upload/complete`

通知服务器文件上传完成。

**请求参数**:
```json
{
  "file_key": "images/2024/12/20/uuid_photo.jpg",
  "file_size": 1024000,
  "file_hash": "md5_hash_string"
}
```

**响应示例**:
```json
{
  "code": 200,
  "message": "上传完成",
  "data": {
    "file_id": "file_123456",
    "access_url": "https://cdn.smellpin.com/images/2024/12/20/uuid_photo.jpg",
    "thumbnail_url": "https://cdn.smellpin.com/images/2024/12/20/uuid_photo_thumb.jpg"
  }
}
```

## 系统接口

### 1. 健康检查

**GET** `/health`

检查系统健康状态。

**响应示例**:
```json
{
  "code": 200,
  "message": "系统正常",
  "data": {
    "status": "healthy",
    "timestamp": "2024-12-20T15:30:00Z",
    "version": "1.0.0",
    "uptime": 86400,
    "services": {
      "database": "healthy",
      "redis": "healthy",
      "storage": "healthy"
    }
  }
}
```

### 2. 系统信息

**GET** `/health/info`

获取系统详细信息。

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "app": {
      "name": "SmellPin API",
      "version": "1.0.0",
      "environment": "production"
    },
    "system": {
      "node_version": "20.10.0",
      "platform": "linux",
      "memory_usage": {
        "used": 256,
        "total": 1024
      },
      "cpu_usage": 15.5
    },
    "database": {
      "type": "postgresql",
      "version": "15.4",
      "connections": {
        "active": 5,
        "idle": 3,
        "max": 20
      }
    }
  }
}
```

### 3. 获取配置

**GET** `/config`

获取客户端配置信息。

**响应示例**:
```json
{
  "code": 200,
  "message": "获取成功",
  "data": {
    "app": {
      "name": "SmellPin",
      "version": "1.0.0",
      "min_version": "1.0.0"
    },
    "features": {
      "social_login": true,
      "push_notifications": true,
      "ai_moderation": false
    },
    "limits": {
      "max_annotations_per_day": 10,
      "max_image_size": 5242880,
      "max_images_per_annotation": 9,
      "min_withdrawal_amount": 10,
      "max_withdrawal_amount": 10000
    },
    "payment": {
      "methods": ["alipay", "wechat", "paypal"],
      "min_recharge": 1,
      "max_recharge": 10000,
      "withdrawal_fee_rate": 0.02
    },
    "lbs": {
      "default_radius": 1000,
      "max_radius": 5000,
      "reward_percentage": 0.7
    }
  }
}
```

## 错误处理

### 错误响应格式
```json
{
  "code": 400,
  "message": "请求参数错误",
  "error": {
    "type": "VALIDATION_ERROR",
    "details": [
      {
        "field": "phone",
        "message": "手机号格式不正确"
      }
    ]
  },
  "timestamp": "2024-12-20T15:30:00Z",
  "requestId": "req_123456789"
}
```

### 常见错误码

| 错误码 | 错误类型 | 描述 |
|--------|----------|------|
| 1001 | VALIDATION_ERROR | 参数验证失败 |
| 1002 | AUTHENTICATION_FAILED | 认证失败 |
| 1003 | AUTHORIZATION_FAILED | 权限不足 |
| 1004 | RESOURCE_NOT_FOUND | 资源不存在 |
| 1005 | DUPLICATE_RESOURCE | 资源重复 |
| 1006 | RATE_LIMIT_EXCEEDED | 请求频率超限 |
| 1007 | INSUFFICIENT_BALANCE | 余额不足 |
| 1008 | LOCATION_TOO_FAR | 位置距离过远 |
| 1009 | ALREADY_CLAIMED | 奖励已领取 |
| 1010 | CONTENT_MODERATION_FAILED | 内容审核失败 |
| 2001 | DATABASE_ERROR | 数据库错误 |
| 2002 | EXTERNAL_SERVICE_ERROR | 外部服务错误 |
| 2003 | FILE_UPLOAD_ERROR | 文件上传错误 |
| 5000 | INTERNAL_SERVER_ERROR | 服务器内部错误 |

### 限流说明

| 接口类型 | 限制 | 时间窗口 |
|----------|------|----------|
| 发送验证码 | 5次 | 1小时 |
| 登录 | 10次 | 15分钟 |
| 创建标注 | 10次 | 1天 |
| 领取奖励 | 100次 | 1小时 |
| 文件上传 | 50次 | 1小时 |
| 其他接口 | 1000次 | 1小时 |

---

**文档版本**: v1.0  
**最后更新**: 2024年12月  
**维护责任人**: API团队  
**技术支持**: api@smellpin.com