# 多阶段构建 Dockerfile
# 阶段1: 构建阶段
FROM node:20-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制package文件
COPY package*.json ./
COPY tsconfig.json ./

# 安装依赖
RUN npm ci --only=production && npm cache clean --force

# 复制源代码
COPY src/ ./src/
COPY public/ ./public/

# 构建应用
RUN npm run build

# 阶段2: 运行阶段
FROM node:20-alpine AS runtime

# 安装必要的系统依赖
RUN apk add --no-cache \
    curl \
    jq \
    tzdata \
    && rm -rf /var/cache/apk/*

# 设