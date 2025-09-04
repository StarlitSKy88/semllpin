# 多阶段构建 Dockerfile
# 阶段1: 构建阶段
FROM node:20-alpine AS builder

# 设置工作目录
WORKDIR /app

# 复制package文件
COPY package*.json ./
COPY tsconfig.json ./

# 安装所有依赖 (包括devDependencies)
RUN npm ci && npm cache clean --force

# 复制源代码
COPY src/ ./src/

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

# 设置时区
ENV TZ=Asia/Shanghai

# 创建非root用户
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# 设置工作目录
WORKDIR /app

# 复制package文件并安装生产依赖
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# 从构建阶段复制编译后的代码
COPY --from=builder --chown=nextjs:nodejs /app/dist ./dist

# 复制路径注册文件
COPY --chown=nextjs:nodejs register-paths.js ./

# 复制其他必要的配置文件
COPY --chown=nextjs:nodejs tsconfig.json ./

# 创建日志目录
RUN mkdir -p logs && chown -R nextjs:nodejs logs

# 切换到非root用户
USER nextjs

# 暴露端口
EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# 启动应用
CMD ["npm", "start"]