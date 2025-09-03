#!/bin/bash
# SmellPin测试环境设置脚本 - 自动化测试方案2.0

set -e

echo "🚀 启动SmellPin测试环境..."

# 检查Docker是否运行
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker未运行，请先启动Docker"
    exit 1
fi

# 检查docker-compose是否可用
if ! command -v docker-compose >/dev/null 2>&1; then
    echo "❌ docker-compose未安装"
    exit 1
fi

# 停止现有测试容器
echo "🛑 停止现有测试容器..."
docker-compose -f docker-compose.test.yml down -v 2>/dev/null || true

# 清理旧的测试数据
echo "🧹 清理旧的测试数据..."
rm -rf tests/temp/* 2>/dev/null || true
mkdir -p tests/temp/uploads

# 启动测试服务
echo "🔧 启动测试服务..."
docker-compose -f docker-compose.test.yml up -d

# 等待服务就绪
echo "⏳ 等待服务启动..."
sleep 15

# 检查服务健康状态
echo "🔍 检查服务健康状态..."

# PostgreSQL
if docker-compose -f docker-compose.test.yml exec -T postgres-test pg_isready -U test -d smellpin_test >/dev/null 2>&1; then
    echo "✅ PostgreSQL测试数据库已就绪"
else
    echo "❌ PostgreSQL测试数据库未就绪"
    exit 1
fi

# Redis
if docker-compose -f docker-compose.test.yml exec -T redis-test redis-cli ping >/dev/null 2>&1; then
    echo "✅ Redis测试缓存已就绪"
else
    echo "❌ Redis测试缓存未就绪"
    exit 1
fi

# 运行数据库迁移
echo "🗄️ 运行数据库迁移..."
if [ -f "package.json" ]; then
    NODE_ENV=test npm run migrate 2>/dev/null || echo "⚠️ 迁移可能已完成或不需要"
fi

echo "🎉 测试环境设置完成！"
echo ""
echo "📊 服务访问信息："
echo "   PostgreSQL: localhost:5433 (test/test)"
echo "   Redis: localhost:6380"
echo "   MinIO: http://localhost:9001 (test/testpassword)"
echo "   MailHog: http://localhost:8026"
echo "   Prometheus: http://localhost:9091"
echo ""
echo "🧪 运行测试命令："
echo "   npm test                    # 运行所有测试"
echo "   npm run test:parallel       # 运行并行测试"
echo "   npm run test:integration    # 运行集成测试"
echo "   npm run test:e2e           # 运行E2E测试"
echo ""
echo "🛑 停止测试环境："
echo "   ./scripts/test-teardown.sh"