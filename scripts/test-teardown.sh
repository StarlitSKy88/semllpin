#!/bin/bash
# SmellPin测试环境清理脚本

set -e

echo "🛑 停止SmellPin测试环境..."

# 停止测试容器
echo "📦 停止测试容器..."
docker-compose -f docker-compose.test.yml down

# 选择性清理数据卷
read -p "是否清理测试数据卷？(y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🗑️ 清理测试数据卷..."
    docker-compose -f docker-compose.test.yml down -v
    docker volume prune -f
fi

# 清理临时文件
echo "🧹 清理临时测试文件..."
rm -rf tests/temp/* 2>/dev/null || true
rm -rf test-results/* 2>/dev/null || true
rm -rf coverage/* 2>/dev/null || true

echo "✅ 测试环境清理完成！"