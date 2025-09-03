#!/bin/bash

# 腾讯云CloudBase部署脚本
echo "开始部署SmellPin前端到腾讯云CloudBase..."

# 检查是否安装了CloudBase CLI
if ! command -v cloudbase &> /dev/null; then
    echo "CloudBase CLI未安装，正在安装..."
    npm install -g @cloudbase/cli
fi

# 登录CloudBase（如果未登录）
echo "请确保已登录CloudBase CLI"
echo "如果未登录，请运行: cloudbase login"

# 构建项目
echo "构建前端项目..."
npm run build

if [ $? -ne 0 ]; then
    echo "构建失败，请检查错误信息"
    exit 1
fi

# 部署到CloudBase
echo "部署到CloudBase..."
cloudbase framework deploy

if [ $? -eq 0 ]; then
    echo "部署成功！"
    echo "请在CloudBase控制台查看部署状态和访问地址"
else
    echo "部署失败，请检查错误信息"
    exit 1
fi