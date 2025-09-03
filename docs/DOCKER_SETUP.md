# Docker 安装和配置指南

本文档提供了在 macOS 上安装和配置 Docker 的详细指南，以及不使用 Docker 的替代方案。

## 方案一：安装 Docker Desktop（推荐）

### 1. 手动下载安装

1. 访问 [Docker Desktop 官网](https://www.docker.com/products/docker-desktop)
2. 下载适用于 macOS 的 Docker Desktop
3. 安装并启动 Docker Desktop
4. 等待 Docker 完全启动（状态栏显示绿色）

### 2. 使用 Homebrew 安装

```bash
# 安装 Docker Desktop
brew install --cask docker

# 启动 Docker Desktop 应用
open /Applications/Docker.app
```

## 方案二：使用 Colima（轻量级替代方案）

Colima 是一个轻量级的 Docker 运行时，适合开发环境使用。

### 安装步骤

```bash
# 安装 Colima 和 Docker CLI
brew install colima docker docker-compose

# 启动 Colima
colima start

# 验证安装
docker --version
docker info
```

### Colima 常用命令

```bash
# 启动 Colima
colima start

# 停止 Colima
colima stop

# 查看状态
colima status

# 重启 Colima
colima restart
```

## 方案三：开发模式（不使用 Docker）

如果您不想安装 Docker，可以使用开发模式直接运行项目。

### 系统要求

- Node.js 18+ 
- npm 或 yarn
- SQLite（自动创建）

### 启动开发模式

```bash
# 使用部署脚本启动开发模式
./scripts/deploy.sh dev

# 或者手动启动
npm install
cd frontend && npm install && cd ..
npm run migrate

# 启动后端服务
npm run dev

# 在新终端启动前端服务
cd frontend && npm run dev
```

### 开发模式特点

- ✅ 无需 Docker 环境
- ✅ 使用 SQLite 数据库
- ✅ 热重载开发
- ✅ 快速启动
- ❌ 不包含生产环境特性（Redis、监控等）
- ❌ 不适合生产部署

## 验证 Docker 安装

安装完成后，运行以下命令验证：

```bash
# 检查 Docker 版本
docker --version

# 检查 Docker Compose 版本
docker-compose --version

# 检查 Docker 是否运行
docker info

# 运行测试容器
docker run hello-world
```

## 常见问题

### 1. Docker Desktop 启动缓慢

- 确保有足够的系统资源
- 在 Docker Desktop 设置中调整资源分配
- 重启 Docker Desktop

### 2. Colima 下载失败

```bash
# 使用代理或更换网络
export HTTPS_PROXY=your-proxy-url
colima start

# 或者手动下载镜像
colima start --vm-type=qemu
```

### 3. 权限问题

```bash
# 将用户添加到 docker 组（Linux/WSL）
sudo usermod -aG docker $USER

# 重新登录或重启终端
```

### 4. 端口冲突

```bash
# 检查端口占用
lsof -i :3000
lsof -i :5173

# 杀死占用端口的进程
kill -9 <PID>
```

## 部署脚本使用

更新后的部署脚本现在支持多种模式：

```bash
# 生产环境部署（需要 Docker）
./scripts/deploy.sh production v1.0.0

# 开发模式（不需要 Docker）
./scripts/deploy.sh dev

# 查看帮助
./scripts/deploy.sh --help
```

## 推荐配置

### 开发环境
- 使用开发模式或 Colima
- 配置热重载
- 使用 SQLite 数据库

### 生产环境
- 使用 Docker Desktop 或服务器上的 Docker
- 配置 PostgreSQL 数据库
- 启用监控和日志

## 下一步

安装完成后，您可以：

1. 运行 `./scripts/deploy.sh dev` 启动开发环境
2. 访问 [开发指南](./DEVELOPMENT_STATUS.md) 了解更多
3. 查看 [部署指南](./DEPLOYMENT_GUIDE.md) 进行生产部署