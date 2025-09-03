#!/bin/bash

# SmellPin 数据库备份和恢复脚本
# 支持自动备份、手动备份、恢复等功能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 配置变量
BACKUP_DIR="./backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_CONTAINER="smellpin-postgres"
DB_NAME="smellpin_prod"
DB_USER="smellpin"
RETENTION_DAYS=30
S3_BUCKET="${BACKUP_S3_BUCKET:-}"
S3_ACCESS_KEY="${BACKUP_S3_ACCESS_KEY:-}"
S3_SECRET_KEY="${BACKUP_S3_SECRET_KEY:-}"

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 数据库备份
backup_database() {
    local backup_file="$BACKUP_DIR/database_$DATE.sql"
    
    log_info "开始备份数据库..."
    
    # 检查数据库容器是否运行
    if ! docker ps | grep -q "$DB_CONTAINER"; then
        log_error "数据库容器 $DB_CONTAINER 未运行"
        exit 1
    fi
    
    # 执行备份
    docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" --verbose --clean --no-owner --no-privileges > "$backup_file"
    
    if [ $? -eq 0 ]; then
        # 压缩备份文件
        gzip "$backup_file"
        backup_file="${backup_file}.gz"
        
        local file_size=$(du -h "$backup_file" | cut -f1)
        log_success "数据库备份完成: $backup_file (大小: $file_size)"
        
        echo "$backup_file"
    else
        log_error "数据库备份失败"
        exit 1
    fi
}

# 文件备份
backup_files() {
    local backup_file="$BACKUP_DIR/files_$DATE.tar.gz"
    
    log_info "开始备份文件..."
    
    # 备份上传文件
    if [ -d "uploads" ]; then
        tar -czf "$backup_file" uploads/
        
        local file_size=$(du -h "$backup_file" | cut -f1)
        log_success "文件备份完成: $backup_file (大小: $file_size)"
        
        echo "$backup_file"
    else
        log_warning "uploads目录不存在，跳过文件备份"
    fi
}

# 配置备份
backup_config() {
    local backup_file="$BACKUP_DIR/config_$DATE.tar.gz"
    
    log_info "开始备份配置文件..."
    
    # 备份配置文件
    tar -czf "$backup_file" \
        --exclude='node_modules' \
        --exclude='dist' \
        --exclude='logs' \
        --exclude='backups' \
        --exclude='.git' \
        .env* docker-compose*.yml nginx/ ssl/ monitoring/ || true
    
    local file_size=$(du -h "$backup_file" | cut -f1)
    log_success "配置备份完成: $backup_file (大小: $file_size)"
    
    echo "$backup_file"
}

# 上传到S3
upload_to_s3() {
    local file="$1"
    local s3_key="smellpin/$(basename "$file")"
    
    if [ -z "$S3_BUCKET" ] || [ -z "$S3_ACCESS_KEY" ] || [ -z "$S3_SECRET_KEY" ]; then
        log_warning "S3配置不完整，跳过云端备份"
        return
    fi
    
    log_info "上传备份到S3: $s3_key"
    
    # 使用AWS CLI上传
    if command -v aws &> /dev/null; then
        AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY" \
        AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY" \
        aws s3 cp "$file" "s3://$S3_BUCKET/$s3_key"
        
        log_success "S3上传完成: s3://$S3_BUCKET/$s3_key"
    else
        log_warning "AWS CLI未安装，跳过S3上传"
    fi
}

# 清理旧备份
cleanup_old_backups() {
    log_info "清理 $RETENTION_DAYS 天前的备份..."
    
    # 删除本地旧备份
    find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
    
    # 清理S3旧备份
    if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
        local cutoff_date=$(date -d "$RETENTION_DAYS days ago" +%Y-%m-%d)
        
        AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY" \
        AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY" \
        aws s3 ls "s3://$S3_BUCKET/smellpin/" | while read -r line; do
            local file_date=$(echo "$line" | awk '{print $1}')
            local file_name=$(echo "$line" | awk '{print $4}')
            
            if [[ "$file_date" < "$cutoff_date" ]]; then
                AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY" \
                AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY" \
                aws s3 rm "s3://$S3_BUCKET/smellpin/$file_name"
                log_info "删除S3旧备份: $file_name"
            fi
        done
    fi
    
    log_success "旧备份清理完成"
}

# 完整备份
full_backup() {
    log_info "开始完整备份..."
    
    local db_backup=$(backup_database)
    local files_backup=$(backup_files)
    local config_backup=$(backup_config)
    
    # 上传到S3
    if [ -n "$db_backup" ]; then
        upload_to_s3 "$db_backup"
    fi
    
    if [ -n "$files_backup" ]; then
        upload_to_s3 "$files_backup"
    fi
    
    if [ -n "$config_backup" ]; then
        upload_to_s3 "$config_backup"
    fi
    
    # 清理旧备份
    cleanup_old_backups
    
    log_success "🎉 完整备份完成！"
}

# 数据库恢复
restore_database() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        log_error "请指定备份文件"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        log_error "备份文件不存在: $backup_file"
        exit 1
    fi
    
    log_warning "即将恢复数据库，这将覆盖现有数据！"
    read -p "确认继续？(y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "恢复操作已取消"
        exit 0
    fi
    
    log_info "开始恢复数据库: $backup_file"
    
    # 检查数据库容器是否运行
    if ! docker ps | grep -q "$DB_CONTAINER"; then
        log_error "数据库容器 $DB_CONTAINER 未运行"
        exit 1
    fi
    
    # 停止应用服务
    log_info "停止应用服务..."
    docker-compose -f docker-compose.prod.yml stop backend
    
    # 恢复数据库
    if [[ "$backup_file" == *.gz ]]; then
        gunzip -c "$backup_file" | docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME"
    else
        docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" < "$backup_file"
    fi
    
    if [ $? -eq 0 ]; then
        log_success "数据库恢复完成"
        
        # 重启应用服务
        log_info "重启应用服务..."
        docker-compose -f docker-compose.prod.yml start backend
        
        log_success "🎉 数据库恢复完成！"
    else
        log_error "数据库恢复失败"
        exit 1
    fi
}

# 文件恢复
restore_files() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        log_error "请指定备份文件"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        log_error "备份文件不存在: $backup_file"
        exit 1
    fi
    
    log_warning "即将恢复文件，这将覆盖现有文件！"
    read -p "确认继续？(y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "恢复操作已取消"
        exit 0
    fi
    
    log_info "开始恢复文件: $backup_file"
    
    # 备份现有文件
    if [ -d "uploads" ]; then
        mv uploads "uploads.backup.$(date +%s)"
    fi
    
    # 恢复文件
    tar -xzf "$backup_file"
    
    log_success "🎉 文件恢复完成！"
}

# 列出备份
list_backups() {
    log_info "本地备份列表:"
    
    if [ -d "$BACKUP_DIR" ]; then
        ls -lh "$BACKUP_DIR"/*.{sql.gz,tar.gz} 2>/dev/null | while read -r line; do
            echo "  $line"
        done
    else
        log_warning "备份目录不存在"
    fi
    
    # S3备份列表
    if [ -n "$S3_BUCKET" ] && command -v aws &> /dev/null; then
        log_info "S3备份列表:"
        
        AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY" \
        AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY" \
        aws s3 ls "s3://$S3_BUCKET/smellpin/" | while read -r line; do
            echo "  $line"
        done
    fi
}

# 从S3下载备份
download_from_s3() {
    local s3_key="$1"
    local local_file="$BACKUP_DIR/$(basename "$s3_key")"
    
    if [ -z "$S3_BUCKET" ] || [ -z "$S3_ACCESS_KEY" ] || [ -z "$S3_SECRET_KEY" ]; then
        log_error "S3配置不完整"
        exit 1
    fi
    
    log_info "从S3下载备份: $s3_key"
    
    AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY" \
    AWS_SECRET_ACCESS_KEY="$S3_SECRET_KEY" \
    aws s3 cp "s3://$S3_BUCKET/smellpin/$s3_key" "$local_file"
    
    log_success "下载完成: $local_file"
    echo "$local_file"
}

# 主函数
main() {
    case "$1" in
        "backup")
            case "$2" in
                "database")
                    backup_database
                    ;;
                "files")
                    backup_files
                    ;;
                "config")
                    backup_config
                    ;;
                "full"|"")
                    full_backup
                    ;;
                *)
                    log_error "未知的备份类型: $2"
                    exit 1
                    ;;
            esac
            ;;
        "restore")
            case "$2" in
                "database")
                    restore_database "$3"
                    ;;
                "files")
                    restore_files "$3"
                    ;;
                *)
                    log_error "未知的恢复类型: $2"
                    exit 1
                    ;;
            esac
            ;;
        "list")
            list_backups
            ;;
        "download")
            download_from_s3 "$2"
            ;;
        "cleanup")
            cleanup_old_backups
            ;;
        *)
            show_help
            ;;
    esac
}

# 显示帮助信息
show_help() {
    echo "SmellPin 备份和恢复脚本"
    echo ""
    echo "使用方法:"
    echo "  $0 backup [类型]              - 执行备份"
    echo "  $0 restore <类型> <文件>      - 执行恢复"
    echo "  $0 list                       - 列出备份"
    echo "  $0 download <S3文件名>        - 从S3下载备份"
    echo "  $0 cleanup                    - 清理旧备份"
    echo ""
    echo "备份类型:"
    echo "  full      - 完整备份（默认）"
    echo "  database  - 仅数据库备份"
    echo "  files     - 仅文件备份"
    echo "  config    - 仅配置备份"
    echo ""
    echo "恢复类型:"
    echo "  database  - 恢复数据库"
    echo "  files     - 恢复文件"
    echo ""
    echo "示例:"
    echo "  $0 backup                     - 完整备份"
    echo "  $0 backup database            - 仅备份数据库"
    echo "  $0 restore database backup.sql.gz  - 恢复数据库"
    echo "  $0 list                       - 列出所有备份"
    echo "  $0 cleanup                    - 清理30天前的备份"
}

# 检查参数
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# 执行主函数
main "$@"