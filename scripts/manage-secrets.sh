#!/bin/bash

# SmellPin Secrets Management Script
# This script helps manage secrets across different environments and platforms

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Environment validation
validate_environment() {
    local env=$1
    if [[ ! "$env" =~ ^(development|staging|production)$ ]]; then
        log_error "Invalid environment: $env. Must be one of: development, staging, production"
        exit 1
    fi
}

# Check required tools
check_dependencies() {
    local tools=("gh" "wrangler" "vercel" "docker")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done
    
    log_success "All required tools are installed"
}

# GitHub Actions Secrets Management
manage_github_secrets() {
    local env=$1
    
    log_info "Managing GitHub Actions secrets for $env environment..."
    
    # Required secrets for GitHub Actions
    local secrets=(
        "VERCEL_TOKEN"
        "VERCEL_ORG_ID"
        "VERCEL_PROJECT_ID"
        "CLOUDFLARE_API_TOKEN"
        "CLOUDFLARE_ACCOUNT_ID"
        "DOCKER_REGISTRY_TOKEN"
        "STAGING_HOST"
        "STAGING_USERNAME" 
        "STAGING_SSH_KEY"
        "PRODUCTION_HOST"
        "PRODUCTION_USERNAME"
        "PRODUCTION_SSH_KEY"
        "SLACK_WEBHOOK_URL"
        "SNYK_TOKEN"
    )
    
    # Environment-specific secrets
    local env_secrets=()
    case $env in
        "staging")
            env_secrets+=(
                "VITE_API_URL_STAGING"
                "VITE_STRIPE_PUBLISHABLE_KEY_STAGING"
                "DATABASE_URL_STAGING"
                "JWT_SECRET_STAGING"
                "STRIPE_SECRET_KEY_STAGING"
                "REDIS_PASSWORD_STAGING"
            )
            ;;
        "production")
            env_secrets+=(
                "VITE_API_URL_PRODUCTION"
                "VITE_STRIPE_PUBLISHABLE_KEY_PRODUCTION"
                "DATABASE_URL"
                "JWT_SECRET"
                "STRIPE_SECRET_KEY"
                "STRIPE_WEBHOOK_SECRET"
                "REDIS_PASSWORD"
                "GRAFANA_PASSWORD"
                "CDN_ACCESS_KEY"
                "CDN_SECRET_KEY"
                "EMAIL_SERVICE_API_KEY"
            )
            ;;
    esac
    
    # Check existing secrets
    log_info "Checking existing GitHub secrets..."
    for secret in "${secrets[@]}" "${env_secrets[@]}"; do
        if gh secret list --repo "$(git remote get-url origin)" | grep -q "^$secret"; then
            log_success "✓ $secret exists"
        else
            log_warning "✗ $secret is missing"
            echo "  Run: gh secret set $secret --body=\"<value>\""
        fi
    done
}

# Vercel Environment Variables Management
manage_vercel_env() {
    local env=$1
    
    log_info "Managing Vercel environment variables for $env..."
    
    local vercel_env
    case $env in
        "development") vercel_env="development" ;;
        "staging") vercel_env="preview" ;;
        "production") vercel_env="production" ;;
    esac
    
    # Required Vercel environment variables
    local env_vars=(
        "VITE_API_URL"
        "VITE_STRIPE_PUBLISHABLE_KEY"
        "VITE_GOOGLE_MAPS_API_KEY"
        "VITE_SENTRY_DSN"
        "VITE_APP_VERSION"
    )
    
    log_info "Setting Vercel environment variables..."
    for var in "${env_vars[@]}"; do
        echo "Please set $var for $vercel_env environment:"
        echo "  vercel env add $var $vercel_env"
    done
}

# Cloudflare Workers Secrets Management
manage_worker_secrets() {
    local env=$1
    
    log_info "Managing Cloudflare Workers secrets for $env..."
    
    # Required Worker secrets
    local secrets=(
        "DATABASE_URL"
        "JWT_SECRET"
        "PAYPAL_CLIENT_ID"
        "PAYPAL_CLIENT_SECRET"
        "PAYPAL_ENVIRONMENT"
        "GOOGLE_MAPS_API_KEY"
    )
    
    log_info "Setting Cloudflare Workers secrets..."
    for secret in "${secrets[@]}"; do
        echo "Please set $secret for $env environment:"
        echo "  wrangler secret put $secret --env $env"
        echo "  Enter the secret value when prompted"
        echo ""
    done
}

# Docker Secrets Management
manage_docker_secrets() {
    local env=$1
    
    log_info "Managing Docker secrets for $env..."
    
    # Generate secure environment file
    local env_file="${PROJECT_ROOT}/.env.${env}"
    
    if [[ ! -f "$env_file" ]]; then
        log_info "Creating $env_file template..."
        
        cat > "$env_file" <<EOF
# SmellPin $env Environment Configuration
NODE_ENV=$env
PORT=3000

# Database Configuration
DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
POSTGRES_PASSWORD=\${DB_PASSWORD}
DATABASE_URL=postgresql://smellpin:\${DB_PASSWORD}@postgres:5432/smellpin_${env}

# Redis Configuration  
REDIS_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
REDIS_URL=redis://:\${REDIS_PASSWORD}@redis:6379

# JWT Configuration
JWT_SECRET=$(openssl rand -base64 32)
JWT_EXPIRES_IN=7d

# Stripe Configuration (REPLACE WITH ACTUAL VALUES)
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...

# CDN Configuration (REPLACE WITH ACTUAL VALUES)
CDN_BASE_URL=https://cdn.smellpin.com
CDN_ACCESS_KEY=your_cdn_access_key
CDN_SECRET_KEY=your_cdn_secret_key

# Email Configuration (REPLACE WITH ACTUAL VALUES)
EMAIL_SERVICE_API_KEY=your_email_service_key

# Monitoring Configuration
GRAFANA_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
SENTRY_DSN=https://your-sentry-dsn
EOF
        
        log_success "Created $env_file template"
        log_warning "Please update the placeholder values in $env_file"
        
        # Set secure permissions
        chmod 600 "$env_file"
        log_info "Set secure permissions (600) on $env_file"
    else
        log_info "$env_file already exists"
    fi
}

# Backup secrets
backup_secrets() {
    local backup_dir="${PROJECT_ROOT}/backups/secrets/$(date +%Y%m%d_%H%M%S)"
    
    log_info "Creating secrets backup in $backup_dir..."
    mkdir -p "$backup_dir"
    
    # Backup environment files
    for env_file in "${PROJECT_ROOT}"/.env.*; do
        if [[ -f "$env_file" ]]; then
            cp "$env_file" "$backup_dir/"
        fi
    done
    
    # Export GitHub secrets list
    gh secret list --repo "$(git remote get-url origin)" > "$backup_dir/github_secrets_list.txt"
    
    # Export Vercel environment variables
    vercel env ls > "$backup_dir/vercel_env_list.txt" 2>/dev/null || log_warning "Could not export Vercel env vars"
    
    log_success "Secrets backup created in $backup_dir"
}

# Rotate secrets
rotate_secrets() {
    local env=$1
    
    log_warning "This will rotate secrets for $env environment. This is a destructive operation!"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Secret rotation cancelled"
        exit 0
    fi
    
    log_info "Rotating secrets for $env..."
    
    # Generate new secrets
    local new_jwt_secret=$(openssl rand -base64 32)
    local new_db_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local new_redis_password=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
    local new_grafana_password=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
    
    log_info "Generated new secrets. Please update them manually in:"
    echo "  1. .env.$env file"
    echo "  2. GitHub Actions secrets"
    echo "  3. Cloudflare Workers secrets"
    echo "  4. Vercel environment variables"
    
    echo ""
    echo "New values:"
    echo "JWT_SECRET=$new_jwt_secret"
    echo "DB_PASSWORD=$new_db_password"
    echo "REDIS_PASSWORD=$new_redis_password"
    echo "GRAFANA_PASSWORD=$new_grafana_password"
}

# Validate secrets
validate_secrets() {
    local env=$1
    
    log_info "Validating secrets for $env environment..."
    
    local env_file="${PROJECT_ROOT}/.env.${env}"
    
    if [[ ! -f "$env_file" ]]; then
        log_error "Environment file $env_file not found"
        exit 1
    fi
    
    # Source environment file
    source "$env_file"
    
    # Check required variables
    local required_vars=(
        "NODE_ENV"
        "DB_PASSWORD"
        "JWT_SECRET"
        "REDIS_PASSWORD"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        exit 1
    fi
    
    # Validate secret strength
    if [[ ${#JWT_SECRET} -lt 32 ]]; then
        log_warning "JWT_SECRET should be at least 32 characters long"
    fi
    
    if [[ ${#DB_PASSWORD} -lt 16 ]]; then
        log_warning "DB_PASSWORD should be at least 16 characters long"
    fi
    
    log_success "All required secrets are present and valid"
}

# Main function
main() {
    local command=${1:-}
    local environment=${2:-}
    
    if [[ -z "$command" ]]; then
        echo "Usage: $0 <command> [environment]"
        echo ""
        echo "Commands:"
        echo "  init <env>      - Initialize secrets for environment"
        echo "  check <env>     - Check secrets status"
        echo "  github <env>    - Manage GitHub Actions secrets"
        echo "  vercel <env>    - Manage Vercel environment variables"
        echo "  workers <env>   - Manage Cloudflare Workers secrets"
        echo "  docker <env>    - Manage Docker environment files"
        echo "  backup          - Backup all secrets"
        echo "  rotate <env>    - Rotate secrets (destructive)"
        echo "  validate <env>  - Validate secrets"
        echo ""
        echo "Environments: development, staging, production"
        exit 1
    fi
    
    # Commands that don't require environment
    case $command in
        "backup")
            check_dependencies
            backup_secrets
            exit 0
            ;;
    esac
    
    # Commands that require environment
    if [[ -z "$environment" ]]; then
        log_error "Environment is required for this command"
        exit 1
    fi
    
    validate_environment "$environment"
    
    case $command in
        "init")
            check_dependencies
            manage_docker_secrets "$environment"
            manage_github_secrets "$environment"
            manage_vercel_env "$environment"
            manage_worker_secrets "$environment"
            ;;
        "check"|"github")
            check_dependencies
            manage_github_secrets "$environment"
            ;;
        "vercel")
            manage_vercel_env "$environment"
            ;;
        "workers")
            manage_worker_secrets "$environment"
            ;;
        "docker")
            manage_docker_secrets "$environment"
            ;;
        "rotate")
            rotate_secrets "$environment"
            ;;
        "validate")
            validate_secrets "$environment"
            ;;
        *)
            log_error "Unknown command: $command"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"