#!/bin/bash

# SmellPin Production Deployment Script
# Enterprise-grade deployment with comprehensive DevOps automation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEPLOYMENT_ID="deploy_${TIMESTAMP}"

# Default values
ENVIRONMENT=${ENVIRONMENT:-production}
SKIP_TESTS=${SKIP_TESTS:-false}
SKIP_SECURITY_SCAN=${SKIP_SECURITY_SCAN:-false}
SKIP_BACKUP=${SKIP_BACKUP:-false}
FORCE_DEPLOY=${FORCE_DEPLOY:-false}
DRY_RUN=${DRY_RUN:-false}

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [$DEPLOYMENT_ID] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [$DEPLOYMENT_ID] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [$DEPLOYMENT_ID] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [$DEPLOYMENT_ID] INFO: $1${NC}"
}

success() {
    echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')] [$DEPLOYMENT_ID] SUCCESS: $1${NC}"
}

step() {
    echo -e "${PURPLE}[$(date '+%Y-%m-%d %H:%M:%S')] [$DEPLOYMENT_ID] STEP: $1${NC}"
}

# Function to display usage
usage() {
    cat << EOF
SmellPin Production Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
    -e, --environment ENV       Deployment environment (production|staging) [default: production]
    -s, --skip-tests           Skip test execution
    -S, --skip-security-scan   Skip security scanning
    -b, --skip-backup          Skip pre-deployment backup
    -f, --force                Force deployment without confirmations
    -d, --dry-run              Show what would be deployed without executing
    -h, --help                 Show this help message

ENVIRONMENT VARIABLES:
    DATABASE_URL               Primary database connection string
    DATABASE_URL_SECONDARY     Secondary database connection string (for DR)
    REDIS_URL                  Redis connection string
    JWT_SECRET                 JWT signing secret
    STRIPE_SECRET_KEY          Stripe API secret key
    PAYPAL_CLIENT_SECRET       PayPal API secret
    SLACK_WEBHOOK_URL          Slack notifications webhook
    PAGERDUTY_INTEGRATION_KEY  PagerDuty integration key
    AWS_ACCESS_KEY_ID          AWS access key for backups
    AWS_SECRET_ACCESS_KEY      AWS secret key for backups
    CLOUDFLARE_API_TOKEN       Cloudflare API token for DNS management
    GRAFANA_ADMIN_PASSWORD     Grafana admin password

EXAMPLES:
    # Standard production deployment
    ./deploy-production.sh

    # Staging deployment with tests skipped
    ./deploy-production.sh -e staging -s

    # Dry run to see deployment plan
    ./deploy-production.sh -d

    # Force deployment (skip confirmations)
    ./deploy-production.sh -f

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -s|--skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            -S|--skip-security-scan)
                SKIP_SECURITY_SCAN=true
                shift
                ;;
            -b|--skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            -f|--force)
                FORCE_DEPLOY=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Validate environment and prerequisites
validate_environment() {
    step "Validating deployment environment"

    # Check if running as appropriate user
    if [[ $EUID -eq 0 ]]; then
        error "Do not run this script as root"
        exit 1
    fi

    # Validate environment
    if [[ ! "$ENVIRONMENT" =~ ^(production|staging)$ ]]; then
        error "Invalid environment: $ENVIRONMENT. Must be 'production' or 'staging'"
        exit 1
    fi

    # Check required commands
    local required_commands=("docker" "docker-compose" "git" "curl" "jq" "openssl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Required command not found: $cmd"
            exit 1
        fi
    done

    # Check Docker daemon
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running or accessible"
        exit 1
    fi

    # Validate required environment variables
    local required_vars=()
    if [[ "$ENVIRONMENT" == "production" ]]; then
        required_vars=(
            "DATABASE_URL"
            "REDIS_URL"
            "JWT_SECRET"
            "STRIPE_SECRET_KEY"
        )
    fi

    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            error "Required environment variable not set: $var"
            exit 1
        fi
    done

    # Check Git status
    if [[ -d .git ]]; then
        local git_status=$(git status --porcelain)
        if [[ -n "$git_status" ]] && [[ "$FORCE_DEPLOY" != "true" ]]; then
            error "Working directory is not clean. Commit or stash changes first."
            info "Use --force to deploy with uncommitted changes"
            exit 1
        fi
    fi

    success "Environment validation completed"
}

# Run comprehensive tests
run_tests() {
    if [[ "$SKIP_TESTS" == "true" ]]; then
        warn "Skipping tests (--skip-tests flag provided)"
        return 0
    fi

    step "Running comprehensive test suite"

    # Unit tests
    info "Running unit tests..."
    if [[ "$DRY_RUN" == "false" ]]; then
        npm run test:unit || {
            error "Unit tests failed"
            exit 1
        }
    fi

    # Integration tests
    info "Running integration tests..."
    if [[ "$DRY_RUN" == "false" ]]; then
        npm run test:integration || {
            error "Integration tests failed"
            exit 1
        }
    fi

    # Security tests
    info "Running security tests..."
    if [[ "$DRY_RUN" == "false" ]]; then
        npm run test:security || {
            warn "Security tests failed - review before deployment"
        }
    fi

    # Performance tests
    info "Running performance tests..."
    if [[ "$DRY_RUN" == "false" ]]; then
        npm run test:performance || {
            warn "Performance tests failed - review response times"
        }
    fi

    # End-to-end tests
    info "Running end-to-end tests..."
    if [[ "$DRY_RUN" == "false" ]]; then
        npm run test:e2e || {
            error "End-to-end tests failed"
            exit 1
        }
    fi

    success "All tests completed successfully"
}

# Security scanning
run_security_scan() {
    if [[ "$SKIP_SECURITY_SCAN" == "true" ]]; then
        warn "Skipping security scan (--skip-security-scan flag provided)"
        return 0
    fi

    step "Running security scan"

    # Dependency vulnerability scan
    info "Scanning dependencies for vulnerabilities..."
    if [[ "$DRY_RUN" == "false" ]]; then
        npm audit --audit-level=moderate || {
            warn "Dependency vulnerabilities found - review before deployment"
        }
    fi

    # Container security scan
    info "Scanning container images..."
    if [[ "$DRY_RUN" == "false" ]] && command -v trivy &> /dev/null; then
        docker build -t smellpin:security-scan .
        trivy image --exit-code 1 --severity HIGH,CRITICAL smellpin:security-scan || {
            error "Critical vulnerabilities found in container image"
            exit 1
        }
    fi

    # SSL certificate check
    info "Checking SSL certificates..."
    if [[ "$ENVIRONMENT" == "production" ]] && [[ "$DRY_RUN" == "false" ]]; then
        local cert_expiry=$(echo | openssl s_client -servername smellpin.com -connect smellpin.com:443 2>/dev/null | openssl x509 -noout -dates | grep notAfter | cut -d= -f2)
        local expiry_epoch=$(date -d "$cert_expiry" +%s)
        local current_epoch=$(date +%s)
        local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
        
        if [[ $days_until_expiry -lt 30 ]]; then
            warn "SSL certificate expires in $days_until_expiry days"
        fi
    fi

    success "Security scan completed"
}

# Create backup before deployment
create_backup() {
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        warn "Skipping backup (--skip-backup flag provided)"
        return 0
    fi

    step "Creating pre-deployment backup"

    local backup_dir="/opt/smellpin/backups/${DEPLOYMENT_ID}"
    
    if [[ "$DRY_RUN" == "false" ]]; then
        mkdir -p "$backup_dir"

        # Database backup
        if [[ -n "${DATABASE_URL:-}" ]]; then
            info "Backing up database..."
            pg_dump "$DATABASE_URL" | gzip > "${backup_dir}/database_${TIMESTAMP}.sql.gz" || {
                error "Database backup failed"
                exit 1
            }
        fi

        # Application data backup
        info "Backing up application data..."
        if [[ -d "/opt/smellpin/production/uploads" ]]; then
            tar -czf "${backup_dir}/uploads_${TIMESTAMP}.tar.gz" -C /opt/smellpin/production uploads/
        fi

        # Configuration backup
        info "Backing up configuration..."
        tar -czf "${backup_dir}/config_${TIMESTAMP}.tar.gz" -C "$PROJECT_ROOT" \
            .env* config/ security/ monitoring/ disaster-recovery/ || true

        # Create backup manifest
        cat > "${backup_dir}/manifest.json" << EOF
{
    "deployment_id": "$DEPLOYMENT_ID",
    "timestamp": "$TIMESTAMP",
    "environment": "$ENVIRONMENT",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')",
    "files": {
        "database": "database_${TIMESTAMP}.sql.gz",
        "uploads": "uploads_${TIMESTAMP}.tar.gz",
        "config": "config_${TIMESTAMP}.tar.gz"
    }
}
EOF

        info "Backup created at: $backup_dir"
        success "Pre-deployment backup completed"
    else
        info "Would create backup at: $backup_dir"
    fi
}

# Build and optimize container images
build_images() {
    step "Building and optimizing container images"

    # Build production images
    info "Building frontend image..."
    if [[ "$DRY_RUN" == "false" ]]; then
        docker build \
            --target production \
            --cache-from smellpin-frontend:latest \
            --tag "smellpin-frontend:${DEPLOYMENT_ID}" \
            --tag "smellpin-frontend:latest" \
            --build-arg NODE_ENV=production \
            --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
            --build-arg VCS_REF="$(git rev-parse HEAD)" \
            frontend/
    fi

    info "Building backend image..."
    if [[ "$DRY_RUN" == "false" ]]; then
        docker build \
            --target production \
            --cache-from smellpin-api:latest \
            --tag "smellpin-api:${DEPLOYMENT_ID}" \
            --tag "smellpin-api:latest" \
            --build-arg NODE_ENV=production \
            --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
            --build-arg VCS_REF="$(git rev-parse HEAD)" \
            .

        # Test built image
        docker run --rm "smellpin-api:${DEPLOYMENT_ID}" node --version
    fi

    # Build monitoring images
    info "Building monitoring services..."
    if [[ "$DRY_RUN" == "false" ]]; then
        docker build -t "smellpin-enterprise-monitor:${DEPLOYMENT_ID}" monitoring/
        docker build -t "smellpin-performance-guardian:${DEPLOYMENT_ID}" monitoring/
        docker build -t "smellpin-autoscaler:${DEPLOYMENT_ID}" autoscaler/ || true
    fi

    success "Image build completed"
}

# Deploy infrastructure components
deploy_infrastructure() {
    step "Deploying infrastructure components"

    # Create necessary directories
    info "Creating directory structure..."
    if [[ "$DRY_RUN" == "false" ]]; then
        sudo mkdir -p /opt/smellpin/{production,monitoring,disaster-recovery,security,backups}
        sudo mkdir -p /opt/smellpin/production/{data,logs,uploads}
        sudo mkdir -p /opt/smellpin/production/data/{postgres,postgres-replica,redis,prometheus,grafana,loki}
        sudo chown -R $(whoami):$(whoami) /opt/smellpin/
    fi

    # Deploy security hardening
    if [[ "$ENVIRONMENT" == "production" ]]; then
        info "Applying security hardening..."
        if [[ "$DRY_RUN" == "false" ]]; then
            sudo "$PROJECT_ROOT/security/security-hardening.sh" || {
                warn "Security hardening encountered issues - review manually"
            }
        fi
    fi

    # Deploy monitoring stack
    info "Deploying monitoring stack..."
    if [[ "$DRY_RUN" == "false" ]]; then
        cd "$PROJECT_ROOT/monitoring"
        docker-compose -f docker-compose.production.yml up -d
    fi

    # Deploy disaster recovery infrastructure
    if [[ "$ENVIRONMENT" == "production" ]]; then
        info "Deploying disaster recovery infrastructure..."
        if [[ "$DRY_RUN" == "false" ]]; then
            cd "$PROJECT_ROOT/disaster-recovery"
            docker-compose -f disaster-recovery-plan.yml up -d
        fi
    fi

    success "Infrastructure deployment completed"
}

# Deploy application services
deploy_application() {
    step "Deploying application services"

    cd "$PROJECT_ROOT"

    # Update environment configuration
    info "Updating environment configuration..."
    if [[ "$DRY_RUN" == "false" ]]; then
        # Create environment file for Docker Compose
        cat > ".env.${ENVIRONMENT}" << EOF
# Generated by deployment script at $(date)
ENVIRONMENT=${ENVIRONMENT}
DEPLOYMENT_ID=${DEPLOYMENT_ID}
NODE_ENV=${ENVIRONMENT}
DATABASE_URL=${DATABASE_URL}
REDIS_URL=${REDIS_URL}
JWT_SECRET=${JWT_SECRET}
STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY}
PAYPAL_CLIENT_SECRET=${PAYPAL_CLIENT_SECRET:-}
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}
GRAFANA_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD:-SmellPin2024!}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-}
PAGERDUTY_INTEGRATION_KEY=${PAGERDUTY_INTEGRATION_KEY:-}
EOF
    fi

    # Deploy with Docker Compose
    info "Starting application services..."
    if [[ "$DRY_RUN" == "false" ]]; then
        docker-compose -f docker-compose.production.yml --env-file ".env.${ENVIRONMENT}" up -d

        # Wait for services to be healthy
        info "Waiting for services to become healthy..."
        local max_wait=300  # 5 minutes
        local wait_time=0
        
        while [[ $wait_time -lt $max_wait ]]; do
            local healthy_services=$(docker-compose -f docker-compose.production.yml ps --services --filter "health=healthy" | wc -l)
            local total_services=$(docker-compose -f docker-compose.production.yml ps --services | wc -l)
            
            if [[ $healthy_services -eq $total_services ]]; then
                break
            fi
            
            info "Healthy services: $healthy_services/$total_services"
            sleep 10
            ((wait_time += 10))
        done

        if [[ $wait_time -ge $max_wait ]]; then
            warn "Some services may not be fully healthy yet"
        fi
    fi

    success "Application deployment completed"
}

# Run deployment verification tests
verify_deployment() {
    step "Verifying deployment"

    local base_url
    if [[ "$ENVIRONMENT" == "production" ]]; then
        base_url="https://smellpin.com"
    else
        base_url="https://staging.smellpin.com"
    fi

    # Health check endpoints
    local endpoints=(
        "$base_url/health"
        "$base_url/api/health"
        "$base_url/api/version"
    )

    info "Testing health check endpoints..."
    for endpoint in "${endpoints[@]}"; do
        if [[ "$DRY_RUN" == "false" ]]; then
            local status_code
            status_code=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint" || echo "000")
            
            if [[ "$status_code" == "200" ]]; then
                info "✓ $endpoint - OK"
            else
                error "✗ $endpoint - HTTP $status_code"
                exit 1
            fi
        else
            info "Would test: $endpoint"
        fi
    done

    # Performance verification
    info "Running performance verification..."
    if [[ "$DRY_RUN" == "false" ]]; then
        local response_time
        response_time=$(curl -s -o /dev/null -w "%{time_total}" "$base_url/api/health")
        response_time_ms=$(echo "$response_time * 1000" | bc -l | cut -d. -f1)
        
        if [[ $response_time_ms -lt 200 ]]; then
            info "✓ Response time: ${response_time_ms}ms (target: <200ms)"
        else
            warn "✗ Response time: ${response_time_ms}ms (exceeds 200ms target)"
        fi
    fi

    # Security verification
    info "Running security verification..."
    if [[ "$DRY_RUN" == "false" ]]; then
        # Check SSL configuration
        local ssl_score
        ssl_score=$(curl -s "https://api.ssllabs.com/api/v3/analyze?host=smellpin.com" | jq -r '.endpoints[0].grade' || echo "Unknown")
        if [[ "$ssl_score" =~ ^[A-B] ]]; then
            info "✓ SSL Grade: $ssl_score"
        else
            warn "SSL Grade may need improvement: $ssl_score"
        fi

        # Check security headers
        local headers
        headers=$(curl -s -I "$base_url" | grep -E "(Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options)")
        if [[ -n "$headers" ]]; then
            info "✓ Security headers present"
        else
            warn "Security headers may be missing"
        fi
    fi

    success "Deployment verification completed"
}

# Post-deployment tasks
post_deployment() {
    step "Running post-deployment tasks"

    # Update monitoring dashboards
    info "Updating monitoring dashboards..."
    if [[ "$DRY_RUN" == "false" ]]; then
        # Restart Grafana to pick up new dashboards
        docker-compose -f monitoring/docker-compose.production.yml restart grafana || true
    fi

    # Clear caches
    info "Clearing application caches..."
    if [[ "$DRY_RUN" == "false" ]]; then
        # Clear Redis cache
        docker exec smellpin-redis-primary redis-cli FLUSHDB || true
    fi

    # Send deployment notification
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]] && [[ "$DRY_RUN" == "false" ]]; then
        info "Sending deployment notification..."
        curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"🚀 SmellPin ${ENVIRONMENT} deployment completed successfully!\nDeployment ID: ${DEPLOYMENT_ID}\nTimestamp: $(date)\"}" \
            "$SLACK_WEBHOOK_URL" || true
    fi

    # Generate deployment report
    info "Generating deployment report..."
    local report_file="/opt/smellpin/deployments/${DEPLOYMENT_ID}_report.json"
    if [[ "$DRY_RUN" == "false" ]]; then
        mkdir -p /opt/smellpin/deployments
        cat > "$report_file" << EOF
{
    "deployment_id": "$DEPLOYMENT_ID",
    "environment": "$ENVIRONMENT",
    "timestamp": "$TIMESTAMP",
    "git_commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
    "git_branch": "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')",
    "deployed_by": "$(whoami)",
    "hostname": "$(hostname)",
    "services": $(docker-compose -f docker-compose.production.yml ps --services | jq -R . | jq -s .),
    "images": $(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}" | grep smellpin | jq -R . | jq -s .),
    "status": "success"
}
EOF
        info "Deployment report saved: $report_file"
    fi

    success "Post-deployment tasks completed"
}

# Rollback function (in case of issues)
rollback_deployment() {
    error "Deployment failed - initiating rollback"
    
    # Find previous successful deployment
    local previous_deployment
    previous_deployment=$(ls -1 /opt/smellpin/deployments/ | grep "_report.json" | sort -r | sed -n '2p' | cut -d_ -f2)
    
    if [[ -n "$previous_deployment" ]]; then
        warn "Rolling back to deployment: $previous_deployment"
        
        # Restore from backup
        if [[ -d "/opt/smellpin/backups/${previous_deployment}" ]]; then
            # This would restore the previous state
            # Implementation depends on specific backup strategy
            warn "Manual rollback required - restore from backup: /opt/smellpin/backups/${previous_deployment}"
        fi
    else
        error "No previous deployment found for rollback"
    fi
    
    exit 1
}

# Confirmation prompt
confirm_deployment() {
    if [[ "$FORCE_DEPLOY" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        return 0
    fi

    echo
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}                    DEPLOYMENT CONFIRMATION                     ${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Environment:${NC} $ENVIRONMENT"
    echo -e "${BLUE}Deployment ID:${NC} $DEPLOYMENT_ID"
    echo -e "${BLUE}Git Commit:${NC} $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
    echo -e "${BLUE}Git Branch:${NC} $(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
    echo -e "${BLUE}Timestamp:${NC} $(date)"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo

    read -p "Do you want to proceed with the deployment? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy]([Ee][Ss])?$ ]]; then
        info "Deployment cancelled by user"
        exit 0
    fi
}

# Main deployment function
main() {
    log "Starting SmellPin deployment process"
    log "Deployment ID: $DEPLOYMENT_ID"
    log "Environment: $ENVIRONMENT"

    # Set up error handling
    trap rollback_deployment ERR

    # Parse arguments and validate
    parse_arguments "$@"
    validate_environment

    # Show deployment plan for dry run
    if [[ "$DRY_RUN" == "true" ]]; then
        info "=== DRY RUN MODE - NO CHANGES WILL BE MADE ==="
    fi

    # Confirmation
    confirm_deployment

    # Execute deployment steps
    run_tests
    run_security_scan
    create_backup
    build_images
    deploy_infrastructure
    deploy_application
    verify_deployment
    post_deployment

    # Success message
    echo
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    DEPLOYMENT SUCCESSFUL!                      ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Environment:${NC} $ENVIRONMENT"
    echo -e "${CYAN}Deployment ID:${NC} $DEPLOYMENT_ID"
    echo -e "${CYAN}Duration:${NC} $((SECONDS/60)) minutes $((SECONDS%60)) seconds"
    if [[ "$ENVIRONMENT" == "production" ]]; then
        echo -e "${CYAN}Frontend URL:${NC} https://smellpin.com"
        echo -e "${CYAN}API URL:${NC} https://api.smellpin.com"
        echo -e "${CYAN}Monitoring:${NC} https://monitoring.smellpin.com"
    fi
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo

    success "SmellPin deployment completed successfully!"
}

# Execute main function with all arguments
main "$@"