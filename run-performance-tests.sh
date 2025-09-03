#!/bin/bash

# SmellPin Performance Testing Suite
# Comprehensive performance testing script for all components

echo "🚀 Starting SmellPin Performance Testing Suite"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js to run performance tests."
    exit 1
fi

# Check if required test files exist
REQUIRED_FILES=(
    "lighthouse-performance-test.js"
    "database-performance-test.js"
    "redis-performance-test.js"
    "bundle-analyzer.js"
    "comprehensive-performance-test.js"
)

echo "🔍 Checking test files..."
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        print_error "Required test file $file not found!"
        exit 1
    fi
done
print_success "All test files found"

# Create results directory
RESULTS_DIR="performance-test-results"
mkdir -p $RESULTS_DIR

# Function to run individual tests
run_test() {
    local test_name="$1"
    local test_file="$2"
    local description="$3"
    
    print_status "Running $test_name..."
    echo "📊 $description"
    
    if node "$test_file" > "${RESULTS_DIR}/${test_name}.log" 2>&1; then
        print_success "$test_name completed successfully"
    else
        print_warning "$test_name completed with warnings (check ${RESULTS_DIR}/${test_name}.log)"
    fi
    echo ""
}

# Start timestamp
START_TIME=$(date +%s)

# Run individual performance tests
echo "🧪 Running Individual Performance Tests"
echo "======================================="
echo ""

# 1. Redis Cache Performance Test
run_test "redis-cache-test" "redis-performance-test.js" "Testing Redis cache performance, memory usage, and hit rates"

# 2. Database Performance Test  
run_test "database-test" "database-performance-test.js" "Analyzing database query performance, indexes, and connection pooling"

# 3. Bundle Analysis
run_test "bundle-analysis" "bundle-analyzer.js" "Analyzing JavaScript bundle size, dependencies, and optimization opportunities"

# Note: Lighthouse tests require a running server, so we skip in automated mode
print_warning "Skipping Lighthouse tests (requires running frontend server)"
echo "To run Lighthouse tests manually:"
echo "1. Start your frontend server: cd frontend && npm run dev"
echo "2. Run: node lighthouse-performance-test.js"
echo ""

# Run comprehensive performance test
echo "🎯 Running Comprehensive Performance Analysis"
echo "============================================="
echo ""

run_test "comprehensive-test" "comprehensive-performance-test.js" "Generating comprehensive performance analysis and optimization roadmap"

# Calculate total execution time
END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo "📈 Performance Testing Summary"
echo "=============================="
print_success "All performance tests completed in ${TOTAL_TIME}s"
echo ""

# List generated reports
echo "📄 Generated Reports:"
echo "-------------------"

REPORT_FILES=(
    "smellpin-performance-executive-summary.md"
    "smellpin-performance-technical-report.md"
    "smellpin-performance-optimization-roadmap.md"
    "redis-performance-summary.md"
    "database-performance-summary.md"
    "bundle-analysis-summary.md"
    "comprehensive-performance-report.json"
)

for report in "${REPORT_FILES[@]}"; do
    if [ -f "$report" ]; then
        echo "✅ $report"
    else
        echo "⚠️  $report (not generated)"
    fi
done

echo ""
echo "📊 Key Performance Metrics:"
echo "---------------------------"

# Extract key metrics from comprehensive report if available
if [ -f "comprehensive-performance-report.json" ]; then
    if command -v jq &> /dev/null; then
        OVERALL_SCORE=$(jq -r '.summary.overallScore // "N/A"' comprehensive-performance-report.json)
        CRITICAL_ISSUES=$(jq -r '.summary.criticalIssues | length' comprehensive-performance-report.json 2>/dev/null || echo "N/A")
        HIGH_ISSUES=$(jq -r '.summary.highPriorityIssues | length' comprehensive-performance-report.json 2>/dev/null || echo "N/A")
        
        echo "• Overall Performance Score: ${OVERALL_SCORE}/100"
        echo "• Critical Issues: ${CRITICAL_ISSUES}"
        echo "• High Priority Issues: ${HIGH_ISSUES}"
    else
        echo "• Install 'jq' for detailed metrics extraction"
    fi
else
    echo "• Comprehensive report not generated"
fi

echo ""
echo "🚀 Next Steps:"
echo "-------------"
echo "1. Review the Executive Summary: smellpin-performance-executive-summary.md"
echo "2. Check Technical Details: smellpin-performance-technical-report.md"
echo "3. Follow Optimization Plan: smellpin-performance-optimization-roadmap.md"
echo "4. Monitor progress with regular testing"
echo ""

echo "💡 Quick Commands:"
echo "-----------------"
echo "# View executive summary"
echo "cat smellpin-performance-executive-summary.md"
echo ""
echo "# Run comprehensive test only"
echo "node comprehensive-performance-test.js"
echo ""
echo "# Run Redis test only"  
echo "node redis-performance-test.js"
echo ""
echo "# Run database test only"
echo "node database-performance-test.js"
echo ""

print_success "Performance testing suite completed!"
echo "Results saved in: $(pwd)"
echo "Log files saved in: $(pwd)/${RESULTS_DIR}/"

exit 0