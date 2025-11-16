#!/bin/bash
# Test runner for Tech Summit deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================"
echo "Tech Summit Test Suite Runner"
echo "================================================"

# Function to run tests
run_test_suite() {
    local suite_name=$1
    local test_path=$2
    
    echo -e "\n${YELLOW}Running $suite_name...${NC}"
    
    if python -m pytest $test_path -v --tb=short; then
        echo -e "${GREEN}✅ $suite_name PASSED${NC}"
        return 0
    else
        echo -e "${RED}❌ $suite_name FAILED${NC}"
        return 1
    fi
}

# Function to run load tests
run_load_test() {
    echo -e "\n${YELLOW}Running Load Tests (150 users)...${NC}"
    
    # Start with fewer users and ramp up
    echo "Starting gradual load test..."
    
    locust -f tests/load/locustfile.py \
           --headless \
           --host http://localhost \
           --users 150 \
           --spawn-rate 5 \
           --run-time 60s \
           --html tests/load/report.html \
           --csv tests/load/results
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Load Tests COMPLETED${NC}"
        echo "Report saved to tests/load/report.html"
        return 0
    else
        echo -e "${RED}❌ Load Tests FAILED${NC}"
        return 1
    fi
}

# Parse command line arguments
TEST_TYPE=${1:-all}

# Check if services are running
echo -e "\n${YELLOW}Checking service status...${NC}"
if ! docker ps | grep -q jarvis-session-manager; then
    echo -e "${RED}❌ Services not running! Please start them first.${NC}"
    echo "Run: docker-compose -f docker-compose.tech-summit.yml up -d"
    exit 1
fi

echo -e "${GREEN}✅ Services are running${NC}"

# Install test dependencies if needed
if [ ! -d "venv" ]; then
    echo -e "\n${YELLOW}Setting up test environment...${NC}"
    python3 -m venv venv
    source venv/bin/activate
    pip install -r tests/requirements.txt
else
    source venv/bin/activate
fi

# Run tests based on type
case $TEST_TYPE in
    smoke)
        run_test_suite "Smoke Tests" "tests/smoke/"
        ;;
    regression)
        run_test_suite "Regression Tests" "tests/regression/"
        ;;
    load)
        run_load_test
        ;;
    quick)
        # Quick test for CI/CD
        run_test_suite "Smoke Tests" "tests/smoke/test_smoke.py::TestSmoke::test_session_manager_health"
        ;;
    all)
        # Run all test suites
        FAILED=0
        
        run_test_suite "Smoke Tests" "tests/smoke/" || FAILED=1
        
        if [ $FAILED -eq 0 ]; then
            run_test_suite "Regression Tests" "tests/regression/" || FAILED=1
        fi
        
        if [ $FAILED -eq 0 ]; then
            run_load_test || FAILED=1
        fi
        
        if [ $FAILED -eq 0 ]; then
            echo -e "\n${GREEN}================================================${NC}"
            echo -e "${GREEN}✅ ALL TESTS PASSED - READY FOR TECH SUMMIT!${NC}"
            echo -e "${GREEN}================================================${NC}"
        else
            echo -e "\n${RED}================================================${NC}"
            echo -e "${RED}❌ SOME TESTS FAILED - PLEASE FIX BEFORE DEPLOYMENT${NC}"
            echo -e "${RED}================================================${NC}"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [smoke|regression|load|quick|all]"
        echo "  smoke      - Run smoke tests only"
        echo "  regression - Run regression tests only"
        echo "  load       - Run load tests (150 users)"
        echo "  quick      - Run quick health check"
        echo "  all        - Run all test suites (default)"
        exit 1
        ;;
esac

# Generate test report
if [ -f "tests/load/results_stats.csv" ]; then
    echo -e "\n${YELLOW}Generating performance summary...${NC}"
    python -c "
import csv
with open('tests/load/results_stats.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['Name'] == 'Aggregated':
            print(f\"Average Response Time: {row['Average Response Time']}ms\")
            print(f\"95th Percentile: {row['95%']}ms\")
            print(f\"Failure Rate: {row['Failure Count']}/{row['Request Count']}\")
            break
    "
fi

echo -e "\n${GREEN}Test run completed!${NC}"