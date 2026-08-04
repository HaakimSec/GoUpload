#!/bin/bash
# DVWA Full Test Suite
# Usage: ./dvwa-test.sh [PHPSESSID]

PHPSESSID=${1:-"YOUR_SESSION_ID"}
BASE_URL="http://localhost/DVWA/vulnerabilities/upload"

echo "🧪 GoUpload DVWA Test Suite"
echo "============================"

for level in low medium high; do
    echo ""
    echo "📊 Testing DVWA $level security..."
    
    ./GoUpload \
        -u "$BASE_URL/" \
        -H "Cookie: PHPSESSID=$PHPSESSID; security=$level" \
        -p "uploaded" \
        -d "MAX_FILE_SIZE=100000&Upload=Upload" \
        -t php \
        --allow-list .jpg,.png \
        --no-validate \
        -c 5 2>&1 | grep -E "Vulnerable|Suspect|Safe|SUMMARY" -A 3
done
