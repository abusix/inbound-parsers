#!/bin/bash
set -euo pipefail

# Script to delete 73 extra Go parsers that have no Python source
# Generated: 2025-10-18

PARSERS_DIR="/Users/tknecht/Projects/inbound-parsers/parsers"

# List of 73 extra Go parsers to delete
EXTRA_PARSERS=(
    "abuse_ch"
    "adobe"
    "apple"
    "aws"
    "azure"
    "baidu"
    "bell"
    "bluehost"
    "bpi"
    "cbs"
    "cert_fi"
    "choopa"
    "cloudflare_report"
    "digital_ocean"
    "dnsimple"
    "dreamhost"
    "ecatel"
    "enom"
    "etsy"
    "facebook"
    "fastly"
    "fbl"
    "feodotracker"
    "fox"
    "gcp"
    "godaddy"
    "google"
    "hbo"
    "huawei"
    "instagram"
    "internap"
    "itv"
    "kabel_deutschland"
    "korea_telecom"
    "lg_uplus"
    "linkedin"
    "linode"
    "microsoft_dmca"
    "mpa"
    "mpaa"
    "namecheap"
    "ncsc_nl"
    "netflix"
    "nocix"
    "oneandone"
    "ovh"
    "packet"
    "paypal"
    "psychz"
    "quadranet"
    "rackspace"
    "recordedfuture"
    "rogers"
    "route53"
    "scaleway"
    "sharktech"
    "shopify"
    "sk_broadband"
    "sky"
    "softlayer"
    "spectrum"
    "strato"
    "tencent"
    "twc"
    "twitter"
    "unity_media"
    "versatel"
    "viacom"
    "vpsville"
    "vultr"
    "wix"
    "wordpress"
    "zenlayer"
)

echo "========================================="
echo "DELETE EXTRA GO PARSERS"
echo "========================================="
echo ""
echo "This script will DELETE 73 Go parser directories"
echo "that have NO corresponding Python source files."
echo ""
echo "Parsers to delete: ${#EXTRA_PARSERS[@]}"
echo "Target directory: $PARSERS_DIR"
echo ""
echo "WARNING: This action CANNOT be undone!"
echo ""
read -p "Are you sure you want to continue? (yes/no): " CONFIRM

if [[ "$CONFIRM" != "yes" ]]; then
    echo "Aborted by user."
    exit 1
fi

echo ""
echo "Starting deletion..."
echo ""

DELETED_COUNT=0
MISSING_COUNT=0

for parser in "${EXTRA_PARSERS[@]}"; do
    PARSER_PATH="$PARSERS_DIR/$parser"

    if [[ -d "$PARSER_PATH" ]]; then
        echo "Deleting: $parser"
        rm -rf "$PARSER_PATH"
        ((DELETED_COUNT++))
    else
        echo "SKIP (not found): $parser"
        ((MISSING_COUNT++))
    fi
done

echo ""
echo "========================================="
echo "DELETION COMPLETE"
echo "========================================="
echo "Deleted: $DELETED_COUNT directories"
echo "Not found: $MISSING_COUNT directories"
echo ""
echo "Remaining Go parsers (should be 477):"
find "$PARSERS_DIR" -mindepth 1 -maxdepth 1 -type d ! -name "base" ! -name "common" | wc -l
echo ""
echo "Run 'go run scripts/map-parsers.go' to verify 1:1 mapping."
