#!/bin/bash

# ================== VPScanner ==================
# Automated Recon Script for Bug Bounty & Pentesting
# Author: Valentim Prado (v7l3nt1m) 
# Hackerone profile: https://hackerone.com/v7l3nt1m
# Linkdin profile: https://www.linkedin.com/in/valentim-prado-25ab6124b/
# 
# This script performs:
#   - Subdomain enumeration
#   - Alive subdomains detection
#   - Screenshots of subdomains
#   - Wayback URL collection & filtering
#   - Sensitive files/URLs detection
#   - Pattern-based filtering with gf
#   - Open ports scanning (optional)
#
# REQUIREMENTS (install before running):
#   subfinder, sublist3r, assetfinder, amass, findomain
#   httpx, gau, uro, ripgrep (rg), gf, gowitness, naabu, nmap
#
# USAGE:
#   ./VPScanner.sh <wordlist>
#   ./VPScanner.sh <wordlist> --skip-ports   (to skip port scanning)
# =================================================

wordlist=$1
seconds=$(date +%s)
data=$(date +%H%m%s)
skip_ports=false
OUTPUT_DIR="gf_results"

# Check if --skip-ports flag was passed
for arg in "$@"; do
    if [ "$arg" == "--skip-ports" ]; then
        skip_ports=true
    fi
done

# Check if required tools are installed
dependencies=(subfinder sublist3r assetfinder amass findomain)
for cmd in "${dependencies[@]}"; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "[!] $cmd is not installed. Please install it before running this script."
        exit 1
    fi
done

[ -f asciiArt.txt ] && cat asciiArt.txt

# If no wordlist provided
if [ -z "$wordlist" ]; then
    echo
    echo "Usage:sudo ./VPScanner.sh <wordlist>"
    echo "Add --skip-ports flag to skip port scanning"
    exit 1
fi

# Function to check internet connection
check_connection() {
    while ! ping -c 1 google.com &> /dev/null; do
        echo "[!] No internet connection. Retrying in 10 seconds..."
        sleep 10
    done
}

# Print ASCII banner if available
[ -f ascii.txt ] && cat ascii.txt

sleep 2
echo
echo "[*] Starting subdomain enumeration for $(wc -l < "$wordlist") domains"
mkdir "results_$data"
cd "results_$data" || exit

echo "================================================================================"
echo "[*] Running Subfinder..."

# Run Subfinder with retry if it fails
check_connection
while ! subfinder -dL "../$wordlist" -o subfinder_results.txt; do
    echo "[!] Subfinder failed. Retrying..."
    check_connection
done &
subfinder_pid=$!

echo "================================================================================"
echo "[*] Running Sublist3r, Assetfinder, and Findomain in parallel..."

pids=()

# Run sublist3r, assetfinder and findomain in parallel per domain
while read -r domain; do
    seconds=$(date +%s)
    echo "[*] Processing domain: $domain"
    check_connection
    
    while ! sublist3r -d "$domain" -o "sublister_results_$seconds.txt"; do
        echo "[!] Sublist3r failed for $domain. Retrying..."
        check_connection
    done &
    pids+=($!)
    
    while ! assetfinder --subs-only "$domain" > "assetfinder_results_$seconds.txt"; do
        echo "[!] Assetfinder failed for $domain. Retrying..."
        check_connection
    done &
    pids+=($!)
    
    while ! findomain --target "$domain" -u "findomains_results_$seconds.txt"; do
        echo "[!] Findomain failed for $domain. Retrying..."
        check_connection
    done &
    pids+=($!)

    sleep 1
done < "../$wordlist"

# Wait for all background processes
wait "$subfinder_pid"
for pid in "${pids[@]}"; do wait "$pid"; done

echo "================================================================================"
echo "[*] Merging results and removing duplicates..."
cat subfinder_results.txt sublister_results_*.txt assetfinder_results_*.txt findomains_results_*.txt | sort -u > final_subdomains.txt

echo "[*] Found $(wc -l < final_subdomains.txt) unique subdomains"
check_connection

echo "================================================================================"
echo "[*] Checking alive subdomains with httpx..."
cat final_subdomains.txt | httpx -t 50 -sc -title -tech-detect -web-server -ip -cdn > subdomains_alive.txt
cat subdomains_alive.txt | cut -d ' ' -f1 | cut -d "/" -f3 > subNoHttp.txt

echo "[+] Alive subdomains saved in: subdomains_alive.txt and subNoHttp.txt"

echo
echo "================================================================================"

## Capture screenshots
echo "[*] Capturing screenshots with gowitness..."
cat subdomains_alive.txt | cut -d ' ' -f1 > subwithHTTP.txt
gowitness scan --screenshot-fullpage file -f subwithHTTP.txt 
echo "[+] Screenshots saved in screenshots/"

echo
echo "================================================================================"

## Subdomain takeover check (basic 404 + CNAME extraction)
echo "[*] Extracting 404 subdomains for potential takeover..."
grep "404" subdomains_alive.txt > subdomains404.txt
cut -d ' ' -f1 subdomains404.txt | cut -d "/" -f3 > subNoHttp404.txt

echo
echo "================================================================================"

echo "[*] Extracting CNAMEs for 404 subdomains..."
while read sub; do
    cname=$(host -t cname "$sub" 2>/dev/null | grep 'alias' | awk '{print $NF}' | sed 's/\.$//')
    if [ -n "$cname" ]; then
        echo "$sub -> $cname"
    fi
done < subNoHttp404.txt > cnames_detected404.txt
echo "[+] CNAMEs saved in: cnames_detected404.txt"

echo
echo "================================================================================"

## Wayback URLs
echo "[*] Collecting Wayback URLs with gau..."
gau < subNoHttp.txt | tee allwaybacksurls.txt
uro < allwaybacksurls.txt > gauUrls.txt

echo
echo "================================================================================"

## Sensitive URLs
echo "[*] Searching for sensitive URLs..."
mkdir -p resultsFiles
touch resultsFiles/sensitiveUrls.txt



rg -i '(phpinfo|debug|admin|config|setup|install|dump|sql|backup|\.git|\.env|\.svn|passwd|token|key|secret|private|example|docs|sample|shell|console|upload|temp|log|logs|db)[^/]*\.(php|jsp|asp|aspx|cgi|json|dist|xml|log|sql|txt|env|bak|zip|tar|gz|conf|pem|crt|key|p12|dist|pfx|csv|yml|ini|sh)?(\?|$)' allwaybacksurls.txt \
  | rg -iv '\.(jpg|jpeg|png|gif|svg|css|woff|ico|mp4|webp|ttf|eot)(\?|$)' \
  | anew resultsFiles/sensitiveUrls.txt
echo "[+] Sensitive URLs saved in resultsFiles/sensitiveUrls.txt"

echo
echo "================================================================================"

## GF patterns

echo "[*] Filtering URLs with gf patterns..."
mkdir -p "$OUTPUT_DIR"
for pattern in $(ls ~/.gf | sed 's/\.json$//'); do
    echo " [+] Pattern: $pattern"
    mkdir -p "$OUTPUT_DIR/$pattern"
    gf "$pattern" < "gauUrls.txt" | sort -u > "$OUTPUT_DIR/$pattern/urls.txt"
done

echo "[*] GF finished"

echo
echo "================================================================================"


## Port scanning
if [ "$skip_ports" = false ]; then
    echo
    echo "================================================================================"
    echo "[*] Scanning open ports with naabu + nmap..."
    naabu -list subNoHttp.txt -top-ports 1000 -nmap-cli 'nmap -sV -Pn -T4 -o nmapResults.txt' -o naabuPortScan.txt
    echo
    echo "[+] Port scan finished"
fi

check_connection

# ================== FINAL RESULTS ==================
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

echo
echo "================================================================================"
echo "FINAL RESULTS"
echo
echo "${GREEN}[*] Alive subdomains:${RESET} $(wc -l < subdomains_alive.txt)"
echo "${RED}[*] Subdomains with 404:${RESET} $(wc -l < subdomains404.txt)"
echo "${YELLOW}[*] CNAMEs from 404:${RESET} $(wc -l < cnames_detected404.txt)"
echo "${YELLOW}[*] Wayback URLs:${RESET} $(wc -l < allwaybacksurls.txt)"
echo "${YELLOW}[*] Filtered URLs (gau):${RESET} $(wc -l < gauUrls.txt)"
echo "${RED}[*] Sensitive URLs detected:${RESET} $(wc -l < resultsFiles/sensitiveUrls.txt)"

if [ "$skip_ports" = false ]; then
    echo "${YELLOW}[*] Unique open ports detected:${RESET} $(cut -d ":" -f2 naabuPortScan.txt | sort -u | wc -l)"
fi

echo
echo "================================================================================"
echo "[*] VPScanner Finished!"
