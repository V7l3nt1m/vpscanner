#!/bin/bash

# ================== VPScanner ==================
# Automated Recon Script for Bug Bounty & Pentesting
# Author: Valentim Prado (v7l3nt1m) 
# Hackerone profile: https://hackerone.com/v7l3nt1m
# LinkedIn profile: https://www.linkedin.com/in/valentim-prado-25ab6124b/
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
# REQUIREMENTS:
#   subfinder, sublist3r, assetfinder, amass, findomain
#   httpx, gau, uro, ripgrep (rg), gf, gowitness, naabu, nmap, hakrawler
#
# USAGE:
#   ./VPScanner.sh <listofdomains>
#   ./VPScanner.sh <listofdomains> --skip-ports
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
dependencies=(subfinder sublist3r assetfinder amass findomain naabu nmap gau uro gf rg gowitness httpx hakrawler jq curl host)
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
    echo "Usage: ./VPScanner.sh <listofdomains>" 
    echo "Add --skip-ports flag to skip port scanning"
    echo "Example: ./VPScanner.sh domains.txt or ./VPScanner.sh domains.txt --skip-ports"
    exit 1
fi

# ================== INTERNET CHECK WRAPPER ==================
run_with_check() {
    local cmd="$*"
    while true; do
        if ping -c 1 google.com &> /dev/null; then
            eval "$cmd" && break
            echo "[!] Command failed: $cmd. Retrying in 10s..."
        else
            echo "[!] No internet connection. Retrying in 10s..."
        fi
        sleep 10
    done
}

# ================== START ==================
[ -f ascii.txt ] && cat ascii.txt
sleep 2
echo
echo "[*] Starting subdomain enumeration for $(wc -l < "$wordlist") domains"

mkdir "results_$data"
cd "results_$data" || exit

echo "================================================================================"
echo "[*] Running Subfinder..."
run_with_check subfinder -dL "../$wordlist" -o subfinder_results.txt & subfinder_pid=$!

echo "================================================================================"
echo "[*] Running Sublist3r, Assetfinder, Findomain, CRT.sh in parallel..."
pids=()

while read -r domain; do
    seconds=$(date +%s)
    echo "[*] Processing domain: $domain"

    run_with_check sublist3r -d "$domain" -o "sublister_results_$seconds.txt" & pids+=($!)
    run_with_check "curl https://crt.sh/\?q=$domain\&output=json | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "crt_$seconds.txt"" & pids+=($!)
    run_with_check assetfinder --subs-only "$domain" > "assetfinder_results_$seconds.txt" & pids+=($!)
    run_with_check findomain --target "$domain" -u "findomains_results_$seconds.txt" & pids+=($!)

    sleep 1
done < "../$wordlist"

# Wait for all background processes
wait "$subfinder_pid"
for pid in "${pids[@]}"; do wait "$pid"; done

echo "================================================================================"
echo "[*] Merging results and removing duplicates..."
cat subfinder_results.txt sublister_results_*.txt assetfinder_results_*.txt findomains_results_*.txt crt_*.txt | sort -u > final_subdomains.txt
rm subfinder_results.txt sublister_results_*.txt assetfinder_results_*.txt findomains_results_*.txt crt_*.txt
echo "[*] Found $(wc -l < final_subdomains.txt) unique subdomains"

echo "================================================================================"
echo "[*] Checking alive subdomains with httpx..."
run_with_check "cat final_subdomains.txt | httpx -t 50 -sc -title -tech-detect -web-server -ip -cdn > subdomains_alive.txt"
cut -d ' ' -f1 subdomains_alive.txt | cut -d "/" -f3 > subNoHttp.txt
echo "[+] Alive subdomains saved in: subdomains_alive.txt and subNoHttp.txt"

echo "================================================================================"
echo "[*] Capturing screenshots with gowitness..."
cut -d ' ' -f1 subdomains_alive.txt > subwithHTTP.txt
run_with_check gowitness scan --screenshot-fullpage file -f subwithHTTP.txt
echo "[+] Screenshots saved in screenshots/"

echo "================================================================================"
echo "[*] Extracting 404 subdomains for potential takeover..."
grep "404" subdomains_alive.txt > subdomains404.txt
cut -d ' ' -f1 subdomains404.txt | cut -d "/" -f3 > subNoHttp404.txt

echo "[*] Extracting CNAMEs for 404 subdomains..."
while read sub; do
    cname=$(host -t cname "$sub" 2>/dev/null | grep 'alias' | awk '{print $NF}' | sed 's/\.$//')
    if [ -n "$cname" ]; then
        echo "$sub -> $cname"
    fi
done < subNoHttp404.txt > cnames_detected404.txt
echo "[+] CNAMEs saved in: cnames_detected404.txt"

echo "================================================================================"
echo "[*] Collecting Wayback URLs with gau..."
run_with_check "gau < subNoHttp.txt > allwaybacksurls.txt"
run_with_check "uro < allwaybacksurls.txt > gauUrls.txt"

echo "================================================================================"
echo "[*] Searching for sensitive URLs..."
mkdir -p resultsFiles
touch resultsFiles/sensitiveUrls.txt

rg -i '\.(php|js|jsp|asp|aspx|cgi|json|xml|log|sql|txt|env|bak|zip|tar|gz|tgz|conf|pem|crt|key|p12|pfx|csv|yml|ini|sh|db|sqlite|mdb|accdb)(\?|$)' allwaybacksurls.txt > extractedFilesExtensionWayback.txt
rg -i '(phpinfo|debug|admin|config|setup|install|dump|sql|backup|\.git|\.env|\.svn|passwd|token|apikey|secret|private|id_rsa|ssh|example|docs|sample|shell|console|upload|temp|log|logs|db|database|error)[^/]*\.(php|jsp|asp|aspx|cgi|json|dist|xml|log|sql|js|txt|env|bak|zip|tar|gz|tgz|conf|pem|crt|key|p12|pfx|csv|yml|ini|sh|db|sqlite|mdb|accdb)?(\?|$)' allwaybacksurls.txt \
    | rg -iv '\.(jpg|jpeg|png|gif|svg|css|woff|ico|mp4|webp|ttf|eot)(\?|$)' \
    | anew resultsFiles/sensitiveUrls.txt
echo "[+] Sensitive URLs saved in resultsFiles/sensitiveUrls.txt"

echo "================================================================================"
echo "[*] Collecting URLs with hakrawler..."
run_with_check "cat subwithHTTP.txt | hakrawler -i -u -subs > urlshakrawler.txt"

mkdir -p resultsFilesHak
touch resultsFilesHak/sensitiveUrlsHak.txt

rg -i '\.(php|js|jsp|asp|aspx|cgi|json|xml|log|sql|txt|env|bak|zip|tar|gz|tgz|conf|pem|crt|key|p12|pfx|csv|yml|ini|sh|db|sqlite|mdb|accdb)(\?|$)' urlshakrawler.txt > extractedFilesExtensionHak.txt
rg -i '(phpinfo|debug|admin|config|setup|install|dump|sql|backup|\.git|\.env|\.svn|passwd|token|apikey|secret|private|id_rsa|ssh|example|docs|sample|shell|console|upload|temp|log|logs|db|database|error)[^/]*\.(php|jsp|asp|aspx|cgi|json|dist|xml|log|sql|js|txt|env|bak|zip|tar|gz|tgz|conf|pem|crt|key|p12|pfx|csv|yml|ini|sh|db|sqlite|mdb|accdb)?(\?|$)' urlshakrawler.txt \
    | rg -iv '\.(jpg|jpeg|png|gif|svg|css|woff|ico|mp4|webp|ttf|eot)(\?|$)' \
    | anew resultsFilesHak/sensitiveUrlsHak.txt
echo "[+] Sensitive URLs saved in resultsFilesHak/sensitiveUrlsHak.txt"

echo "================================================================================"
echo "[*] Filtering URLs with GF patterns..."
mkdir -p "$OUTPUT_DIR"
for pattern in $(ls ~/.gf | sed 's/\.json$//'); do
    echo " [+] Pattern: $pattern"
    mkdir -p "$OUTPUT_DIR/$pattern"
    gf "$pattern" < gauUrls.txt | sort -u > "$OUTPUT_DIR/$pattern/urls.txt"
done
echo "[*] GF finished"

# ================== PORT SCANNING ==================
if [ "$skip_ports" = false ]; then
    echo "================================================================================"
    echo "[*] Scanning open ports with naabu + nmap..."
    run_with_check "naabu -list subNoHttp.txt -p - -rate 1500 -retries 2 -timeout 1500 -verify -silent -o naabuPortScan.txt"
    cut -d ':' -f1 naabuPortScan.txt | sort -u > hosts.txt
    ports=$(cut -d ':' -f2 naabuPortScan.txt | sort -u | tr '\n' ',' | sed 's/,$//')
    run_with_check "nmap -sV -sC -T4 -iL hosts.txt -p$ports -oA nmapFocusedScan"
    echo "[+] Port scan finished, saved in nmapFocusedScan and naabuPortScan.txt"
fi

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
echo "${YELLOW}[*] Filtered files (hakrawler):${RESET} $(wc -l < extractedFilesExtensionHak.txt)"
echo "${RED}[*] Sensitive files (hakrawler):${RESET} $(wc -l < resultsFilesHak/sensitiveUrlsHak.txt)"

if [ "$skip_ports" = false ]; then
    echo "${YELLOW}[*] Unique open ports detected:${RESET} $(cut -d ":" -f2 naabuPortScan.txt | sort -u | wc -l)"
    echo
    echo "${GREEN}[*] Top open ports:${RESET}"
    cut -d ":" -f2 naabuPortScan.txt | sort | uniq -c | sort -nr | head -10
fi

echo
echo "================================================================================"
echo "[*] VPScanner Finished!"
