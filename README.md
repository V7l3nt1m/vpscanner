========================================================
VPScanner - Automated Recon Script
========================================================

CONTACT:
--------
[![License](https://img.shields.io/badge/License-Educational-lightgrey.svg)](LICENSE) 
[![HackerOne](https://img.shields.io/badge/HackerOne-v7l3nt1m-blue)](https://hackerone.com/v7l3nt1m) 
[![GitHub](https://img.shields.io/badge/GitHub-V7l3nt1m-green)](https://github.com/V7l3nt1m/vpscanner) 
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Valentim_Prado-blue)](https://www.linkedin.com/in/valentim-prado-25ab6124b/)

DESCRIPTION:
-------------
VPScanner is a fully automated reconnaissance script designed for bug bounty hunters and penetration testers. 

It performs:

- Subdomain enumeration (subfinder, sublist3r, assetfinder, findomain, amass and crt.sh)  
- Alive subdomain detection (httpx)  
- Screenshots of alive subdomains (gowitness)  
- Wayback URL collection & filtering (gau, uro)  
- Sensitive file/URL detection (ripgrep)  
- GF pattern filtering (gf)  
- Hakrawler fuzzing for additional URLs  
- Optional port scanning (naabu + nmap)  

✅ Automatic retries for failed commands  
✅ Internet connectivity checks before each step  
✅ Parallel execution for faster processing  
✅ Timestamped, organized outputs  

REQUIREMENTS:
-------------
Make sure the following tools are installed on your system:

- subfinder
- sublist3r
- assetfinder
- amass
- findomain
- httpx
- gau
- uro
- ripgrep (rg)
- gf
- gowitness
- naabu
- nmap
- hakrawler

USAGE:
------
Basic usage:
    ./VPScanner.sh <wordlist>

Skip port scanning:
    ./VPScanner.sh <wordlist> --skip-ports

ARGUMENTS:
----------
<wordlist>      : Path to a file containing domains to enumerate
--skip-ports    : Optional flag to skip open port scanning

OUTPUT:
-------
All output files will be saved in a folder named results_<timestamp>. The main outputs include:

- final_subdomains.txt      : List of unique subdomains found
- subdomains_alive.txt      : Alive subdomains detected
- subSemHttpx.txt           : Alive subdomains without HTTP scheme
- screenshots/              : Full-page screenshots of alive subdomains
- subdomains404.txt         : Subdomains returning HTTP 404
- cnames_detected404.txt    : Extracted CNAMEs from 404 subdomains
- allwaybacksurls.txt       : Wayback URLs collected
- gauUrls.txt               : Filtered URLs from uro
- resultsFiles/sensitiveUrls.txt : Detected sensitive URLs
- gf_results/               : URLs filtered by GF patterns
- naabuPortScan.txt         : Open ports discovered (if not skipped)
- nmapResults.txt           : Detailed nmap results for open ports

NOTES:
------
- Ensure all dependencies are installed and accessible from your PATH.
- Recommended to run on Linux or WSL.
- Internet connection is required for most tools to work.
- Script includes automatic retries for subdomain enumeration tools if they fail.

========================================================
