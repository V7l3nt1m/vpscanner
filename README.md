========================================================
VPScanner - Automated Recon Script
========================================================

DESCRIPTION:
-------------
VPScanner is a fully automated reconnaissance script designed for bug bounty hunters and penetration testers. 
It performs:
  - Subdomain enumeration
  - Alive subdomain detection
  - Screenshots of subdomains
  - Wayback URL collection and filtering
  - Sensitive file/URL detection
  - GF pattern filtering
  - Optional port scanning

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

CONTACT:
--------
Author: Valentim Prado (v7l3nt1m)

GitHub: https://github.com/V7l3nt1m/vpscanner

Hackerone: https://hackerone.com/v7l3nt1m

Linkdin: https://www.linkedin.com/in/valentim-prado-25ab6124b/

LICENSE:
--------
This script is provided as-is for educational purposes. Use responsibly and ethically.

========================================================
