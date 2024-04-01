### Find SQL vulnerabilities:
./recon.sh --find-sql-vuln -w target.com
### Find Header Blind vulnerabilities:
./recon.sh --header-blind -w target.com
### Find Time-Based Blind SQL Injection vulnerabilities:
./recon.sh --time-based -w target.com
### Extract URLs from source code:
./recon.sh --extract-urls -u https://target.com
### Find XSS vulnerabilities:
./recon.sh --xss -u https://target.com -b https://chirag.bxss.in
### Find endpoints in JavaScript files:
./recon.sh --find-js-endpoint -u https://target.com
### Check for wp-config.php files:
./recon.sh --wp-config -w target.com
### Find Information Disclosure in JSON body:
./recon.sh --info-disclosure-json -w target.com
