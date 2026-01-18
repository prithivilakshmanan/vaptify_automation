#!/usr/bin/env python3

import subprocess
import argparse
import sys

# ================= ANSI STYLES =================
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"

TIMEOUT = 90

# ================= UTILS =================
def run(cmd):
    p = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=TIMEOUT
    )
    return p.stdout.strip()

def logo():
    print(f"""
{CYAN}{BOLD}
██╗   ██╗ █████╗ ██████╗ ████████╗███████╗██╗███████╗██╗   ██╗
██║   ██║██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║██╔════╝╚██╗ ██╔╝
██║   ██║███████║██████╔╝   ██║   █████╗  ██║█████╗   ╚████╔╝ 
╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   ██╔══╝  ██║██╔══╝    ╚██╔╝  
 ╚████╔╝ ██║  ██║██║        ██║   ██║     ██║███████╗   ██║   
  ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   ╚═╝     ╚═╝╚══════╝   ╚═╝   

                 VAPTIFY
        Automated VA Reporting Tool
{RESET}
""")

def banner(title):
    print(f"\n{BOLD}🔍 {title}{RESET}")
    print(f"{BLUE}{'-'*75}{RESET}")

def show_cmd(tool, cmd):
    print(f"{BLUE}[Tool]{RESET} {tool}")
    print(f"{BLUE}[CMD ]{RESET} {cmd}")

def vuln_result(name, vulnerable, output, summary):
    status = "VULNERABLE" if vulnerable else "NOT VULNERABLE"
    color = RED if vulnerable else GREEN
    summary[name] = status

    print(f"{color}{BOLD}[{status}] {name}{RESET}")
    print(f"{YELLOW}--- Details ---{RESET}")
    print(output if output else "No output")
    print(f"{BLUE}{'-'*75}{RESET}")

# ================= CHECKS =================
def run_checks(domain):
    summary = {}

    print(f"\n{CYAN}{BOLD}========== SCAN STARTED : {domain} =========={RESET}")

    # 1. SPF Record Not Configured
    banner("SPF Record Check")
    show_cmd("dig", f"dig txt {domain}")
    out = run(f"dig txt {domain}")
    vuln_result("SPF", "v=spf1" not in out.lower(), out, summary)

    # 2. DMARC Record Not Configured
    banner("DMARC Record Check")
    show_cmd("dig", f"dig txt _dmarc.{domain}")
    out = run(f"dig txt _dmarc.{domain}")
    vuln_result("DMARC", "v=dmarc1" not in out.lower(), out, summary)

    # 3. DKIM Record Not Configured
    banner("DKIM Record Check")
    show_cmd("dig", f"dig txt default._domainkey.{domain}")
    out = run(f"dig txt default._domainkey.{domain}")
    vuln_result("DKIM", "v=dkim1" not in out.lower(), out, summary)

    # 4. Direct IP Accessible
    banner("Direct IP Accessibility Check")
    show_cmd("dig", f"dig +short {domain}")
    ips = run(f"dig +short {domain}").splitlines()

    vulnerable = False
    output = ""
    if ips:
        ip = ips[0]
        show_cmd("curl", f"curl http://{ip}")
        code = run(f"curl -o /dev/null -s -w '%{{http_code}}' http://{ip}")
        output = f"IP: {ip}\nHTTP Status Code: {code}"
        if code == "200":
            vulnerable = True

    vuln_result("Direct IP Accessible", vulnerable, output, summary)

    # 5. Missing Security Headers
    banner("Missing Security Headers Check")
    show_cmd("curl", f"curl -I https://{domain}")
    headers = run(f"curl -I https://{domain}").lower()

    required_headers = [
        "strict-transport-security",
        "x-xss-protection",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "content-security-policy"
    ]

    missing = [h for h in required_headers if h not in headers]
    vuln_result(
        "Security Headers",
        len(missing) > 0,
        "Missing Headers:\n" + "\n".join(missing) if missing else "All required security headers are present",
        summary
    )

    # 6. Server Version Disclosure
    banner("Server Version Disclosure Check")
    show_cmd("curl", f"curl -I https://{domain}")
    out = run(f"curl -I https://{domain}")
    disclosed = any(h in out.lower() for h in ["server:", "x-powered-by"])
    vuln_result("Server Version Disclosure", disclosed, out, summary)

    # 7. TLS / SSL Configuration
    banner("TLS / SSL Configuration & Vulnerability Check")
    show_cmd(
        "testssl.sh",
        f"testssl.sh --protocols --cipher-per-proto --vulnerable {domain}"
    )

    tls_out = run(f"testssl.sh --protocols --cipher-per-proto --vulnerable {domain}").lower()

    bad_indicators = [
        "ssl v2 offered",
        "ssl v3 offered",
        "tls 1 offered",
        "tls 1.1 offered",
        "null ciphers offered",
        "anonymous",
        "export ciphers offered",
        "low:",
        "rc4",
        "3des",
        "sweet32",
        "lucky13",
        "breach",
        "poodle",
        "heartbleed vulnerable",
        "crime",
        "freak",
        "drown",
        "logjam",
        "beast"
    ]

    findings = [i for i in bad_indicators if i in tls_out]

    vuln_result(
        "TLS / SSL Configuration",
        len(findings) > 0,
        "Issues Found:\n" + "\n".join(findings) if findings else "TLS configuration is secure (No weak protocols, ciphers, or vulnerabilities)",
        summary
    )

    # 8. Missing HTTPOnly & Secure Cookie Flags
    banner("HTTPOnly & Secure Cookie Flags Check")
    show_cmd("curl", f"curl -I https://{domain}")
    out = run(f"curl -I https://{domain}").lower()
    vuln_result(
        "Cookie Flags",
        not ("httponly" in out and "secure" in out),
        out,
        summary
    )

    # ================= FINAL SUMMARY =================
    print(f"\n{CYAN}{BOLD}========== FINAL SUMMARY : {domain} =========={RESET}")
    for k, v in summary.items():
        color = GREEN if v == "NOT VULNERABLE" else RED
        print(f"{color}{k:<35} : {v}{RESET}")

# ================= MAIN =================
parser = argparse.ArgumentParser(description="VAPTIFY - Automated VA Scanning Tool")
parser.add_argument("-d", help="Single domain or subdomain")
parser.add_argument("-t", help="File with list of domains")

args = parser.parse_args()

logo()

if args.d:
    run_checks(args.d.strip())
elif args.t:
    with open(args.t) as f:
        for line in f:
            domain = line.strip()
            if domain:
                run_checks(domain)
else:
    parser.print_help()
    sys.exit(1)
