#!/usr/bin/env python3

import subprocess
import argparse
import sys
import re

# ================= ANSI STYLES =================
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
RESET = "\033[0m"

DEFAULT_TIMEOUT = 90
TESTSSL_TIMEOUT = 300

# ================= UTILS =================
def run(cmd, timeout=DEFAULT_TIMEOUT):
    try:
        p = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return p.stdout.strip()
    except subprocess.TimeoutExpired:
        return "__TIMEOUT__"
    except Exception as e:
        return f"__ERROR__:{e}"

def logo():
    print(f"""
          {CYAN}{BOLD}
██╗   ██╗ █████╗ ██████╗ ████████╗██╗███████╗██╗   ██╗
██║   ██║██╔══██╗██╔══██╗╚══██╔══╝██║██╔════╝╚██╗ ██╔╝
██║   ██║███████║██████╔╝   ██║   ██║█████╗   ╚████╔╝ 
╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   ██║██╔══╝    ╚██╔╝  
 ╚████╔╝ ██║  ██║██║        ██║   ██║██         ██║   
  ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   ╚═╝╚═         ╚═╝   

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

def result(name, status, output, summary):
    summary[name] = status
    color = GREEN if status == "NOT VULNERABLE" else RED if status == "VULNERABLE" else YELLOW

    print(f"{color}{BOLD}[{status}] {name}{RESET}")
    print(f"{YELLOW}--- Details ---{RESET}")
    print(output if output else "No output")
    print(f"{BLUE}{'-'*75}{RESET}")

# ================= CHECKS =================
def run_checks(domain):
    summary = {}

    print(f"\n{CYAN}{BOLD}========== SCAN STARTED : {domain} =========={RESET}")

    # 1. SPF
    banner("SPF Record Check")
    try:
        show_cmd("dig", f"dig txt {domain}")
        out = run(f"dig txt {domain}")
        if "__" in out:
            raise Exception(out)
        status = "VULNERABLE" if "v=spf1" not in out.lower() else "NOT VULNERABLE"
        result("SPF", status, out, summary)
    except Exception as e:
        result("SPF", "SCAN ERROR", str(e), summary)

    # 2. DMARC
    banner("DMARC Record Check")
    try:
        show_cmd("dig", f"dig txt _dmarc.{domain}")
        out = run(f"dig txt _dmarc.{domain}")
        if "__" in out:
            raise Exception(out)
        status = "VULNERABLE" if "v=dmarc1" not in out.lower() else "NOT VULNERABLE"
        result("DMARC", status, out, summary)
    except Exception as e:
        result("DMARC", "SCAN ERROR", str(e), summary)

    # 3. DKIM
    banner("DKIM Record Check")
    try:
        show_cmd("dig", f"dig txt default._domainkey.{domain}")
        out = run(f"dig txt default._domainkey.{domain}")
        if "__" in out:
            raise Exception(out)
        status = "VULNERABLE" if "v=dkim1" not in out.lower() else "NOT VULNERABLE"
        result("DKIM", status, out, summary)
    except Exception as e:
        result("DKIM", "SCAN ERROR", str(e), summary)

    # 4. Direct IP
    banner("Direct IP Accessibility Check")
    try:
        show_cmd("dig", f"dig +short {domain}")
        ips = run(f"dig +short {domain}").splitlines()
        if not ips:
            raise Exception("No IP resolved")

        ip = ips[0]
        show_cmd("curl", f"curl http://{ip}")
        code = run(f"curl -o /dev/null -s -w '%{{http_code}}' http://{ip}")
        status = "VULNERABLE" if code == "200" else "NOT VULNERABLE"
        result("Direct IP Accessible", status, f"IP: {ip}\nHTTP Code: {code}", summary)
    except Exception as e:
        result("Direct IP Accessible", "SCAN ERROR", str(e), summary)

    # 5. Security Headers
    banner("Missing Security Headers Check")
    try:
        show_cmd("curl", f"curl -I https://{domain}")
        headers = run(f"curl -I https://{domain}")
        if "__" in headers:
            raise Exception(headers)

        required = [
            "strict-transport-security",
            "x-xss-protection",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
            "content-security-policy"
        ]
        missing = [h for h in required if h not in headers.lower()]
        status = "VULNERABLE" if missing else "NOT VULNERABLE"
        result("Security Headers", status, "\n".join(missing) if missing else "All headers present", summary)
    except Exception as e:
        result("Security Headers", "SCAN ERROR", str(e), summary)

    # 6. Server Version Disclosure (FIXED)
    banner("Server Version Disclosure Check")
    try:
        show_cmd("curl", f"curl -I https://{domain}")
        out = run(f"curl -I https://{domain}")

        vulnerable = False
        findings = []

        for line in out.splitlines():
            l = line.lower()

            # Server header with version number
            if l.startswith("server:"):
                if re.search(r"\d+\.\d+", l):
                    vulnerable = True
                    findings.append(line.strip())

            # X-Powered-By always disclosure
            if l.startswith("x-powered-by:"):
                vulnerable = True
                findings.append(line.strip())

        status = "VULNERABLE" if vulnerable else "NOT VULNERABLE"
        details = "\n".join(findings) if findings else "No server version disclosed"
        result("Server Version Disclosure", status, details, summary)

    except Exception as e:
        result("Server Version Disclosure", "SCAN ERROR", str(e), summary)

    # 7. TLS / SSL
    banner("TLS / SSL Configuration & Vulnerability Check")
    try:
        show_cmd("testssl.sh", f"testssl.sh --fast {domain}")
        tls_out = run(f"testssl.sh --fast {domain}", timeout=TESTSSL_TIMEOUT)

        if tls_out in ["__TIMEOUT__"] or tls_out.startswith("__ERROR__"):
            raise Exception("TLS scan timed out or failed")

        tls_out = tls_out.lower()

        # Vulnerable ONLY if NOT marked OK
        bad_patterns = [
            "offered (not ok)",
            "vulnerable",
            "potentially not ok"
        ]

        vulnerable = any(p in tls_out for p in bad_patterns)

        result(
            "TLS / SSL Configuration",
            "VULNERABLE" if vulnerable else "NOT VULNERABLE",
            "TLS scan completed successfully",
            summary
        )

    except Exception as e:
        result("TLS / SSL Configuration", "SCAN ERROR", str(e), summary)

    # 8. Cookies
    banner("HTTPOnly & Secure Cookie Flags Check")
    try:
        show_cmd("curl", f"curl -I https://{domain}")
        out = run(f"curl -I https://{domain}")
        status = "NOT VULNERABLE" if "httponly" in out.lower() and "secure" in out.lower() else "VULNERABLE"
        result("Cookie Flags", status, out, summary)
    except Exception as e:
        result("Cookie Flags", "SCAN ERROR", str(e), summary)

    # ================= SUMMARY =================
    print(f"\n{CYAN}{BOLD}========== FINAL SUMMARY : {domain} =========={RESET}")
    for k, v in summary.items():
        color = GREEN if v == "NOT VULNERABLE" else RED if v == "VULNERABLE" else YELLOW
        print(f"{color}{k:<35} : {v}{RESET}")

# ================= MAIN =================
parser = argparse.ArgumentParser(description="VAPTIFY - Automated VA Scanning Tool")
parser.add_argument("-d", help="Single domain")
parser.add_argument("-t", help="File with domains")

args = parser.parse_args()
logo()

if args.d:
    run_checks(args.d.strip())
elif args.t:
    with open(args.t) as f:
        for d in f:
            if d.strip():
                run_checks(d.strip())
else:
    parser.print_help()
    sys.exit(1)
