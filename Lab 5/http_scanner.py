import requests

BASE_URL = "http://localhost:3000"

# Endpoints to probe (method, path, parameter key for injection)
ENDPOINTS = [
    ("GET",  "/rest/products/search", "q"),
    ("GET",  "/api/Products",         None),
    ("GET",  "/api/Challenges",       None),
    ("POST", "/rest/user/login",      None),
    ("GET",  "/api/Feedbacks",        None),
    ("GET",  "/redirect",             "to"),
]

# Sample input values injected into the parameter field
SAMPLE_INPUTS = [
    "test",
    "admin",
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "../../../../etc/passwd",
]

# Security headers every server should set
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
]



def log_result(method, endpoint, payload, status_code, resp_length):
    print(f"  {method:5s} | {endpoint:40s} | "
          f"Payload: {str(payload):35s} | "
          f"Status: {status_code} | Length: {resp_length}")


def scan_endpoint(method, path, param_key, payload=None):
    url = f"{BASE_URL}{path}"
    try:
        if method == "GET":
            params = {param_key: payload} if param_key and payload else None
            resp = requests.get(url, params=params, timeout=10)
        else:  # POST
            json_body = {"email": payload, "password": payload} if payload else {}
            resp = requests.post(url, json=json_body, timeout=10)
        return resp.status_code, len(resp.text), resp
    except requests.RequestException as e:
        print(f"  [!] Connection error on {method} {path}: {e}")
        return None, None, None


# ── Part 1 – Reconnaissance
def run_recon():
    """Fetch the main page and dump all response headers to show server chattiness."""
    print("=" * 120)
    print("PART 1 – Reconnaissance (Attack Surface & Server Fingerprinting)")
    print("=" * 120)

    try:
        resp = requests.get(BASE_URL, timeout=10)
    except requests.RequestException as e:
        print(f"  [!] Could not reach {BASE_URL}: {e}")
        return

    print(f"\n  HTTP {resp.status_code} from {BASE_URL}")
    print(f"  All response headers (look for information leakage):")
    for header, value in resp.headers.items():
        print(f"    {header}: {value}")

    print(f"\n  Endpoints being tested:")
    for method, path, param in ENDPOINTS:
        tag = f"  param={param}" if param else ""
        print(f"    {method:5s} {path}{tag}")

    print()


# ── Part 2 – Endpoint Scanning 
def run_endpoint_scan():
    """Iterate over endpoints × payloads and log every response."""
    print("=" * 120)
    print("PART 2 – HTTP Endpoint Scan")
    print("=" * 120)

    for method, path, param_key in ENDPOINTS:
        # If the endpoint accepts a parameter, send each sample input
        if param_key or method == "POST":
            for payload in SAMPLE_INPUTS:
                status, length, _ = scan_endpoint(method, path, param_key, payload)
                if status is not None:
                    log_result(method, path, payload, status, length)
        else:
            # No parameter – just request the endpoint once
            status, length, _ = scan_endpoint(method, path, None)
            if status is not None:
                log_result(method, path, "N/A", status, length)

    print()


# ── Part 5 – Security Header Analysis 
def run_header_check():
    """Fetch the main page and flag missing security headers."""
    print("=" * 120)
    print("PART 5 – Security Header Analysis")
    print("=" * 120)

    try:
        resp = requests.get(BASE_URL, timeout=10)
    except requests.RequestException as e:
        print(f"  [!] Could not reach {BASE_URL}: {e}")
        return []

    missing = []
    print(f"\n  Response headers from {BASE_URL}:")
    for header in SECURITY_HEADERS:
        value = resp.headers.get(header)
        if value:
            print(f"    [OK]      {header}: {value}")
        else:
            print(f"    [WARNING] {header}: MISSING  –  Low Severity")
            missing.append(header)

    print()
    return missing


# ── Main 
if __name__ == "__main__":
    print("\n  Point-in-Time Vulnerability Assessment")
    print("  Target: OWASP Juice Shop @ {}\n".format(BASE_URL))
    run_recon()
    run_endpoint_scan()
    missing_headers = run_header_check()

    print("=" * 120)
    print("Scan complete.")
    if missing_headers:
        print(f"  Missing security headers: {', '.join(missing_headers)}")
    print("=" * 120)
