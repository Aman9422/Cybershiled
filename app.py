"""
CyberShield — Cybersecurity Toolkit Backend
Flask API serving 8 security tools.
"""

from flask import Flask, render_template, request, jsonify
import hashlib
import requests
import socket
import base64
import re
import math
import string
import secrets
import urllib.parse
from collections import Counter

app = Flask(__name__)

# ──────────────────────────────────────────────
# ROUTE: Home
# ──────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ──────────────────────────────────────────────
# API 1: Password Strength Analyzer
# ──────────────────────────────────────────────
@app.route("/api/password-analyze", methods=["POST"])
def password_analyze():
    data = request.json
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "Password is required"}), 400

    # Charset size for entropy
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>?/`~\\]", password):
        charset += 32

    entropy = len(password) * math.log2(charset) if charset else 0

    # Criteria checks
    common_passwords = [
        "password", "123456", "123456789", "qwerty", "abc123",
        "monkey", "master", "dragon", "111111", "baseball",
        "iloveyou", "trustno1", "sunshine", "princess", "football",
        "shadow", "superman", "letmein", "welcome", "admin",
    ]
    sequential = [
        "abc", "bcd", "cde", "def", "efg", "123", "234",
        "345", "456", "567", "678", "789", "qwe", "wer",
        "ert", "rty", "asd", "sdf", "dfg", "zxc", "xcv",
    ]

    checks = {
        "min_length_8": len(password) >= 8,
        "min_length_12": len(password) >= 12,
        "min_length_16": len(password) >= 16,
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>?/`~\\]", password)),
        "no_common": password.lower() not in common_passwords,
        "no_repeating": not re.search(r"(.)\1{2,}", password),
        "no_sequential": not any(s in password.lower() for s in sequential),
    }

    score = sum(checks.values())

    if score <= 3:
        strength = "Very Weak"
        color = "#ff4444"
    elif score <= 5:
        strength = "Weak"
        color = "#ff8800"
    elif score <= 7:
        strength = "Fair"
        color = "#ffcc00"
    elif score <= 9:
        strength = "Strong"
        color = "#88cc00"
    else:
        strength = "Very Strong"
        color = "#00ff88"

    # Crack-time estimation (10 billion guesses/sec)
    gps = 1e10
    combos = charset ** len(password) if charset else 0
    secs = combos / gps if gps else 0

    if secs < 1:
        crack_time = "Instantly"
    elif secs < 60:
        crack_time = f"{secs:.0f} seconds"
    elif secs < 3600:
        crack_time = f"{secs / 60:.0f} minutes"
    elif secs < 86400:
        crack_time = f"{secs / 3600:.0f} hours"
    elif secs < 2592000:
        crack_time = f"{secs / 86400:.0f} days"
    elif secs < 31536000:
        crack_time = f"{secs / 2592000:.0f} months"
    elif secs < 31536000 * 1000:
        crack_time = f"{secs / 31536000:.0f} years"
    elif secs < 31536000 * 1e6:
        crack_time = f"{secs / 31536000:.2e} years"
    else:
        crack_time = "Centuries+"

    # HaveIBeenPwned check
    breached = False
    breach_count = 0
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5
        )
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                h, c = line.split(":")
                if h == suffix:
                    breached = True
                    breach_count = int(c)
                    break
    except Exception:
        pass

    return jsonify(
        {
            "length": len(password),
            "entropy": round(entropy, 2),
            "score": score,
            "max_score": len(checks),
            "strength": strength,
            "color": color,
            "checks": checks,
            "crack_time": crack_time,
            "breached": breached,
            "breach_count": breach_count,
        }
    )


# ──────────────────────────────────────────────
# API 2: Secure Password Generator
# ──────────────────────────────────────────────
@app.route("/api/password-generate", methods=["POST"])
def password_generate():
    data = request.json
    length = min(max(int(data.get("length", 16)), 4), 128)
    use_upper = data.get("uppercase", True)
    use_lower = data.get("lowercase", True)
    use_digits = data.get("digits", True)
    use_special = data.get("special", True)
    exclude_ambiguous = data.get("exclude_ambiguous", False)

    pool = ""
    required = []

    if use_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace("l", "").replace("o", "")
        pool += chars
        required.append(secrets.choice(chars))
    if use_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace("I", "").replace("O", "")
        pool += chars
        required.append(secrets.choice(chars))
    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace("0", "").replace("1", "")
        pool += chars
        required.append(secrets.choice(chars))
    if use_special:
        chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        pool += chars
        required.append(secrets.choice(chars))

    if not pool:
        pool = string.ascii_letters + string.digits

    remaining = length - len(required)
    pwd_list = required + [secrets.choice(pool) for _ in range(remaining)]

    # Shuffle using Fisher-Yates via secrets
    for i in range(len(pwd_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd_list[i], pwd_list[j] = pwd_list[j], pwd_list[i]

    password = "".join(pwd_list)
    return jsonify({"password": password, "length": len(password)})


# ──────────────────────────────────────────────
# API 3: Hash Generator
# ──────────────────────────────────────────────
@app.route("/api/hash-generate", methods=["POST"])
def hash_generate():
    data = request.json
    text = data.get("text", "")

    results = {
        "MD5": hashlib.md5(text.encode()).hexdigest(),
        "SHA-1": hashlib.sha1(text.encode()).hexdigest(),
        "SHA-256": hashlib.sha256(text.encode()).hexdigest(),
        "SHA-512": hashlib.sha512(text.encode()).hexdigest(),
        "SHA3-256": hashlib.sha3_256(text.encode()).hexdigest(),
        "SHA3-512": hashlib.sha3_512(text.encode()).hexdigest(),
        "BLAKE2b": hashlib.blake2b(text.encode()).hexdigest(),
        "BLAKE2s": hashlib.blake2s(text.encode()).hexdigest(),
    }

    return jsonify(results)


# ──────────────────────────────────────────────
# API 4: Encoder / Decoder
# ──────────────────────────────────────────────
@app.route("/api/encode-decode", methods=["POST"])
def encode_decode():
    data = request.json
    text = data.get("text", "")
    operation = data.get("operation", "encode")
    method = data.get("method", "base64")
    key = data.get("key", "3")

    try:
        if method == "base64":
            if operation == "encode":
                result = base64.b64encode(text.encode()).decode()
            else:
                result = base64.b64decode(text.encode()).decode()

        elif method == "base32":
            if operation == "encode":
                result = base64.b32encode(text.encode()).decode()
            else:
                result = base64.b32decode(text.encode()).decode()

        elif method == "hex":
            if operation == "encode":
                result = text.encode().hex()
            else:
                result = bytes.fromhex(text).decode()

        elif method == "binary":
            if operation == "encode":
                result = " ".join(format(ord(c), "08b") for c in text)
            else:
                bits = text.replace(" ", "")
                result = "".join(
                    chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits), 8)
                )

        elif method == "url":
            if operation == "encode":
                result = urllib.parse.quote(text, safe="")
            else:
                result = urllib.parse.unquote(text)

        elif method == "caesar":
            shift = int(key) if key.lstrip("-").isdigit() else 3
            if operation == "decode":
                shift = -shift
            result = ""
            for ch in text:
                if ch.isalpha():
                    base = ord("A") if ch.isupper() else ord("a")
                    result += chr((ord(ch) - base + shift) % 26 + base)
                else:
                    result += ch

        elif method == "rot13":
            result = ""
            for ch in text:
                if ch.isalpha():
                    base = ord("A") if ch.isupper() else ord("a")
                    result += chr((ord(ch) - base + 13) % 26 + base)
                else:
                    result += ch

        elif method == "xor":
            k = key if key else "K"
            xored = "".join(
                chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(text)
            )
            if operation == "encode":
                result = base64.b64encode(xored.encode("latin-1")).decode()
            else:
                decoded = base64.b64decode(text).decode("latin-1")
                result = "".join(
                    chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(decoded)
                )

        elif method == "morse":
            MORSE = {
                "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".",
                "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---",
                "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---",
                "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-",
                "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--",
                "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
                "3": "...--", "4": "....-", "5": ".....", "6": "-....",
                "7": "--...", "8": "---..", "9": "----.", " ": "/",
            }
            if operation == "encode":
                result = " ".join(MORSE.get(c.upper(), c) for c in text)
            else:
                REV = {v: k for k, v in MORSE.items()}
                result = "".join(REV.get(c, c) for c in text.split(" "))

        else:
            result = "Unsupported method"

        return jsonify({"result": result, "method": method, "operation": operation})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ──────────────────────────────────────────────
# API 5: Port Scanner
# ──────────────────────────────────────────────
@app.route("/api/port-scan", methods=["POST"])
def port_scan():
    data = request.json
    target = data.get("target", "").strip()

    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPCBind",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        587: "SMTP-TLS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"error": f"Cannot resolve hostname: {target}"}), 400

    open_ports = []
    closed_count = 0

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                # Try banner grab
                banner = ""
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(100).decode("utf-8", errors="ignore").strip()[:80]
                except Exception:
                    pass
                open_ports.append(
                    {"port": port, "service": service, "status": "Open", "banner": banner}
                )
            else:
                closed_count += 1
            sock.close()
        except Exception:
            closed_count += 1

    return jsonify(
        {
            "target": target,
            "ip": target_ip,
            "open_ports": open_ports,
            "open_count": len(open_ports),
            "closed_count": closed_count,
            "total_scanned": len(COMMON_PORTS),
        }
    )


# ──────────────────────────────────────────────
# API 6: Security Headers Checker
# ──────────────────────────────────────────────
@app.route("/api/security-headers", methods=["POST"])
def security_headers():
    data = request.json
    url = data.get("url", "").strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    HEADERS_INFO = {
        "Strict-Transport-Security": {
            "desc": "Enforces HTTPS connections to the server",
            "severity": "high",
            "weight": 15,
        },
        "Content-Security-Policy": {
            "desc": "Prevents XSS, clickjacking, and code injection",
            "severity": "high",
            "weight": 15,
        },
        "X-Frame-Options": {
            "desc": "Prevents clickjacking via framing",
            "severity": "medium",
            "weight": 10,
        },
        "X-Content-Type-Options": {
            "desc": "Prevents MIME-type sniffing",
            "severity": "medium",
            "weight": 10,
        },
        "Referrer-Policy": {
            "desc": "Controls referrer information leakage",
            "severity": "medium",
            "weight": 10,
        },
        "Permissions-Policy": {
            "desc": "Controls browser feature permissions",
            "severity": "medium",
            "weight": 10,
        },
        "X-XSS-Protection": {
            "desc": "Legacy XSS filter (deprecated but still useful)",
            "severity": "low",
            "weight": 5,
        },
        "X-Permitted-Cross-Domain-Policies": {
            "desc": "Restricts cross-domain policy files",
            "severity": "low",
            "weight": 5,
        },
        "Cross-Origin-Opener-Policy": {
            "desc": "Isolates browsing context",
            "severity": "medium",
            "weight": 10,
        },
        "Cross-Origin-Resource-Policy": {
            "desc": "Blocks cross-origin resource loading",
            "severity": "medium",
            "weight": 10,
        },
    }

    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        headers = dict(resp.headers)

        results = []
        total_weight = sum(h["weight"] for h in HEADERS_INFO.values())
        earned = 0

        for header, info in HEADERS_INFO.items():
            present = any(h.lower() == header.lower() for h in headers)
            value = ""
            if present:
                for h in headers:
                    if h.lower() == header.lower():
                        value = headers[h]
                        break
                earned += info["weight"]

            results.append(
                {
                    "header": header,
                    "present": present,
                    "value": value if present else "Not Set",
                    "description": info["desc"],
                    "severity": info["severity"],
                }
            )

        pct = (earned / total_weight) * 100 if total_weight else 0
        if pct >= 90:
            grade = "A+"
        elif pct >= 80:
            grade = "A"
        elif pct >= 70:
            grade = "B"
        elif pct >= 55:
            grade = "C"
        elif pct >= 40:
            grade = "D"
        else:
            grade = "F"

        return jsonify(
            {
                "url": url,
                "status_code": resp.status_code,
                "results": results,
                "score": round(pct),
                "grade": grade,
                "server": headers.get("Server", "Hidden"),
                "powered_by": headers.get("X-Powered-By", "Hidden"),
            }
        )
    except requests.exceptions.SSLError:
        return jsonify({"error": "SSL Certificate verification failed"}), 400
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "Could not connect to the server"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ──────────────────────────────────────────────
# API 7: Phishing URL Detector
# ──────────────────────────────────────────────
@app.route("/api/phishing-check", methods=["POST"])
def phishing_check():
    data = request.json
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    path = parsed.path

    indicators = []
    risk = 0

    # 1. IP address instead of domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain.split(":")[0]):
        indicators.append(
            {"test": "IP address used instead of domain name", "risk": "High", "pts": 20}
        )
        risk += 20

    # 2. Suspicious TLDs
    sus_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                ".click", ".link", ".buzz", ".surf", ".rest", ".fit"]
    if any(domain.lower().endswith(t) for t in sus_tlds):
        indicators.append(
            {"test": "Suspicious/free top-level domain", "risk": "Medium", "pts": 12}
        )
        risk += 12

    # 3. Excessive subdomains
    dots = domain.count(".")
    if dots > 3:
        indicators.append(
            {"test": f"Excessive subdomains ({dots} levels)", "risk": "High", "pts": 15}
        )
        risk += 15

    # 4. Long domain
    if len(domain) > 30:
        indicators.append(
            {"test": f"Unusually long domain ({len(domain)} chars)", "risk": "Medium", "pts": 8}
        )
        risk += 8

    # 5. Phishing keywords
    keywords = ["login", "signin", "verify", "secure", "account", "update",
                 "confirm", "banking", "paypal", "ebay", "amazon", "microsoft",
                 "apple", "google", "facebook", "netflix", "support", "helpdesk"]
    found = [k for k in keywords if k in url.lower()]
    if len(found) >= 2:
        indicators.append(
            {"test": f"Multiple suspicious keywords: {', '.join(found)}", "risk": "High", "pts": 18}
        )
        risk += 18
    elif found:
        indicators.append(
            {"test": f"Suspicious keyword: {', '.join(found)}", "risk": "Low", "pts": 5}
        )
        risk += 5

    # 6. @ symbol
    if "@" in url:
        indicators.append(
            {"test": "@ symbol (URL redirect trick)", "risk": "Critical", "pts": 25}
        )
        risk += 25

    # 7. HTTPS check
    if not url.lower().startswith("https"):
        indicators.append(
            {"test": "Missing HTTPS encryption", "risk": "Medium", "pts": 10}
        )
        risk += 10

    # 8. URL length
    if len(url) > 100:
        indicators.append(
            {"test": f"Very long URL ({len(url)} chars)", "risk": "Medium", "pts": 8}
        )
        risk += 8

    # 9. Hyphens in domain
    hyphens = domain.count("-")
    if hyphens > 2:
        indicators.append(
            {"test": f"Multiple hyphens in domain ({hyphens})", "risk": "Medium", "pts": 10}
        )
        risk += 10

    # 10. Data URI or javascript
    if url.lower().startswith(("data:", "javascript:")):
        indicators.append(
            {"test": "Data/JavaScript URI scheme", "risk": "Critical", "pts": 30}
        )
        risk += 30

    # 11. Punycode / IDN
    if "xn--" in domain.lower():
        indicators.append(
            {"test": "Punycode/Internationalized domain (homograph risk)", "risk": "High", "pts": 20}
        )
        risk += 20

    # 12. Double slashes in path
    if "//" in path:
        indicators.append(
            {"test": "Double slashes in path (redirect trick)", "risk": "Low", "pts": 5}
        )
        risk += 5

    # 13. Shortener domains
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd",
                   "buff.ly", "ow.ly", "rebrand.ly", "bl.ink"]
    if domain.lower() in shorteners:
        indicators.append(
            {"test": "URL shortener service used", "risk": "Medium", "pts": 12}
        )
        risk += 12

    risk = min(risk, 100)

    if risk >= 70:
        verdict = "High Risk — Likely Phishing"
        verdict_color = "#ff4444"
    elif risk >= 40:
        verdict = "Medium Risk — Suspicious"
        verdict_color = "#ffaa00"
    elif risk >= 20:
        verdict = "Low Risk — Minor Concerns"
        verdict_color = "#ffcc00"
    else:
        verdict = "Minimal Risk — Appears Safe"
        verdict_color = "#00ff88"

    return jsonify(
        {
            "url": url,
            "domain": domain,
            "risk_score": risk,
            "verdict": verdict,
            "verdict_color": verdict_color,
            "indicators": indicators,
        }
    )


# ──────────────────────────────────────────────
# API 8: IP Geolocation Lookup
# ──────────────────────────────────────────────
@app.route("/api/ip-lookup", methods=["POST"])
def ip_lookup():
    data = request.json
    ip = data.get("ip", "").strip()

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,"
            f"countryCode,region,regionName,city,zip,lat,lon,timezone,"
            f"isp,org,as,query,mobile,proxy,hosting",
            timeout=10,
        )
        result = r.json()

        if result.get("status") == "fail":
            return jsonify({"error": result.get("message", "Lookup failed")}), 400

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ──────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)