"""
================================================================================
🛡️ PhishGuard: Threat Intelligence & Heuristic Phishing Detection Suite
Author: Vishal Pal (vishalpal9868@gmail.com)
Bootcamp: IBM SkillsBuild Cyber Security Bootcamp Oct 2026, conducted by BharatCares
Single-File Standalone Architecture (app.py)
================================================================================
Description:
A comprehensive, multi-factor heuristic detection engine and analyst dashboard
for identifying malicious URLs, typosquatting/homoglyph domains, and social-
engineering email campaigns without requiring external paid API keys.

Technologies: Python 3, Streamlit, Pandas
================================================================================
"""

import datetime
import math
import re
from urllib.parse import urlparse
import pandas as pd
import streamlit as st

# ==============================================================================
# SECTION 1: THREAT INTELLIGENCE DATABASES & CONFIGURATION
# ==============================================================================

# Popular Brands and their authentic, verified domain names
# Used to catch brand impersonation in subdomains, paths, or lookalike hosts
POPULAR_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.co.in", "google.co.uk", "gmail.com", "accounts.google.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "windows.net"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "binance": ["binance.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
}

# High-risk / frequently abused Top-Level Domains (TLDs)
# Frequently used in disposable phishing infrastructure due to free/cheap pricing
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "cam",
    "fit", "icu", "sbs", "country", "stream", "men", "bid", "loan",
    "win", "date", "racing", "click", "rest", "party", "gdn", "support",
    "quest", "monster", "cfd"
}

# Known URL Shortener Services used to mask final destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "tiny.cc"
}

# Credential-harvesting keywords commonly found in phishing URIs
SUSPICIOUS_URL_KEYWORDS = [
    "login", "signin", "verify", "update", "account", "banking", "secure",
    "security", "credential", "wallet", "recovery", "password", "confirm",
    "billing", "authenticate", "suspend", "unlock", "re-activate", "portal"
]

# Homoglyph character substitution map (visual lookalike characters)
HOMOGLYPH_MAP = {
    "0": "o",
    "1": "l",
    "vv": "w",
    "rn": "m",
    "5": "s",
    "8": "b",
    "@": "a",
    "$": "s",
}


# ==============================================================================
# SECTION 2: HEURISTIC DETECTION CORE ALGORITHMS
# ==============================================================================

def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon Entropy of a string: H(X) = -sum(P(x) * log2(P(x)))
    
    Higher entropy indicates random or obfuscated strings (typical of Domain
    Generation Algorithms used by malware & phishing kits).
    - Normal English words/domains: 2.0 to 3.5 bits/char.
    - Algorithmic / DGA domains: > 3.8 bits/char.
    """
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def is_ip_address(netloc: str) -> bool:
    """Check if the network host is a raw IPv4 or IPv6 address instead of a domain."""
    host = netloc.split(":")[0].strip("[]")
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    if ":" in host:
        return True
    return False


def extract_domain_parts(url: str):
    """
    Parse a URL into scheme, host, subdomains, registered domain, and path.
    """
    cleaned_url = url.strip()
    if not re.match(r"^https?://", cleaned_url, re.IGNORECASE):
        cleaned_url = "http://" + cleaned_url

    parsed = urlparse(cleaned_url)
    netloc = parsed.netloc.lower()
    host = netloc.split(":")[0]
    port = parsed.port

    segments = host.split(".")
    tld = segments[-1] if len(segments) > 1 else ""

    if len(segments) >= 2:
        registered_domain = ".".join(segments[-2:])
        subdomain = ".".join(segments[:-2])
    else:
        registered_domain = host
        subdomain = ""

    return {
        "full_url": cleaned_url,
        "scheme": parsed.scheme.lower(),
        "host": host,
        "port": port,
        "subdomain": subdomain,
        "registered_domain": registered_domain,
        "tld": tld,
        "path": parsed.path,
        "query": parsed.query,
    }


def analyze_url(raw_url: str) -> dict:
    """
    Multi-factor static & heuristic analyzer for URLs.
    Evaluates protocol security, IP hosting, TLD reputation, brand mimicry,
    homoglyphs, Shannon entropy, and URL obfuscation.
    """
    if not raw_url or not raw_url.strip():
        return {"error": "Please enter a valid URL."}

    parts = extract_domain_parts(raw_url)
    host = parts["host"]
    registered_domain = parts["registered_domain"]
    subdomain = parts["subdomain"]
    path = parts["path"].lower()
    query = parts["query"].lower()
    scheme = parts["scheme"]
    port = parts["port"]
    full_url = parts["full_url"]

    risk_points = 0
    flags = []

    # 1. Unencrypted HTTP Protocol Check
    if scheme == "http":
        risk_points += 15
        flags.append({
            "category": "Insecure Protocol",
            "severity": "Medium",
            "title": "Unencrypted HTTP Protocol",
            "description": "Legitimate banking, commerce, and login portals universally require HTTPS. HTTP exposes user traffic to eavesdropping and MITM interception.",
            "points": 15
        })

    # 2. Raw IP Address in URL
    if is_ip_address(host):
        risk_points += 40
        flags.append({
            "category": "Network Anomaly",
            "severity": "Critical",
            "title": "Direct IP Address in URL",
            "description": f"URL uses raw IP '{host}' instead of a verified registered domain. Phishing kits frequently host temporary credential harvesters on direct IP addresses.",
            "points": 40
        })

    # 3. High-Risk / Abused TLD
    if parts["tld"] in SUSPICIOUS_TLDS:
        risk_points += 25
        flags.append({
            "category": "Domain Reputation",
            "severity": "High",
            "title": f"High-Risk Top-Level Domain (.{parts['tld']})",
            "description": f"The TLD '.{parts['tld']}' has a high abuse-to-registration ratio due to free/cheap registrar pricing.",
            "points": 25
        })

    # 4. URL Shortener Service
    if host in URL_SHORTENERS:
        risk_points += 20
        flags.append({
            "category": "Obfuscation",
            "severity": "Medium",
            "title": f"URL Shortener Detected ({host})",
            "description": "Shorteners mask the final destination, preventing users and basic email filters from inspecting the landing domain.",
            "points": 20
        })

    # 5. Non-Standard Port Anomaly
    if port and port not in (80, 443, 8080):
        risk_points += 20
        flags.append({
            "category": "Network Anomaly",
            "severity": "High",
            "title": f"Non-Standard Port ({port})",
            "description": f"Connection routes through unusual port {port}. Standard websites operate on 80 (HTTP) or 443 (HTTPS).",
            "points": 20
        })

    # 6. Basic Auth '@' Symbol Redirect Exploit
    if "@" in full_url:
        risk_points += 35
        flags.append({
            "category": "Deceptive URL Structure",
            "severity": "Critical",
            "title": "Credential Separator '@' Detected",
            "description": "The '@' character instructs browsers to ignore text preceding it and navigate solely to the domain after the '@', confusing users.",
            "points": 35
        })

    # 7. Brand Impersonation & Targeted Phishing
    detected_brands = []
    for brand, legit_domains in POPULAR_BRANDS.items():
        brand_in_host = brand in host
        brand_in_path = brand in path
        is_legit = any(legit_domain in host for legit_domain in legit_domains)

        if (brand_in_host or brand_in_path) and not is_legit:
            detected_brands.append(brand.capitalize())

    if detected_brands:
        risk_points += 45
        brands_str = ", ".join(detected_brands)
        flags.append({
            "category": "Brand Impersonation",
            "severity": "Critical",
            "title": f"Targeted Brand Mimicry ({brands_str})",
            "description": f"The URL mentions protected brand(s) ({brands_str}), but authoritative domain '{registered_domain}' does NOT belong to the brand.",
            "points": 45
        })

    # 8. Lookalike / Homoglyph / Typosquatting
    homoglyphs_found = []
    for sub, real_char in HOMOGLYPH_MAP.items():
        if sub in host:
            test_host = host.replace(sub, real_char)
            for brand in POPULAR_BRANDS:
                if brand in test_host and brand not in host:
                    homoglyphs_found.append(f"'{sub}' mimicking '{real_char}' to imitate {brand.capitalize()}")

    if homoglyphs_found:
        risk_points += 35
        flags.append({
            "category": "Typosquatting & Homoglyphs",
            "severity": "Critical",
            "title": "Visual Character Substitution",
            "description": "Visual spoofing detected: " + "; ".join(homoglyphs_found) + ". Attackers substitute lookalike characters to fool human eyes.",
            "points": 35
        })

    # 9. Excessive Subdomains (Subdomain Camouflage)
    subdomain_parts = [p for p in subdomain.split(".") if p]
    if len(subdomain_parts) >= 3:
        risk_points += 20
        flags.append({
            "category": "Deceptive URL Structure",
            "severity": "High",
            "title": f"Excessive Subdomain Nesting ({len(subdomain_parts)} levels)",
            "description": f"Deep subdomain hierarchy '{subdomain}'. Attackers nest authentic brand names to trick mobile browsers that truncate long address bars.",
            "points": 20
        })

    # 10. Hyphen Overuse
    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        risk_points += 20
        flags.append({
            "category": "Deceptive URL Structure",
            "severity": "Medium",
            "title": f"Excessive Domain Hyphens ({hyphen_count} hyphens)",
            "description": "Legitimate enterprise sites rarely chain multiple hyphens. This is a common signature of disposable phishing registration.",
            "points": 20
        })

    # 11. Credential-Harvesting Keywords
    matched_keywords = []
    combined_search_area = f"{host} {path} {query}".lower()
    for kw in SUSPICIOUS_URL_KEYWORDS:
        if kw in combined_search_area:
            matched_keywords.append(kw)

    if len(matched_keywords) >= 2:
        risk_points += 25
        flags.append({
            "category": "Suspicious Intent",
            "severity": "High",
            "title": f"Credential Bait Keywords ({', '.join(matched_keywords[:4])})",
            "description": f"Contains sensitive action keywords ({', '.join(matched_keywords[:4])}) on an unverified third-party host.",
            "points": 25
        })
    elif len(matched_keywords) == 1 and risk_points > 0:
        risk_points += 10
        flags.append({
            "category": "Suspicious Intent",
            "severity": "Low",
            "title": f"Authentication Keyword ('{matched_keywords[0]}')",
            "description": f"URL contains login/security keyword '{matched_keywords[0]}'.",
            "points": 10
        })

    # 12. Shannon Entropy (DGA Detection)
    entropy_val = calculate_entropy(host)
    if entropy_val >= 3.8 and not is_ip_address(host):
        risk_points += 15
        flags.append({
            "category": "Algorithmic Anomaly",
            "severity": "Medium",
            "title": f"High Domain Entropy ({entropy_val} bits/char)",
            "description": "High mathematical randomness indicates an algorithmically generated domain (DGA) used by botnets or automated phishing kits.",
            "points": 15
        })

    # 13. URL Length Anomaly
    if len(raw_url) > 120:
        risk_points += 10
        flags.append({
            "category": "Obfuscation",
            "severity": "Low",
            "title": f"Abnormally Long URL ({len(raw_url)} characters)",
            "description": "Long URLs are often engineered to push the true host off-screen on mobile devices or convey obfuscated payloads.",
            "points": 10
        })

    final_score = min(risk_points, 100)

    if final_score >= 70:
        risk_level = "Critical Threat"
        badge_color = "#f85149"
        summary = "HIGH RISK: Severe phishing indicators detected. Do not click or enter credentials."
    elif final_score >= 45:
        risk_level = "Suspicious"
        badge_color = "#d29922"
        summary = "MODERATE RISK: Multiple suspicious anomalies detected. Proceed with extreme caution."
    elif final_score >= 20:
        risk_level = "Low Risk"
        badge_color = "#58a6ff"
        summary = "LOW RISK: Minor anomalies found, but no direct malicious signatures confirmed."
    else:
        risk_level = "Safe / Legitimate"
        badge_color = "#3fb950"
        summary = "SAFE: No malicious phishing, typosquatting, or spoofing patterns detected."

    return {
        "url": raw_url,
        "score": final_score,
        "risk_level": risk_level,
        "badge_color": badge_color,
        "summary": summary,
        "flags": flags,
        "metrics": {
            "entropy": entropy_val,
            "scheme": scheme.upper(),
            "host": host,
            "registered_domain": registered_domain,
            "subdomain": subdomain if subdomain else "(None)",
            "tld": parts["tld"],
            "url_length": len(raw_url),
            "flag_count": len(flags)
        }
    }


def analyze_email(subject: str, sender: str, body: str) -> dict:
    """
    Social engineering & phishing inspector for email messages and headers.
    Checks sender spoofing, artificial urgency, financial extortion, and embedded links.
    """
    risk_points = 0
    flags = []

    combined_text = f"{subject} {body}".lower()

    # 1. Sender Spoofing Check (Display Name vs Envelope Email Address)
    sender_lower = sender.lower().strip()
    match = re.search(r"^(.*?)\s*<([^>]+)>$", sender_lower)
    display_name = ""
    email_addr = sender_lower

    if match:
        display_name = match.group(1).strip().replace('"', '')
        email_addr = match.group(2).strip()

    for brand, legit_domains in POPULAR_BRANDS.items():
        if brand in display_name.lower() or brand in sender_lower.split("@")[0]:
            is_legit_sender = any(domain in email_addr for domain in legit_domains)
            if not is_legit_sender:
                risk_points += 45
                flags.append({
                    "category": "Sender Identity Spoofing",
                    "severity": "Critical",
                    "title": f"Sender Name Mimics '{brand.capitalize()}'",
                    "description": f"Display name poses as '{display_name or brand.capitalize()}', but actual email is '{email_addr}'. Attackers disguise disposable webmail with corporate names.",
                    "points": 45
                })

    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "proton.me"]
    sender_domain = email_addr.split("@")[-1] if "@" in email_addr else ""

    if sender_domain in free_providers and any(b in display_name.lower() for b in ["support", "security", "admin", "billing", "service"]):
        risk_points += 30
        flags.append({
            "category": "Sender Identity Spoofing",
            "severity": "High",
            "title": f"Corporate Persona on Free Webmail (@{sender_domain})",
            "description": f"Message poses as an administrative service ('{display_name}') from a free, unverified consumer mailbox.",
            "points": 30
        })

    # 2. Urgency and Coercion Patterns
    urgency_patterns = [
        r"within\s+\d+\s+hours?",
        r"account\s+(will\s+be\s+)?suspended",
        r"immediate\s+action\s+required",
        r"unauthorized\s+(login|access|transaction)",
        r"action\s+required",
        r"urgent\s+notice",
        r"legal\s+action",
        r"warrant\s+for\s+arrest",
        r"security\s+breach\s+detected",
        r"account\s+terminated",
        r"permanently\s+disabled"
    ]
    matched_urgency = [p for p in urgency_patterns if re.search(p, combined_text)]
    if matched_urgency:
        risk_points += 25
        flags.append({
            "category": "Social Engineering",
            "severity": "High",
            "title": "Artificial Urgency & Fear Tactics",
            "description": "Attackers manufacture panic with threats of immediate suspension or legal action to rush victims into bypassing caution.",
            "points": 25
        })

    # 3. Financial Bait / Extortion / BEC
    financial_keywords = [
        "wire transfer", "gift card", "bitcoin", "crypto wallet", "invoice attached",
        "overdue payment", "payroll update", "direct deposit", "tax refund",
        "lottery winner", "inheritance", "million dollars", "funds transfer"
    ]
    matched_finance = [kw for kw in financial_keywords if kw in combined_text]
    if matched_finance:
        risk_points += 25
        flags.append({
            "category": "Financial Exploitation",
            "severity": "High",
            "title": f"Financial / Payment Trigger ({', '.join(matched_finance[:3])})",
            "description": f"Contains financial transfer requests ({', '.join(matched_finance[:3])}), typical of Business Email Compromise (BEC).",
            "points": 25
        })

    # 4. Credential Harvesting Cues
    credential_cues = [
        "confirm your password", "reset password immediately", "verify your identity",
        "send your otp", "verification code", "two-factor authentication", "re-authenticate",
        "update your billing information", "click the link below to verify"
    ]
    matched_cues = [cue for cue in credential_cues if cue in combined_text]
    if matched_cues:
        risk_points += 20
        flags.append({
            "category": "Credential Harvesting",
            "severity": "High",
            "title": "Direct Verification / Credential Prompt",
            "description": "Legitimate organizations never solicit passwords or 2FA codes through links in unsolicited emails.",
            "points": 20
        })

    # 5. Generic Impersonal Salutations
    generic_greetings = [
        "dear customer", "dear user", "valued client", "dear account holder",
        "undisclosed recipient", "dear sir/madam", "attention customer"
    ]
    if any(g in body.lower() for g in generic_greetings):
        risk_points += 15
        flags.append({
            "category": "Impersonal Salutation",
            "severity": "Medium",
            "title": "Generic Customer Greeting",
            "description": "Generic greetings ('Dear Customer') indicate bulk automated phishing broadcasts rather than personalized legitimate correspondence.",
            "points": 15
        })

    # 6. Embedded Link Extraction & Deep Inspection
    url_pattern = r"(https?://[^\s<>\"'()]+)"
    found_urls = re.findall(url_pattern, body)
    url_scan_results = []

    for u in found_urls[:3]:
        u_res = analyze_url(u)
        url_scan_results.append(u_res)
        if u_res["score"] >= 45:
            risk_points += 30
            flags.append({
                "category": "Malicious Embedded Link",
                "severity": "Critical",
                "title": f"High-Risk URL Detected in Email Body",
                "description": f"Link pointing to '{u_res['metrics']['host']}' was flagged with a threat score of {u_res['score']}/100.",
                "points": 30
            })

    final_score = min(risk_points, 100)

    if final_score >= 70:
        verdict = "Phishing Attack Likely"
        badge_color = "#f85149"
        summary = "HIGH DANGER: Strong indicators of a phishing or social engineering attack."
    elif final_score >= 45:
        verdict = "Suspicious Email"
        badge_color = "#d29922"
        summary = "WARNING: Contains multiple deception indicators. Treat with suspicion."
    elif final_score >= 20:
        verdict = "Low Risk"
        badge_color = "#58a6ff"
        summary = "Minor security flags detected. Verify sender before acting."
    else:
        verdict = "Legitimate / Normal"
        badge_color = "#3fb950"
        summary = "No noticeable phishing or coercion patterns identified."

    return {
        "score": final_score,
        "verdict": verdict,
        "badge_color": badge_color,
        "summary": summary,
        "flags": flags,
        "embedded_urls": url_scan_results,
        "sender": email_addr,
        "display_name": display_name,
        "url_count": len(found_urls),
    }


# ==============================================================================
# SECTION 3: SCENARIO DATASETS, SAMPLE PAYLOADS & QUIZ QUESTIONS
# ==============================================================================

SAMPLE_URLS = [
    {
        "name": "🚨 PayPal Credential Harvester (Direct IP + Port)",
        "url": "http://192.168.1.105:8080/paypal-login/verification.php?user=victim",
        "type": "Malicious",
        "description": "Combines raw IP hosting, unencrypted HTTP, non-standard port 8080, and brand impersonation targeting PayPal."
    },
    {
        "name": "🚨 Microsoft Homoglyph / Typosquatting (.xyz domain)",
        "url": "https://security-update-micros0ft.support-verify.xyz/login.html",
        "type": "Malicious",
        "description": "Uses visual number '0' instead of letter 'o' (micros0ft), high-risk .xyz TLD, and excessive hyphenated keywords."
    },
    {
        "name": "🚨 Netflix Account Suspension Phish (Subdomain Camouflage)",
        "url": "http://netflix.account-billing-update.com/signin?ref=suspicious",
        "type": "Malicious",
        "description": "Puts 'netflix' in subdomain to fool mobile users while registered domain is 'account-billing-update.com'."
    },
    {
        "name": "⚠️ Shortened Link (Obfuscated Target - Smishing)",
        "url": "https://bit.ly/3xUR9Qk",
        "type": "Suspicious",
        "description": "Hides the final destination behind a URL shortener service; high risk in SMS and unsolicited messages."
    },
    {
        "name": "✅ Legitimate Official PayPal Portal",
        "url": "https://www.paypal.com/signin",
        "type": "Safe",
        "description": "Official HTTPS portal under genuine paypal.com domain with zero flags."
    },
    {
        "name": "✅ Legitimate GitHub Repository",
        "url": "https://github.com/login",
        "type": "Safe",
        "description": "Official authentic developer authentication gateway."
    }
]

SAMPLE_EMAILS = [
    {
        "name": "🚨 PayPal 24-Hour Suspension Scare",
        "sender": "PayPal Support <service-notice@paypa1-security-alert.xyz>",
        "subject": "URGENT: Your account has been temporarily restricted (Action Required within 24 hours)",
        "body": """Dear Customer,

We have detected unusual sign-in activity and unauthorized transactions on your PayPal wallet from an unrecognized device in Moscow, Russia.

For your protection, your access has been limited. You must verify your identity immediately to prevent permanent account suspension.

Failure to complete verification within 24 hours will result in legal escalation and account forfeiture.

Please confirm your password and update your billing information now:
http://192.168.1.105:8080/paypal-login/verification.php?user=victim

Sincerely,
PayPal Security & Fraud Department"""
    },
    {
        "name": "🚨 CEO Fraud / Urgent Wire Transfer (BEC)",
        "sender": "David Miller (CEO) <ceo.internal.office99@gmail.com>",
        "subject": "Confidential: Urgent Wire Transfer Needed Before 3:00 PM",
        "body": """Good morning,

I am currently in an executive board meeting and cannot take calls.

We are closing a confidential acquisition today and I need you to initiate a wire transfer of $48,500 immediately to our escrow vendor. 

Please reply as soon as you see this and I will send the wire payment details. Do not discuss this with anyone in the office yet due to NDA requirements.

Process this as high priority.

Best regards,
David Miller
Chief Executive Officer"""
    },
    {
        "name": "🚨 DHL Package Delivery Smishing / Phishing",
        "sender": "DHL Express Tracking <express-shipment@dhl-package-redelivery.top>",
        "subject": "Delivery Exception: Your parcel #US-884920 could not be delivered",
        "body": """Dear Customer,

Your parcel #US-884920 could not be delivered on October 22 due to an incomplete delivery address and an unpaid customs clearance fee ($2.40).

To schedule re-delivery for tomorrow, please confirm your address and pay the fee online:
http://netflix.account-billing-update.com/signin?ref=suspicious

If not claimed within 48 hours, the package will be returned to the sender.

Regards,
DHL Express Delivery Team"""
    },
    {
        "name": "✅ Legitimate Google Security Alert",
        "sender": "Google <no-reply@accounts.google.com>",
        "subject": "Security alert: New device signed in to your Google Account",
        "body": """Hi Alex,

Your Google Account was just signed in to from a new Windows device.

Device: Windows PC, Chrome Browser
Location: Mumbai, India
Time: Oct 23, 2026, 4:30 PM IST

If this was you, you don't need to do anything. If you didn't sign in, please review your devices and secure your account immediately by visiting https://myaccount.google.com/device-activity.

The Google Security Team"""
    }
]

QUIZ_QUESTIONS = [
    {
        "id": 1,
        "scenario": "You receive an email claiming: 'Your Netflix subscription expired. Click here to update your credit card or your account will be deleted today.' The sender is 'Netflix Billing <support@netfIix-accounts.xyz>' (notice the capital 'I' instead of 'l').",
        "options": [
            "It's legitimate because Netflix accounts really do expire.",
            "It's a phishing attack using typosquatting/homoglyph trickery and urgency.",
            "It's safe as long as I don't give my password.",
            "It's an official marketing promotion."
        ],
        "correct_index": 1,
        "explanation": "Attackers substituted 'l' with an uppercase 'I' (netfIix) and used a cheap .xyz TLD along with artificial urgency ('deleted today') to trick you into submitting credit card details."
    },
    {
        "id": 2,
        "scenario": "An SMS arrives with a link: 'http://192.168.4.15/bank/login.php'. Why is this URL immediately suspicious?",
        "options": [
            "Because banks never use links in SMS.",
            "Because legitimate banks use registered domain names (like chase.com) with HTTPS, not raw IP addresses with unencrypted HTTP.",
            "Because the port number is missing.",
            "Because 192.168 is always a virus."
        ],
        "correct_index": 1,
        "explanation": "Banks own authenticated SSL certificates tied to registered domains. Using raw IP addresses over plain HTTP is a major red flag for temporary phishing servers."
    },
    {
        "id": 3,
        "scenario": "What is the primary purpose of Domain Shannon Entropy analysis in cybersecurity?",
        "options": [
            "To measure how fast a website loads.",
            "To detect mathematically randomized or machine-generated domain names (DGAs) used by botnets and phishing kits.",
            "To check if the password has numbers and symbols.",
            "To encrypt passwords in the database."
        ],
        "correct_index": 1,
        "explanation": "Shannon entropy quantifies the unpredictability of characters. Normal human domains (e.g., 'google.com') have low entropy, while algorithmic phishing/malware domains (e.g., 'x7k9q-p2z9.xyz') have very high entropy."
    },
    {
        "id": 4,
        "scenario": "An email arrives from 'ceo.corporate@gmail.com' asking the accounting team to urgently wire money to an offshore vendor under NDA. What specific cyber attack is this?",
        "options": [
            "SQL Injection",
            "Distributed Denial of Service (DDoS)",
            "Business Email Compromise (BEC) / CEO Fraud",
            "Ransomware Encryption"
        ],
        "correct_index": 2,
        "explanation": "This is Business Email Compromise (BEC), where criminals impersonate executives using free email addresses or spoofed domains to manipulate employees into initiating wire transfers."
    },
    {
        "id": 5,
        "scenario": "In the URL 'https://login.microsoft.com.account-update.xyz/auth', what is the actual destination domain your browser connects to?",
        "options": [
            "microsoft.com",
            "login.microsoft.com",
            "account-update.xyz",
            "None, it connects to Google"
        ],
        "correct_index": 2,
        "explanation": "In DNS hierarchy, the true domain is the one directly preceding the top-level domain (.xyz). Here, 'account-update.xyz' is the attacker's server; 'login.microsoft.com' is just an arbitrarily named subdomain crafted to deceive you!"
    }
]


# ==============================================================================
# SECTION 4: STREAMLIT UI & DASHBOARD STYLING
# ==============================================================================

st.set_page_config(
    page_title="PhishGuard - Threat Intelligence Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown(
    """
    <style>
    /* Dark cybersecurity terminal aesthetics */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    
    /* Top Hero Header */
    .hero-container {
        background: linear-gradient(135deg, #161b22 0%, #0d1117 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 1.5rem 2rem;
        margin-bottom: 1.5rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .hero-title {
        font-size: 2.2rem;
        font-weight: 800;
        background: linear-gradient(90deg, #58a6ff, #bc8cff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .hero-subtitle {
        color: #8b949e;
        font-size: 0.95rem;
        margin-top: 0.3rem;
    }
    
    /* Metric Cards */
    .cyber-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 10px;
        padding: 1.2rem;
        text-align: center;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .cyber-card:hover {
        border-color: #58a6ff;
        transform: translateY(-2px);
    }
    .cyber-label {
        font-size: 0.8rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.4rem;
    }
    .cyber-value {
        font-size: 1.8rem;
        font-weight: 700;
    }

    /* Score Indicator Gauge Box */
    .score-box {
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
        margin-bottom: 1.2rem;
        border: 1px solid;
    }
    .score-critical {
        background: radial-gradient(circle, rgba(248,81,73,0.15) 0%, rgba(22,27,34,0.95) 100%);
        border-color: #f85149;
    }
    .score-suspicious {
        background: radial-gradient(circle, rgba(210,153,34,0.15) 0%, rgba(22,27,34,0.95) 100%);
        border-color: #d29922;
    }
    .score-low {
        background: radial-gradient(circle, rgba(88,166,255,0.15) 0%, rgba(22,27,34,0.95) 100%);
        border-color: #58a6ff;
    }
    .score-safe {
        background: radial-gradient(circle, rgba(63,185,80,0.15) 0%, rgba(22,27,34,0.95) 100%);
        border-color: #3fb950;
    }

    /* Flag item styling */
    .flag-card {
        background-color: #161b22;
        border-left: 5px solid;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.8rem;
        border-top: 1px solid #30363d;
        border-right: 1px solid #30363d;
        border-bottom: 1px solid #30363d;
    }
    .flag-critical { border-left-color: #f85149; }
    .flag-high     { border-left-color: #f85149; }
    .flag-medium   { border-left-color: #d29922; }
    .flag-low      { border-left-color: #58a6ff; }

    .badge {
        display: inline-block;
        padding: 0.2rem 0.55rem;
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        margin-left: 0.5rem;
    }
    .badge-critical { background-color: #f85149; color: #0d1117; }
    .badge-high     { background-color: #f85149; color: #0d1117; }
    .badge-medium   { background-color: #d29922; color: #0d1117; }
    .badge-low      { background-color: #58a6ff; color: #0d1117; }
    .badge-safe     { background-color: #3fb950; color: #0d1117; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Top Hero Banner ───────────────────────────────────────────────────────────
st.markdown(
    """
    <div class="hero-container">
        <div>
            <h1 class="hero-title">🛡️ PhishGuard : Threat Intelligence Suite</h1>
            <p class="hero-subtitle">
                Advanced heuristic phishing detection, domain reputation analysis & social engineering inspector.
            </p>
        </div>
        <div style="text-align: right;">
            <span class="badge badge-safe" style="font-size: 0.85rem; padding: 0.35rem 0.8rem;">
                ● ENGINE ONLINE
            </span>
            <div style="font-size: 0.78rem; color: #8b949e; margin-top: 0.4rem;">
                Heuristic Core v2.4 | Academic Edition
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Sidebar Quick Controls & Project Info ─────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ Engine Controls")
    sensitivity = st.select_slider(
        "Heuristic Sensitivity",
        options=["Standard", "Aggressive", "Paranoid"],
        value="Standard",
        help="Controls algorithmic thresholds for entropy and keyword clustering."
    )

    st.divider()
    st.markdown("### 🎓 Project Information")
    st.markdown("**Domain:** Cybersecurity & Threat Analysis")
    st.markdown("**Scope:** Anti-Phishing & Social Engineering")
    st.markdown("**Status:** Ready for Examination")

    st.divider()
    st.markdown("### 📌 Why this is different:")
    st.caption(
        "Unlike basic login failure log counters, PhishGuard inspects live URLs, "
        "calculates Shannon entropy, detects homoglyph/typosquatting, parses email "
        "psychological manipulation triggers, and generates SOC remediation reports."
    )

# ── Main Tab Navigation ───────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔍 URL & Domain Scanner",
    "✉️ Email Phishing Inspector",
    "🧪 Live Attack Lab",
    "🎯 Security Quiz",
    "🛡️ Defense & Education"
])


# ==============================================================================
# TAB 1: URL & DOMAIN SCANNER
# ==============================================================================
with tab1:
    st.subheader("🌐 Heuristic URL & Domain Security Scanner")
    st.caption("Inspect any URL or test one of the pre-loaded real-world attack vectors below.")

    # Quick demo buttons
    demo_cols = st.columns(4)
    if demo_cols[0].button("🚨 Test PayPal Phish", use_container_width=True):
        st.session_state["input_url"] = SAMPLE_URLS[0]["url"]
    if demo_cols[1].button("🚨 Test Homoglyph .xyz", use_container_width=True):
        st.session_state["input_url"] = SAMPLE_URLS[1]["url"]
    if demo_cols[2].button("🚨 Test Subdomain Camouflage", use_container_width=True):
        st.session_state["input_url"] = SAMPLE_URLS[2]["url"]
    if demo_cols[3].button("✅ Test Official PayPal", use_container_width=True):
        st.session_state["input_url"] = SAMPLE_URLS[4]["url"]

    # Input Box
    default_url = st.session_state.get("input_url", "https://security-update-micros0ft.support-verify.xyz/login.html")
    url_to_scan = st.text_input("Enter URL to analyze:", value=default_url, key="scanner_input")

    col_btn, col_blank = st.columns([1, 4])
    scan_clicked = col_btn.button("🔍 Scan Target", type="primary", use_container_width=True)

    if url_to_scan:
        result = analyze_url(url_to_scan)

        if "error" in result:
            st.error(result["error"])
        else:
            score = result["score"]
            risk_level = result["risk_level"]
            metrics = result["metrics"]
            flags = result["flags"]

            if score >= 70:
                css_score = "score-critical"
                accent_color = "#f85149"
            elif score >= 45:
                css_score = "score-suspicious"
                accent_color = "#d29922"
            elif score >= 20:
                css_score = "score-low"
                accent_color = "#58a6ff"
            else:
                css_score = "score-safe"
                accent_color = "#3fb950"

            st.write("")
            st.markdown(
                f"""
                <div class="score-box {css_score}">
                    <div style="font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.1em; color: #8b949e;">
                        Overall Threat Index
                    </div>
                    <div style="font-size: 3.5rem; font-weight: 800; color: {accent_color}; margin: 0.2rem 0;">
                        {score} <span style="font-size: 1.5rem; color: #8b949e;">/ 100</span>
                    </div>
                    <div style="font-size: 1.25rem; font-weight: 600; color: #c9d1d9;">
                        Verdict: <span style="color: {accent_color};">{risk_level}</span>
                    </div>
                    <div style="font-size: 0.9rem; color: #8b949e; margin-top: 0.5rem;">
                        {result['summary']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # 4 Metric summary cards
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                st.markdown(
                    f"""
                    <div class="cyber-card">
                        <div class="cyber-label">Host Entropy</div>
                        <div class="cyber-value" style="color: {'#f85149' if metrics['entropy'] > 3.8 else '#58a6ff'};">
                            {metrics['entropy']}
                        </div>
                        <div style="font-size: 0.72rem; color: #8b949e;">Shannon Index (bits)</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with m2:
                st.markdown(
                    f"""
                    <div class="cyber-card">
                        <div class="cyber-label">Protocol</div>
                        <div class="cyber-value" style="color: {'#3fb950' if metrics['scheme'] == 'HTTPS' else '#f85149'};">
                            {metrics['scheme']}
                        </div>
                        <div style="font-size: 0.72rem; color: #8b949e;">Transport Encryption</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with m3:
                st.markdown(
                    f"""
                    <div class="cyber-card">
                        <div class="cyber-label">Root Domain</div>
                        <div class="cyber-value" style="font-size: 1.2rem; word-break: break-all; color: #c9d1d9; padding-top: 0.4rem;">
                            {metrics['registered_domain']}
                        </div>
                        <div style="font-size: 0.72rem; color: #8b949e;">Authoritative Host</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with m4:
                st.markdown(
                    f"""
                    <div class="cyber-card">
                        <div class="cyber-label">Red Flags Triggered</div>
                        <div class="cyber-value" style="color: {accent_color};">
                            {metrics['flag_count']}
                        </div>
                        <div style="font-size: 0.72rem; color: #8b949e;">Heuristic Rules Hit</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.write("")
            st.divider()

            # Detailed Flag Breakdown Section
            st.markdown("### 🚩 Heuristic Indicator Breakdown")
            if flags:
                for idx, flag in enumerate(flags, start=1):
                    sev = flag["severity"].lower()
                    st.markdown(
                        f"""
                        <div class="flag-card flag-{sev}">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                                <div>
                                    <strong style="color: #c9d1d9; font-size: 1rem;">#{idx}. {flag['title']}</strong>
                                    <span class="badge badge-{sev}">{flag['severity']}</span>
                                </div>
                                <div style="font-size: 0.82rem; color: #8b949e;">
                                    Category: <span style="color: #58a6ff;">{flag['category']}</span> | +{flag['points']} pts
                                </div>
                            </div>
                            <div style="font-size: 0.88rem; color: #8b949e; line-height: 1.4;">
                                {flag['description']}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.success("✅ Clean Scan: No malicious signatures, typosquatting patterns, or high-risk indicators were detected.")

            # DNS & Structural Breakdown Table
            with st.expander("🔬 View Deep Structural & Lexical Analysis Details", expanded=False):
                struct_data = {
                    "Analysis Attribute": [
                        "Original Target URL",
                        "Resolved Hostname",
                        "Registered Root Domain",
                        "Subdomain Hierarchy",
                        "Top-Level Domain (TLD)",
                        "Transport Scheme",
                        "URL Character Length",
                        "Shannon Entropy Score"
                    ],
                    "Detected Value": [
                        url_to_scan,
                        metrics["host"],
                        metrics["registered_domain"],
                        metrics["subdomain"],
                        f".{metrics['tld']}" if metrics['tld'] else "None",
                        metrics["scheme"],
                        f"{metrics['url_length']} characters",
                        f"{metrics['entropy']} bits/char (Normal: 2.0 - 3.5)"
                    ],
                    "Security Context": [
                        "Raw input supplied to the scanner",
                        "Destination server queried by the browser",
                        "Domain registrant accountable for DNS records",
                        "Nesting above 2 levels is common in mobile address bar spoofing",
                        "Cheap TLDs have higher rates of abuse according to ICANN",
                        "Plain HTTP is vulnerable to Man-In-The-Middle (MITM) attacks",
                        "Long strings (>120 chars) often camouflage the real destination",
                        "Mathematical randomness calculation for DGA identification"
                    ]
                }
                st.dataframe(pd.DataFrame(struct_data), width="stretch", hide_index=True)

            # Export Incident Report Button
            report_text = f"""# PHISHGUARD THREAT INTELLIGENCE INCIDENT REPORT
Generated At: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target URL: {url_to_scan}

=======================================================
EXECUTIVE SUMMARY
=======================================================
Overall Threat Score: {score}/100
Classification: {risk_level}
Summary: {result['summary']}

=======================================================
TECHNICAL METRICS
=======================================================
- Target Host: {metrics['host']}
- Registered Domain: {metrics['registered_domain']}
- Subdomain: {metrics['subdomain']}
- Protocol: {metrics['scheme']}
- Shannon Entropy: {metrics['entropy']} bits/character
- Red Flags Triggered: {metrics['flag_count']}

=======================================================
DETECTED THREAT INDICATORS
=======================================================
"""
            for i, f in enumerate(flags, 1):
                report_text += f"\n[{i}] {f['title']} ({f['severity'].upper()})\n"
                report_text += f"    Category: {f['category']} | Penalty: +{f['points']} pts\n"
                report_text += f"    Details: {f['description']}\n"

            report_text += """
=======================================================
RECOMMENDED SOC DEFENSIVE ACTIONS
=======================================================
1. Block domain and associated IP addresses at perimeter firewalls / secure web gateways.
2. Submit takedown request to domain registrar / hosting abuse response teams.
3. Search corporate proxy logs for internal workstations that accessed this destination.
4. Enforce immediate password reset and session invalidation if credentials were entered.
"""

            st.download_button(
                label="📄 Download SOC Incident Report (.txt)",
                data=report_text,
                file_name=f"PhishGuard_Report_{metrics['host']}.txt",
                mime="text/plain",
            )


# ==============================================================================
# TAB 2: EMAIL PHISHING INSPECTOR
# ==============================================================================
with tab2:
    st.subheader("✉️ Social Engineering & Email Threat Analyzer")
    st.caption("Inspect suspicious emails for sender spoofing, urgency traps, financial coercion, and hidden links.")

    st.markdown("**Load Real-World Attack Scenarios:**")
    email_demo_cols = st.columns(4)
    if email_demo_cols[0].button("🚨 Fake PayPal Urgent Notice", use_container_width=True):
        st.session_state["email_subject"] = SAMPLE_EMAILS[0]["subject"]
        st.session_state["email_sender"] = SAMPLE_EMAILS[0]["sender"]
        st.session_state["email_body"] = SAMPLE_EMAILS[0]["body"]
    if email_demo_cols[1].button("🚨 CEO Wire Fraud (BEC)", use_container_width=True):
        st.session_state["email_subject"] = SAMPLE_EMAILS[1]["subject"]
        st.session_state["email_sender"] = SAMPLE_EMAILS[1]["sender"]
        st.session_state["email_body"] = SAMPLE_EMAILS[1]["body"]
    if email_demo_cols[2].button("🚨 DHL Failed Delivery", use_container_width=True):
        st.session_state["email_subject"] = SAMPLE_EMAILS[2]["subject"]
        st.session_state["email_sender"] = SAMPLE_EMAILS[2]["sender"]
        st.session_state["email_body"] = SAMPLE_EMAILS[2]["body"]
    if email_demo_cols[3].button("✅ Legitimate Google Alert", use_container_width=True):
        st.session_state["email_subject"] = SAMPLE_EMAILS[3]["subject"]
        st.session_state["email_sender"] = SAMPLE_EMAILS[3]["sender"]
        st.session_state["email_body"] = SAMPLE_EMAILS[3]["body"]

    col_sender, col_subj = st.columns([1, 1])
    with col_sender:
        sender_val = st.text_input(
            "Sender (Display Name + Email):",
            value=st.session_state.get("email_sender", SAMPLE_EMAILS[0]["sender"]),
            placeholder="e.g. PayPal Support <service@paypa1-security.xyz>"
        )
    with col_subj:
        subject_val = st.text_input(
            "Email Subject Line:",
            value=st.session_state.get("email_subject", SAMPLE_EMAILS[0]["subject"]),
            placeholder="e.g. Urgent: Account suspended within 24 hours"
        )

    body_val = st.text_area(
        "Email Body Text:",
        value=st.session_state.get("email_body", SAMPLE_EMAILS[0]["body"]),
        height=200,
        placeholder="Paste full email text here..."
    )

    if st.button("🔍 Analyze Email Threat", type="primary"):
        if not body_val.strip() and not subject_val.strip():
            st.warning("Please provide email text or subject to analyze.")
        else:
            email_res = analyze_email(subject_val, sender_val, body_val)
            e_score = email_res["score"]
            verdict = email_res["verdict"]
            badge_color = email_res["badge_color"]

            st.write("")
            st.markdown(
                f"""
                <div class="score-box" style="border-color: {badge_color}; background: radial-gradient(circle, {badge_color}22 0%, #161b22 100%);">
                    <div style="font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.1em; color: #8b949e;">
                        Social Engineering Risk Score
                    </div>
                    <div style="font-size: 3.5rem; font-weight: 800; color: {badge_color}; margin: 0.2rem 0;">
                        {e_score} <span style="font-size: 1.5rem; color: #8b949e;">/ 100</span>
                    </div>
                    <div style="font-size: 1.25rem; font-weight: 600; color: #c9d1d9;">
                        Assessment: <span style="color: {badge_color};">{verdict}</span>
                    </div>
                    <div style="font-size: 0.9rem; color: #8b949e; margin-top: 0.5rem;">
                        {email_res['summary']}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown("### 🧠 Psychological & Identity Flags")
            if email_res["flags"]:
                for idx, flag in enumerate(email_res["flags"], 1):
                    sev = flag["severity"].lower()
                    st.markdown(
                        f"""
                        <div class="flag-card flag-{sev}">
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                                <div>
                                    <strong style="color: #c9d1d9;">#{idx}. {flag['title']}</strong>
                                    <span class="badge badge-{sev}">{flag['severity']}</span>
                                </div>
                                <div style="font-size: 0.8rem; color: #58a6ff;">
                                    {flag['category']} | +{flag['points']} pts
                                </div>
                            </div>
                            <div style="font-size: 0.88rem; color: #8b949e;">
                                {flag['description']}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.success("✅ No social engineering, urgency manipulation, or sender deception patterns found.")

            if email_res["embedded_urls"]:
                st.markdown("### 🔗 Links Discovered in Message Body")
                st.caption("PhishGuard automatically extracted and scanned the destination links found in the text:")
                for u_res in email_res["embedded_urls"]:
                    u_col1, u_col2 = st.columns([3, 1])
                    with u_col1:
                        st.code(u_res["url"])
                    with u_col2:
                        u_color = u_res["badge_color"]
                        st.markdown(
                            f"""
                            <div style="text-align: center; padding: 0.5rem; border-radius: 6px; background-color: #161b22; border: 1px solid {u_color};">
                                <span style="font-weight: 700; color: {u_color};">{u_res['risk_level']}</span>
                                <div style="font-size: 0.75rem; color: #8b949e;">Score: {u_res['score']}/100</div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )


# ==============================================================================
# TAB 3: LIVE ATTACK LAB
# ==============================================================================
with tab3:
    st.subheader("🧪 Live Phishing Techniques Demonstration Lab")
    st.caption("Demonstrate how attackers evade visual human checks versus how algorithmic heuristics catch them.")

    exp_col1, exp_col2 = st.columns(2)

    with exp_col1:
        st.markdown("#### 🔬 Technique 1: Typosquatting / Homoglyph Attack")
        st.markdown(
            """
            **How it works:** Attackers replace Latin characters with identical-looking Cyrillic, 
            digits, or character pairs (e.g. `micros0ft.com`, `paypa1.com`, `arnazon.com`).
            """
        )
        sample_legit = "https://www.paypal.com"
        sample_spoof = "http://www.paypa1-security.xyz"

        st.text("Target A (Legitimate):")
        st.code(sample_legit)
        res_a = analyze_url(sample_legit)
        st.markdown(f"**PhishGuard Score:** `{res_a['score']}/100` ({res_a['risk_level']})")

        st.text("Target B (Spoofed with '1' and .xyz):")
        st.code(sample_spoof)
        res_b = analyze_url(sample_spoof)
        st.markdown(f"**PhishGuard Score:** `{res_b['score']}/100` ({res_b['risk_level']})")

    with exp_col2:
        st.markdown("#### 🔬 Technique 2: Subdomain Camouflage")
        st.markdown(
            """
            **How it works:** Attackers prepend legitimate brand names as subdomains 
            (`netflix.com.attacker-server.com`). Mobile devices truncate long URLs, showing only the subdomain.
            """
        )
        sample_cam = "http://login.microsoft.com.account-update.xyz/auth"
        st.code(sample_cam)
        res_c = analyze_url(sample_cam)
        st.markdown(f"**PhishGuard Score:** `{res_c['score']}/100` ({res_c['risk_level']})")
        st.info(f"**Authoritative DNS Host Identified:** `{res_c['metrics']['registered_domain']}` (Attacker) vs claimed brand (Microsoft).")

    st.divider()
    st.markdown("#### 📊 Comparative Analysis Matrix")
    matrix_data = []
    for item in SAMPLE_URLS:
        r = analyze_url(item["url"])
        matrix_data.append({
            "Scenario Name": item["name"],
            "Target URL": item["url"],
            "True Nature": item["type"],
            "PhishGuard Score": r["score"],
            "System Verdict": r["risk_level"],
            "Flags Hit": len(r["flags"])
        })
    df_matrix = pd.DataFrame(matrix_data)
    st.dataframe(df_matrix, width="stretch", hide_index=True)


# ==============================================================================
# TAB 4: SECURITY QUIZ
# ==============================================================================
with tab4:
    st.subheader("🎯 Interactive Cybersecurity Awareness Quiz")
    st.caption("Test your threat detection instincts against realistic phishing attacks. Perfect for class presentations!")

    if "quiz_answers" not in st.session_state:
        st.session_state["quiz_answers"] = {}

    score_counter = 0
    submitted = st.session_state.get("quiz_submitted", False)

    for q in QUIZ_QUESTIONS:
        qid = q["id"]
        st.markdown(f"**Question {qid}:** {q['scenario']}")
        choice = st.radio(
            label=f"Options for Q{qid}:",
            options=q["options"],
            key=f"q_{qid}",
            label_visibility="collapsed"
        )
        st.session_state["quiz_answers"][qid] = choice

        if submitted:
            correct_text = q["options"][q["correct_index"]]
            if choice == correct_text:
                score_counter += 1
                st.success(f"✅ Correct! {q['explanation']}")
            else:
                st.error(f"❌ Incorrect. Correct answer: **{correct_text}**\n\nExplanation: {q['explanation']}")
        st.write("")

    col_sub, col_rst = st.columns([1, 4])
    if col_sub.button("Submit Quiz Answers", type="primary"):
        st.session_state["quiz_submitted"] = True
        st.rerun()

    if col_rst.button("Reset Quiz"):
        st.session_state["quiz_submitted"] = False
        st.rerun()

    if submitted:
        percentage = int((score_counter / len(QUIZ_QUESTIONS)) * 100)
        st.markdown(
            f"""
            <div class="score-box score-safe" style="margin-top: 1.5rem;">
                <div style="font-size: 1.1rem; color: #8b949e;">Your Final Score</div>
                <div style="font-size: 2.5rem; font-weight: 700; color: #3fb950;">
                    {score_counter} / {len(QUIZ_QUESTIONS)} ({percentage}%)
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


# ==============================================================================
# TAB 5: DEFENSE & EDUCATION
# ==============================================================================
with tab5:
    st.subheader("🛡️ Enterprise Defense, Protocols & Threat Taxonomy")
    st.caption("Comprehensive educational reference for oral examinations and project viva.")

    g1, g2 = st.columns(2)
    with g1:
        st.markdown("### 📧 Email Authentication Trifecta (SPF, DKIM, DMARC)")
        st.markdown(
            """
            Modern anti-spoofing relies on three interlocking cryptographic and DNS standards:
            
            1. **SPF (Sender Policy Framework)**:
               - A DNS TXT record listing all IP addresses authorized to send emails on behalf of a domain.
               - Prevents attackers from using simple mail-servers to forge the envelope sender.
               
            2. **DKIM (DomainKeys Identified Mail)**:
               - Adds a cryptographic signature to email headers matching a public key published in DNS.
               - Guarantees message integrity: ensures the email was not tampered with in transit.
               
            3. **DMARC (Domain-based Message Authentication)**:
               - Bridges SPF and DKIM with an alignment policy (`none`, `quarantine`, `reject`).
               - Instructs receiving servers to automatically reject emails that fail SPF/DKIM checks.
            """
        )

    with g2:
        st.markdown("### 🧮 Mathematical Model: Shannon Entropy in SecOps")
        st.markdown(
            """
            **Formula:**
            $$H(X) = -\\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)$$
            
            **Why it matters in Cybersecurity:**
            - **Natural Language:** English words have recurring patterns (`th`, `ea`, `in`), resulting in entropy values between **2.0 and 3.5**.
            - **Domain Generation Algorithms (DGA):** Malware and phishing automation generate pseudo-random strings (e.g. `as98d7f12jh.xyz`), producing entropy **>= 3.9**.
            - PhishGuard flags domains with abnormally high entropy as automated or disposable.
            """
        )

    st.divider()
    st.markdown("### 📋 Organizational Anti-Phishing Defense Checklist")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**1. Technical Controls**")
        st.markdown("- Enforce FIDO2 / WebAuthn Hardware Keys (immune to credential proxy phishing).")
        st.markdown("- Implement DNS filtering (Quad9, Cloudflare Zero Trust).")
        st.markdown("- Restrict macro execution in office attachments.")
    with c2:
        st.markdown("**2. Email Gateway Hardening**")
        st.markdown("- Configure DMARC policy with `p=reject`.")
        st.markdown("- Strip or rewrite inbound email links using Secure Email Gateways (SEG).")
        st.markdown("- Add visual external sender warning tags.")
    with c3:
        st.markdown("**3. Human Defense**")
        st.markdown("- Conduct monthly simulated phishing tests.")
        st.markdown("- Establish a clear 1-click 'Report Phishing' button.")
        st.markdown("- Enforce multi-channel verification for wire transfer requests.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.markdown(
    """
    <div style="text-align: center; color: #8b949e; font-size: 0.82rem; padding: 1.2rem 0; line-height: 1.6;">
        🛡️ <strong>PhishGuard Threat Intelligence Suite</strong> &nbsp;|&nbsp;
        Developed by <strong>Vishal Pal</strong>
     </div>  
    """,
    unsafe_allow_html=True,
)
