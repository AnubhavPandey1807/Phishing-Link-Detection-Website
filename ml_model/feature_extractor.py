import re
import tldextract
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

# Keywords often abused in phishing
SENSITIVE_KEYWORDS = ["secure", "account", "login", "bank", "update", "verify"]
BRAND_KEYWORDS = ["paypal", "google", "facebook", "amazon", "apple"]

# ✅ Final selected features (22 implemented now)
selected_features = [
    "NumDots", "SubdomainLevel", "PathLevel", "UrlLength",
    "NumDash", "NumDashInHostname", "AtSymbol", "TildeSymbol",
    "NumUnderscore", "NumPercent", "NumQueryComponents", "NumAmpersand",
    "NumHash", "NumNumericChars", "NoHttps", "IpAddress",
    "HostnameLength", "PathLength", "QueryLength", "DoubleSlashInPath",
    "NumSensitiveWords", "EmbeddedBrandName"
]

def is_ip_address(hostname):
    """Check if the hostname is an IP address"""
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    return 1 if ip_pattern.match(hostname) else 0

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    features = {
        # ✅ Implemented (22 features)
        "NumDots": url.count('.'),
        "SubdomainLevel": len(tldextract.extract(url).subdomain.split('.')) if tldextract.extract(url).subdomain else 0,
        "PathLevel": path.count('/'),
        "UrlLength": len(url),
        "NumDash": url.count('-'),
        "NumDashInHostname": hostname.count('-'),
        "AtSymbol": 1 if '@' in url else 0,
        "TildeSymbol": 1 if '~' in url else 0,
        "NumUnderscore": url.count('_'),
        "NumPercent": url.count('%'),
        "NumQueryComponents": query.count('='),
        "NumAmpersand": query.count('&'),
        "NumHash": url.count('#'),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "NoHttps": 0 if url.lower().startswith("https") else 1,
        "IpAddress": is_ip_address(hostname),
        "HostnameLength": len(hostname),
        "PathLength": len(path),
        "QueryLength": len(query),
        "DoubleSlashInPath": 1 if '//' in path else 0,
        "NumSensitiveWords": sum(1 for word in SENSITIVE_KEYWORDS if word in url.lower()),
        "EmbeddedBrandName": sum(1 for brand in BRAND_KEYWORDS if brand in url.lower()),

        # 🚧 TODO (26 more features placeholders)
        # "PctExtHyperlinks": 0,
        # "PctExtResourceUrls": 0,
        # "ExtFavicon": 0,
        # "InsecureForms": 0,
        # "RelativeFormAction": 0,
        # "ExtFormAction": 0,
        # "AbnormalFormAction": 0,
        # "PctNullSelfRedirectHyperlinks": 0,
        # "FrequentDomainNameMismatch": 0,
        # "FakeLinkInStatusBar": 0,
        # "RightClickDisabled": 0,
        # "PopUpWindow": 0,
        # "SubmitInfoToEmail": 0,
        # "IframeOrFrame": 0,
        # "MissingTitle": 0,
        # "ImagesOnlyInForm": 0,
        # "SubdomainLevelRT": 0,
        # "UrlLengthRT": 0,
        # "PctExtResourceUrlsRT": 0,
        # "AbnormalExtFormActionR": 0,
        # "ExtMetaScriptLinkRT": 0,
        # "PctExtNullSelfRedirectHyperlinksRT": 0,
        # "CLASS_LABEL": 0
    }


    # --- ADVANCED FEATURES (optional for demo) ---
    try:
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            if forms:
                for f in forms:
                    action = f.get("action", "").lower()
                    if action.startswith("mailto:"):
                        features["SubmitInfoToEmail"] = 1
                    if action.startswith("/") or action == "":
                        features["RelativeFormAction"] = 1
                    if "http" in action and hostname not in action:
                        features["ExtFormAction"] = 1
            if soup.find("iframe"):
                features["IframeOrFrame"] = 1
            if not soup.find("title"):
                features["MissingTitle"] = 1
    except Exception:
        pass

    # ✅ Return only implemented features
    return [features[f] for f in selected_features]