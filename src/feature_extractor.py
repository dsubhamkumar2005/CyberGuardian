import ipaddress
import math
import re
from urllib.parse import urlparse, unquote
import tldextract

# ---------------------------------------------------------------------------
# GLOBAL CONSTANTS AND KNOWLEDGE BASES
# ---------------------------------------------------------------------------

# Known URL shortener services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "shorturl.at", "rebrand.ly",
    "tiny.cc", "clck.ru", "cutt.ly", "g5.lu", "tny.im", "bc.vc",
    "u.to", "v.gd", "rb.gy", "shortcm.li", "isgd.net"
}

# TLDs historically observed with statistically elevated abuse / registration volatility
# Note: Used strictly as a weak statistical feature alongside other indicators, never as a sole verdict.
HIGH_RISK_TLDS = {
    "xyz", "top", "club", "work", "ru", "cn", "tk", "ml", "ga", "cf", "gq",
    "buzz", "wang", "link", "icu", "cam", "sbs", "surf", "space", "monster",
    "fit", "rest", "click", "live", "su", "pw", "country", "stream",
    "download", "racing", "kim", "loan", "gdn", "bid", "men", "date",
    "accountant", "party", "trade", "science", "cricket"
}

# Accredited institutional TLDs with verified organizational registration controls
INSTITUTIONAL_TLDS = {
    "edu", "gov", "mil", "ac.uk", "gov.uk", "edu.au", "gov.au",
    "edu.in", "gov.in", "ac.in", "edu.cn", "gov.cn"
}

# Major targeted brands frequently impersonated in credential phishing
TARGETED_BRANDS = {
    "paypal", "apple", "microsoft", "google", "netflix", "amazon", "chase",
    "wellsfargo", "bankofamerica", "facebook", "instagram", "binance",
    "coinbase", "walmart", "steam", "roblox", "outlook", "yahoo", "dropbox",
    "adobe", "dhl", "fedex", "usps", "icloud", "meta", "whatsapp", "telegram"
}

# Strong credential harvesting keywords (matched as whole tokens)
CREDENTIAL_LURE_TOKENS = {
    "login", "signin", "verify", "verification", "authenticate", "wallet",
    "password", "credential", "webscr", "ebayisapi", "securelogin",
    "accountrecovery", "banking", "passcode"
}

# Ambiguous lure keywords suspicious when occurring in domain or subdomain
DOMAIN_LURE_TOKENS = {
    "secure", "security", "account", "banking", "update", "confirm",
    "recover", "validate", "token", "support", "billing", "service"
}

# Known executable and script payload extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".apk", ".dll", ".bin", ".lnk", ".bat", ".sh",
    ".vbs", ".iso", ".msi", ".ps1", ".cmd", ".scr", ".jar"
}

# Reusable TLDExtract instance with public suffix list support
_EXTRACTOR = tldextract.TLDExtract(include_psl_private_domains=True)


# ---------------------------------------------------------------------------
# URL SANITIZATION & VALIDATION
# ---------------------------------------------------------------------------

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validates the URL string and ensures the scheme is HTTP or HTTPS.
    Safely rejects malformed or non-web schemes (e.g. javascript:, data:, file:).
    Returns (is_valid, normalized_url_or_error_message).
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL input"

    clean_url = url.strip()
    if not clean_url:
        return False, "Empty URL string"

    lower_url = clean_url.lower()
    non_web_schemes = ("javascript:", "data:", "file:", "mailto:", "ftp:", "about:", "blob:")
    for bad_scheme in non_web_schemes:
        if lower_url.startswith(bad_scheme):
            return False, f"Unsupported URL scheme '{bad_scheme.rstrip(':')}' (only HTTP/HTTPS supported)"

    # Prepend scheme if missing for accurate parsing
    normalized = clean_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        normalized = "http://" + clean_url

    try:
        parsed = urlparse(normalized)
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported protocol scheme '{parsed.scheme}'"
        if not parsed.netloc and not parsed.hostname:
            return False, "Malformed URL: missing hostname or network location"
    except Exception as exc:
        return False, f"Malformed URL parsing error: {exc}"

    return True, normalized


# ---------------------------------------------------------------------------
# FEATURE EXTRACTION HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    length = len(text)

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def is_ip_address(hostname: str) -> int:
    """
    Robust check whether hostname is an IPv4 or IPv6 address.
    Correctly handles bare IPs, bracketed IPv6, and port-bearing addresses.
    E.g.: '192.168.1.1:8080', '[2001:db8::1]:8443', '::1'
    """
    if not hostname:
        return 0

    clean = hostname.strip()

    # Handle bracketed IPv6 (with or without port): [2001:db8::1] or [2001:db8::1]:8080
    if clean.startswith("[") and "]" in clean:
        clean = clean[1:clean.index("]")]
    elif ":" in clean:
        # IPv4 with port has exactly 1 colon: 192.168.1.1:8080
        # IPv6 addresses have multiple colons: 2001:db8::1
        if clean.count(":") == 1:
            clean = clean.split(":")[0]

    try:
        ipaddress.ip_address(clean)
        return 1
    except ValueError:
        return 0


def count_subdomains(url: str, hostname: str = "") -> int:
    """
    Accurately count subdomains using the Public Suffix List.
    Correctly recognizes multi-part suffixes like '.co.uk', '.com.au', etc.
    """
    if not hostname and not url:
        return 0

    if is_ip_address(hostname):
        return 0

    extracted = _EXTRACTOR(url if "://" in url else "http://" + url)
    sub = extracted.subdomain.strip()
    if not sub:
        return 0

    return len(sub.split("."))


def count_special_characters(url: str) -> int:
    """Count special characters commonly found in URLs: @?=-_&%#:/.!"""
    special_characters = "@?=-_&%#:/.!"
    return sum(1 for char in url if char in special_characters)


def count_digits(url: str) -> int:
    """Count numeric digits (0-9) in the URL."""
    return sum(1 for char in url if char.isdigit())


def calculate_digit_ratio(url: str, length: int) -> float:
    """Calculate the ratio of digits to total characters in the URL."""
    if length == 0:
        return 0.0
    return round(count_digits(url) / length, 4)


def count_hyphens(url: str) -> int:
    """Count occurrences of hyphens '-' in the URL."""
    return url.count("-")


def check_at_symbol(url: str) -> int:
    """Check if the URL contains '@' (credential injection / open redirect technique)."""
    return 1 if "@" in url else 0


def check_double_slash_redirect(path: str) -> int:
    """Check for '//' in the URL path (open redirect attempt)."""
    if not path:
        return 0
    return 1 if "//" in path else 0


def check_url_shortener(hostname: str) -> int:
    """Check if the hostname matches known URL shortener services."""
    if not hostname:
        return 0
    h_lower = hostname.lower().strip()
    return 1 if h_lower in SHORTENER_DOMAINS or any(h_lower.endswith("." + d) for d in SHORTENER_DOMAINS) else 0


def check_suspicious_keywords(url: str, hostname: str = "") -> int:
    """
    Check for suspicious phishing or credential harvesting keywords.
    Uses tokenization (word boundaries) to avoid false positives on words like 'cybersecurity'.
    """
    url_lower = unquote(url).lower()
    hostname_lower = (hostname or "").lower()

    url_tokens = set(re.findall(r"[a-zA-Z0-9]+", url_lower))
    hostname_tokens = set(re.findall(r"[a-zA-Z0-9]+", hostname_lower))

    # Check for direct credential lure tokens in the URL
    if any(token in url_tokens for token in CREDENTIAL_LURE_TOKENS):
        return 1

    # Check for brand/domain manipulation lures in the hostname
    if any(token in hostname_tokens for token in DOMAIN_LURE_TOKENS):
        return 1

    return 0


def check_high_risk_tld(suffix: str) -> int:
    """Check if the top-level domain suffix is in statistical high-abuse TLD set."""
    if not suffix:
        return 0
    s_lower = suffix.lower().strip().split(".")[-1]
    return 1 if s_lower in HIGH_RISK_TLDS else 0


def check_institutional_tld(suffix: str) -> int:
    """Check if the suffix is an accredited institutional/government TLD (e.g. .edu, .gov)."""
    if not suffix:
        return 0
    s_lower = suffix.lower().strip()
    return 1 if s_lower in INSTITUTIONAL_TLDS or any(s_lower.endswith("." + t) or s_lower == t for t in ("edu", "gov", "mil")) else 0


def check_brand_impersonation(url: str, hostname: str, extracted_domain: str) -> int:
    """
    Detect brand impersonation: checks if a known brand appears in the URL
    (subdomain, path, credentials, or hyphenated domain), but the registrable domain is NOT the brand's own domain.
    E.g.: 'paypal-security.com' -> 1, 'paypal.com' -> 0, 'bankofamerica.com@evil.com' -> 1
    """
    url_lower = unquote(url).lower()
    host_lower = (hostname or "").lower()
    reg_domain = (extracted_domain or "").lower()

    for brand in TARGETED_BRANDS:
        if brand in url_lower:
            if reg_domain == brand or reg_domain.startswith(brand + "."):
                continue
            if brand in host_lower or f"@{brand}" in url_lower or f"{brand}-" in host_lower or f"-{brand}" in host_lower:
                return 1
            path_tokens = set(re.findall(r"[a-zA-Z0-9]+", url_lower))
            if brand in path_tokens and reg_domain != brand:
                return 1
    return 0


def check_non_standard_port(parsed_url) -> int:
    """Check if the URL explicitly defines a non-standard network port (not 80 or 443)."""
    try:
        port = parsed_url.port
        if port is not None and port not in (80, 443):
            return 1
    except (ValueError, TypeError):
        pass
    return 0


def check_executable_extension(path: str) -> int:
    """Check if the URL path ends with an executable or payload script extension."""
    if not path:
        return 0
    clean_path = path.lower().split("?")[0].split("#")[0].rstrip("/")
    return 1 if any(clean_path.endswith(ext) for ext in EXECUTABLE_EXTENSIONS) else 0


# ---------------------------------------------------------------------------
# MAIN FEATURE EXTRACTION (EXACTLY 23 PARAMETERS)
# ---------------------------------------------------------------------------

FEATURE_COLUMNS_V3 = [
    # Core 16 lexical and structural parameters
    "length",
    "path_length",
    "query_length",
    "subdomain_count",
    "num_subdirectories",
    "uses_ip",
    "has_https",
    "special_char_count",
    "shannon_entropy",
    "num_digits",
    "digit_ratio",
    "num_hyphens",
    "has_at_symbol",
    "has_double_slash_redirect",
    "is_shortened",
    "has_suspicious_keywords",

    # Advanced statistical & security signals (7 features)
    "domain_entropy",
    "path_entropy",
    "is_high_risk_tld",
    "is_institutional_tld",
    "brand_impersonation",
    "non_standard_port",
    "has_executable_extension",
]


def extract_features(url: str) -> dict:
    """
    Extracts exactly 23 numerical security parameters from a URL:
    1.  length                     (Total URL character length)
    2.  path_length                (Length of URL path)
    3.  query_length               (Length of query parameters)
    4.  subdomain_count            (PSL-aware subdomain depth)
    5.  num_subdirectories         (Path directory hierarchy count)
    6.  uses_ip                    (IPv4 or IPv6 address indicator)
    7.  has_https                  (HTTPS protocol indicator)
    8.  special_char_count         (Count of special characters)
    9.  shannon_entropy            (Overall URL Shannon entropy)
    10. num_digits                 (Count of numeric digits)
    11. digit_ratio                (Ratio of digits to length)
    12. num_hyphens                (Count of hyphens in URL)
    13. has_at_symbol              (Presence of '@' credential injection)
    14. has_double_slash_redirect  (Presence of '//' open redirect pattern in path)
    15. is_shortened               (Known URL shortener service indicator)
    16. has_suspicious_keywords    (Tokenized credential phishing keywords)
    17. domain_entropy             (Shannon entropy of hostname/domain)
    18. path_entropy               (Shannon entropy of path & query)
    19. is_high_risk_tld           (Statistical high-abuse TLD flag)
    20. is_institutional_tld       (Accredited .edu/.gov/.mil domain flag)
    21. brand_impersonation        (Contextual brand mismatch detection)
    22. non_standard_port          (Non-standard network port specified)
    23. has_executable_extension   (Payload/executable extension in path)
    """
    url_str = str(url).strip()

    valid, validated_or_err = validate_url(url_str)
    parsed_input = validated_or_err if valid else ("http://" + url_str if "://" not in url_str else url_str)

    parsed_url = urlparse(parsed_input)
    hostname = (parsed_url.hostname or "").strip()
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    # Parse registrable domain via Public Suffix List
    extracted = _EXTRACTOR(parsed_input)
    reg_domain = extracted.domain.lower() if extracted.domain else ""
    suffix = extracted.suffix.lower() if extracted.suffix else ""

    # 1. Structural dimensions
    length = len(url_str)
    path_length = len(path)
    query_length = len(query)

    clean_path = path.strip("/")
    num_subdirectories = len(clean_path.split("/")) if clean_path else 0
    subdomain_count = count_subdomains(parsed_input, hostname)

    # 2. Host, protocol, and network parameters
    uses_ip = is_ip_address(hostname)
    has_https = 1 if parsed_url.scheme.lower() == "https" else 0
    is_shortened = check_url_shortener(hostname)
    non_standard_port = check_non_standard_port(parsed_url)
    is_high_risk_tld = check_high_risk_tld(suffix)
    is_institutional_tld = check_institutional_tld(suffix)

    # 3. Statistical & entropy parameters
    special_char_count = count_special_characters(url_str)
    shannon_entropy = calculate_entropy(url_str)
    domain_entropy = calculate_entropy(hostname)
    path_entropy = calculate_entropy(path + ("?" + query if query else ""))
    num_digits = count_digits(url_str)
    digit_ratio = calculate_digit_ratio(url_str, length)
    num_hyphens = count_hyphens(url_str)

    # 4. Attack pattern & payload indicators
    has_at_symbol = check_at_symbol(url_str)
    has_double_slash_redirect = check_double_slash_redirect(path)
    has_suspicious_keywords = check_suspicious_keywords(url_str, hostname)
    brand_impersonation = check_brand_impersonation(url_str, hostname, reg_domain)
    has_executable_extension = check_executable_extension(path)

    return {
        "length": length,
        "path_length": path_length,
        "query_length": query_length,
        "subdomain_count": subdomain_count,
        "num_subdirectories": num_subdirectories,
        "uses_ip": uses_ip,
        "has_https": has_https,
        "special_char_count": special_char_count,
        "shannon_entropy": shannon_entropy,
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "num_hyphens": num_hyphens,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "is_shortened": is_shortened,
        "has_suspicious_keywords": has_suspicious_keywords,
        "domain_entropy": domain_entropy,
        "path_entropy": path_entropy,
        "is_high_risk_tld": is_high_risk_tld,
        "is_institutional_tld": is_institutional_tld,
        "brand_impersonation": brand_impersonation,
        "non_standard_port": non_standard_port,
        "has_executable_extension": has_executable_extension,
    }


# ---------------------------------------------------------------------------
# CLI VERIFICATION
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_suite = [
        "https://google.com",
        "https://docs.python.org/3/library/math.html",
        "http://[2001:db8::1]:8080/login/update",
        "http://192.168.1.50:8080/login/paypal/update",
        "https://amazon.co.uk/dp/B08N5WRWNW",
        "http://paypal-security-alert.com//verify-account?token=89234823",
        "http://bankofamerica.com@evil-phishing.ru/auth/login.php",
        "https://dl.zerotheme.ir/kokorila/cgl-bin/bin.exe",
        "https://subdomain.university.edu/courses/cs101/syllabus",
    ]

    print("=" * 72)
    print(f"VERIFIED FEATURE EXTRACTOR PIPELINE (EXACTLY {len(FEATURE_COLUMNS_V3)} PARAMETERS)")
    print("=" * 72)

    for test_url in test_suite:
        print(f"\nURL: {test_url}")
        feats = extract_features(test_url)
        assert len(feats) == len(FEATURE_COLUMNS_V3), f"Count mismatch: {len(feats)} vs {len(FEATURE_COLUMNS_V3)}"
        for k in FEATURE_COLUMNS_V3:
            print(f"  {k:26}: {feats[k]}")
        print("-" * 72)
    print("\nAll feature extractions completed and validated.")