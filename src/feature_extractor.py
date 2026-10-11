from urllib.parse import urlparse
import ipaddress
import math
import re

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "shorturl.at", "rebrand.ly",
    "tiny.cc", "clck.ru", "cutt.ly", "g5.lu", "tny.im", "bc.vc"
}

# Strong credential harvesting and phishing keywords (matched as whole tokens)
CREDENTIAL_LURE_TOKENS = {
    "login", "signin", "verify", "verification",
    "authenticate", "wallet", "password", "credential", "webscr", "ebayisapi"
}

# Ambiguous lure keywords that indicate phishing when present in the hostname / domain
DOMAIN_LURE_TOKENS = {
    "secure", "security", "account", "banking", "update", "confirm",
    "recover", "validate", "token"
}


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Higher entropy indicates more randomness / complexity (common in DGAs).
    """
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

    return entropy


def is_ip_address(hostname: str) -> int:
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    Returns:
        1 -> IP address
        0 -> normal domain name
    """
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def count_subdomains(hostname: str) -> int:
    """
    Count the number of subdomains.
    Example:
        example.com -> 0
        login.example.com -> 1
        login.account.example.com -> 2
    """
    if not hostname:
        return 0

    hostname = hostname.rstrip(".")

    if is_ip_address(hostname):
        return 0

    parts = hostname.split(".")
    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def count_special_characters(url: str) -> int:
    """
    Count special characters commonly found in URLs: @?=-_&%#:/.!
    """
    special_characters = "@?=-_&%#:/.!"
    count = 0
    for char in url:
        if char in special_characters:
            count += 1
    return count


def count_digits(url: str) -> int:
    """
    Count the number of numeric digits (0-9) in the URL.
    """
    return sum(1 for char in url if char.isdigit())


def calculate_digit_ratio(url: str, length: int) -> float:
    """
    Calculate the ratio of digits to total characters in the URL.
    """
    if length == 0:
        return 0.0
    digits = count_digits(url)
    return round(digits / length, 4)


def count_hyphens(url: str) -> int:
    """
    Count occurrences of hyphens '-'.
    Attackers frequently use hyphens for brand impersonation
    (e.g., 'paypal-security-update.com').
    """
    return url.count("-")


def check_at_symbol(url: str) -> int:
    """
    Check if the URL contains '@'.
    In URLs, '@' causes browsers to treat everything before it as user credentials,
    redirecting the victim to the host specified after '@'.
    """
    return 1 if "@" in url else 0


def check_double_slash_redirect(path: str) -> int:
    """
    Check for '//' in the URL path.
    Often used in open-redirect attacks (e.g., 'http://example.com//phish.com').
    """
    if not path:
        return 0
    return 1 if "//" in path else 0


def check_url_shortener(hostname: str) -> int:
    """
    Check if the hostname matches known URL shortener services.
    Shorteners conceal the final destination and target URL.
    """
    if not hostname:
        return 0
    hostname_lower = hostname.lower().strip()
    return 1 if hostname_lower in SHORTENER_DOMAINS else 0


def check_suspicious_keywords(url: str, hostname: str = "") -> int:
    """
    Check for suspicious phishing or credential harvesting keywords.
    Uses tokenization (word boundaries) to avoid false positives on words like 'cybersecurity'.
    - Lures like 'login', 'verify', 'wallet' are flagged anywhere when appearing as whole tokens.
    - Ambiguous lures like 'security', 'secure', 'account' are flagged if appearing in the hostname/domain.
    """
    url_lower = url.lower()
    hostname_lower = (hostname or "").lower()

    # Extract clean alphanumeric word tokens
    url_tokens = set(re.findall(r"[a-zA-Z0-9]+", url_lower))
    hostname_tokens = set(re.findall(r"[a-zA-Z0-9]+", hostname_lower))

    # Check for direct credential lure tokens in the URL
    if any(token in url_tokens for token in CREDENTIAL_LURE_TOKENS):
        return 1

    # Check for brand/domain manipulation lures in the hostname
    if any(token in hostname_tokens for token in DOMAIN_LURE_TOKENS):
        return 1

    return 0


def extract_features(url: str) -> dict:
    """
    Convert a raw URL into 16 numerical security features:
        1.  length
        2.  path_length
        3.  query_length
        4.  subdomain_count
        5.  num_subdirectories
        6.  uses_ip
        7.  has_https
        8.  special_char_count
        9.  shannon_entropy
        10. num_digits
        11. digit_ratio
        12. num_hyphens
        13. has_at_symbol
        14. has_double_slash_redirect
        15. is_shortened
        16. has_suspicious_keywords
    """
    url = str(url).strip()

    # Prepend scheme if missing for accurate urlparse parsing
    parsed_input = url
    if not re.match(r"^[a-zA-Z]+://", url):
        parsed_input = "http://" + url

    parsed_url = urlparse(parsed_input)
    hostname = parsed_url.hostname or ""
    path = parsed_url.path or ""
    query = parsed_url.query or ""

    # 1. Length metrics
    length = len(url)
    path_length = len(path)
    query_length = len(query)

    # 2. Structural & hierarchy metrics
    subdomain_count = count_subdomains(hostname)
    clean_path = path.strip("/")
    num_subdirectories = len(clean_path.split("/")) if clean_path else 0

    # 3. Protocol & host security checks
    uses_ip = is_ip_address(hostname)
    has_https = 1 if parsed_url.scheme.lower() == "https" else 0
    is_shortened = check_url_shortener(hostname)

    # 4. Statistical & character metrics
    special_char_count = count_special_characters(url)
    shannon_entropy = calculate_entropy(url)
    num_digits = count_digits(url)
    digit_ratio = calculate_digit_ratio(url, length)
    num_hyphens = count_hyphens(url)

    # 5. Attack pattern indicators (with tokenization)
    has_at_symbol = check_at_symbol(url)
    has_double_slash_redirect = check_double_slash_redirect(path)
    has_suspicious_keywords = check_suspicious_keywords(url, hostname)

    return {
        "length": length,
        "path_length": path_length,
        "query_length": query_length,
        "subdomain_count": subdomain_count,
        "num_subdirectories": num_subdirectories,
        "uses_ip": uses_ip,
        "has_https": has_https,
        "special_char_count": special_char_count,
        "shannon_entropy": round(shannon_entropy, 4),
        "num_digits": num_digits,
        "digit_ratio": digit_ratio,
        "num_hyphens": num_hyphens,
        "has_at_symbol": has_at_symbol,
        "has_double_slash_redirect": has_double_slash_redirect,
        "is_shortened": is_shortened,
        "has_suspicious_keywords": has_suspicious_keywords
    }


# --------------------------------------------------
# TESTING
# --------------------------------------------------

if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "https://en.wikipedia.org/wiki/Cybersecurity",
        "https://login.example.com/account/update",
        "http://192.168.1.50/login/paypal/update",
        "http://www.deskthipk.com/",
        "https://g5.lu/vu39k",
        "http://paypal-security-alert.com//verify-account?token=89234823"
    ]

    print("=" * 60)
    print("TESTING REFINED FEATURE EXTRACTOR (TOKENIZED KEYWORDS)")
    print("=" * 60)

    for test_url in test_urls:
        print(f"\nURL: {test_url}")
        feats = extract_features(test_url)
        print("Extracted features:")
        for k, v in feats.items():
            print(f"  {k:26}: {v}")
        print("-" * 60)