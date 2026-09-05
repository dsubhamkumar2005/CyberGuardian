from urllib.parse import urlparse
import ipaddress
import math


def calculate_entropy(text):
    """
    Calculate Shannon entropy of a string.

    Higher entropy generally means the characters
    are more random/complex.
    """

    if not text:
        return 0.0

    # Count frequency of every character
    frequencies = {}

    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    length = len(text)

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_ip_address(hostname):
    """
    Check whether the hostname is an IP address.

    Returns:
        1 → IP address
        0 → normal domain
    """

    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def count_subdomains(hostname):
    """
    Count the number of subdomains.

    Example:
        example.com
        → 0

        login.example.com
        → 1

        login.account.example.com
        → 2
    """

    if not hostname:
        return 0

    # Remove trailing dot if present
    hostname = hostname.rstrip(".")

    parts = hostname.split(".")

    # IP addresses should not be treated as domains
    if is_ip_address(hostname):
        return 0

    # A normal domain needs at least:
    # domain + TLD
    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def count_special_characters(url):
    """
    Count special characters commonly found in URLs.

    We count:
        @
        ?
        =
        -
        _
        &
        %
        #
        .
        :
        /
    """

    special_characters = "@?=-_&%#:/.!"

    count = 0

    for char in url:
        if char in special_characters:
            count += 1

    return count


def extract_features(url):
    """
    Extract security-related features from a URL.

    The six ML features remain unchanged so the
    existing trained Random Forest model continues
    to work correctly.
    """

    # Make sure URL is a string
    url = str(url).strip()

    # Parse URL
    parsed_url = urlparse(url)

    # Get hostname/domain
    hostname = parsed_url.hostname or ""

    # Existing ML features
    length = len(url)
    subdomain_count = count_subdomains(hostname)
    uses_ip = is_ip_address(hostname)
    has_https = 1 if parsed_url.scheme.lower() == "https" else 0
    special_char_count = count_special_characters(url)
    shannon_entropy = calculate_entropy(url)

    # Additional security features
    url_lower = url.lower()

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "update",
        "secure",
        "account",
        "bank",
        "password",
        "signin",
        "confirm",
        "payment",
        "paypal"
    ]

    has_suspicious_keyword = any(
        keyword in url_lower
        for keyword in suspicious_keywords
    )

    features = {
        # Additional information
        "url": url,
        "domain": hostname,
        "url_length": length,
        "uses_https": bool(has_https),
        "has_ip": bool(uses_ip),
        "num_dots": url.count("."),
        "has_at_symbol": "@" in url,
        "has_suspicious_keyword": has_suspicious_keyword,
        "num_special_characters": special_char_count,
        "num_subdomains": subdomain_count,

        # Original ML features
        "length": length,
        "subdomain_count": subdomain_count,
        "uses_ip": uses_ip,
        "has_https": has_https,
        "special_char_count": special_char_count,
        "shannon_entropy": shannon_entropy
    }

    return features


# --------------------------------------------------
# TESTING
# --------------------------------------------------

if __name__ == "__main__":

    test_urls = [
        "https://google.com",
        "https://login.example.com/account/update",
        "http://192.168.1.50/login/paypal/update",
        "http://www.deskthipk.com/"
    ]

    print("=" * 60)
    print("TESTING FEATURE EXTRACTOR")
    print("=" * 60)

    for url in test_urls:

        print("\nURL:")
        print(url)

        features = extract_features(url)

        print("\nExtracted features:")

        for feature, value in features.items():
            print(f"{feature}: {value}")

        print("-" * 60)