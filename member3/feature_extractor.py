from urllib.parse import urlparse
import ipaddress
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "password",
    "account",
    "update",
    "secure",
    "bank",
    "signin",
    "confirm"
]


def check_ip_address(domain):

    try:
        ipaddress.ip_address(domain)
        return True

    except ValueError:
        return False


def check_suspicious_keyword(url):

    url_lower = url.lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:
            return True

    return False


def count_special_characters(url):

    special_characters = r"[@?=&%]"

    return len(re.findall(special_characters, url))


def extract_features(url):

    parsed_url = urlparse(url)

    domain = parsed_url.hostname or ""

    features = {

        "url": url,

        "domain": domain,

        "url_length": len(url),

        "uses_https": parsed_url.scheme == "https",

        "has_ip": check_ip_address(domain),

        "num_dots": domain.count("."),

        "has_at_symbol": "@" in url,

        "has_suspicious_keyword":
            check_suspicious_keyword(url),

        "num_special_characters":
            count_special_characters(url),

        "num_subdomains":
            max(0, domain.count(".") - 1)
    }

    return features