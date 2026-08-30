from urllib.parse import urlparse


def is_valid_url(url):

    if not url:
        return False

    url = url.strip()

    try:
        parsed = urlparse(url)

        # Only allow HTTP/HTTPS
        if parsed.scheme not in ["http", "https"]:
            return False

        # URL must contain a hostname
        if not parsed.hostname:
            return False

        # Reject whitespace
        if any(char.isspace() for char in url):
            return False

        return True

    except Exception:
        return False