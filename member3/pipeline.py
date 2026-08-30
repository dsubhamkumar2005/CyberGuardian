from url_validator import is_valid_url
from feature_extractor import extract_features


processed_urls = set()


def process_url(url):

    # Remove unnecessary spaces
    url = url.strip()

    # Validate URL
    if not is_valid_url(url):

        return {
            "valid": False,
            "duplicate": False,
            "message": "Invalid URL"
        }

    # Normalize URL for duplicate checking
    normalized_url = url.lower()

    # Check duplicate
    if normalized_url in processed_urls:

        return {
            "valid": True,
            "duplicate": True,
            "message": "URL already processed",
            "url": url
        }

    # Store URL
    processed_urls.add(normalized_url)

    # Extract features
    features = extract_features(url)

    return {
        "valid": True,
        "duplicate": False,
        "features": features
    }