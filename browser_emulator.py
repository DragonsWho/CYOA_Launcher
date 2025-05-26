# browser_emulator.py
from urllib.parse import urlparse
from typing import Optional, Dict

# Specific headers for certain domains if needed
DOMAIN_SPECIFIC_HEADERS: Dict[str, Dict[str, str]] = {
    'imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
    'i.imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
    # 'static.zerochan.net': {"User-Agent": "Mozilla/5.0..."}
}

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"

def get_request_headers(
    target_url: str,
    referring_page_url: Optional[str] = None,
    sec_fetch_dest_override: Optional[str] = None # New parameter to specify resource type
) -> Dict[str, str]:
    """
    Generates headers for an HTTP request, mimicking a browser.
    """
    parsed_target = urlparse(target_url)
    target_domain = parsed_target.hostname

    # Determine Sec-Fetch-Dest: use override if provided, otherwise default to "image"
    # This default is because the component was initially for images.
    # The caller (project_downloader.py) will now be more specific.
    actual_sec_fetch_dest = sec_fetch_dest_override if sec_fetch_dest_override else "image"

    # Basic headers
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": actual_sec_fetch_dest,
    }

    # Adjust Accept header based on Sec-Fetch-Dest
    if actual_sec_fetch_dest == "style":
        headers["Accept"] = "text/css,*/*;q=0.1"
    elif actual_sec_fetch_dest == "script":
        headers["Accept"] = "application/javascript, */*;q=0.8" # Common for scripts
    elif actual_sec_fetch_dest == "document":
        headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    elif actual_sec_fetch_dest == "font":
        headers["Accept"] = "*/*" # Fonts often use */*
    elif actual_sec_fetch_dest == "image":
        headers["Accept"] = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
    else: # Default or "empty"
        headers["Accept"] = "*/*"


    # Apply domain-specific headers from this emulator's config.
    # These can override any of the general headers set above.
    if target_domain and target_domain in DOMAIN_SPECIFIC_HEADERS:
        headers.update(DOMAIN_SPECIFIC_HEADERS[target_domain])
    
    # Set Referer and Sec-Fetch-Site based on referring_page_url
    if referring_page_url:
        parsed_referer = urlparse(referring_page_url)
        if parsed_target.scheme and parsed_referer.scheme and \
           parsed_target.netloc and parsed_referer.netloc and \
           parsed_target.netloc.lower() != parsed_referer.netloc.lower():
            
            if "Sec-Fetch-Site" not in headers:
                headers["Sec-Fetch-Site"] = "cross-site"
            if "Referer" not in headers:
                headers["Referer"] = referring_page_url
            if "Sec-Fetch-Mode" not in headers:
                 headers["Sec-Fetch-Mode"] = "no-cors" # Typical for cross-site sub-resources

        else: # Same-origin or one of the URLs is incomplete/local
            if "Sec-Fetch-Site" not in headers:
                headers["Sec-Fetch-Site"] = "same-origin"
            if "Referer" not in headers and parsed_target.netloc == parsed_referer.netloc: # Add referer for same-origin too if not set
                 headers["Referer"] = referring_page_url
            if "Sec-Fetch-Mode" not in headers:
                headers["Sec-Fetch-Mode"] = "no-cors" # For same-origin sub-resources

    else: # No information about the referer page
        if "Sec-Fetch-Site" not in headers:
            headers["Sec-Fetch-Site"] = "none"
        if "Sec-Fetch-Mode" not in headers:
            # For 'none', if it's a document, it's 'navigate'. If subresource directly accessed, 'no-cors'
            # Defaulting to no-cors here as this function is mostly for sub-resources
            headers["Sec-Fetch-Mode"] = "no-cors" if actual_sec_fetch_dest != "document" else "navigate"


    return headers