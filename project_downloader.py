# project_downloader.py (Corrected and Complete)

import os
import re
import json

from urllib.parse import urljoin, urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import sleep, time
from bs4 import BeautifulSoup
from functools import lru_cache
from pathlib import Path
import chardet
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
import mimetypes
import base64
from typing import Optional, List, Tuple, Callable

# --- Global variables and settings ---
# LOGS_DIR = 'logs_downloader' # Removed
# os.makedirs(LOGS_DIR, exist_ok=True) # Removed
# log_file_path = os.path.join(LOGS_DIR, 'project_downloader.log') # Removed

# _logger = logging.getLogger('project_downloader_module') # Removed
# if not _logger.hasHandlers(): # Removed
#     _logger.setLevel(logging.DEBUG) # Removed
#     fh = logging.FileHandler(log_file_path, mode='a', encoding='utf-8') # Append mode # Removed
#     fh.setLevel(logging.DEBUG) # Removed
#     formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s') # Removed
#     fh.setFormatter(formatter) # Removed
#     _logger.addHandler(fh) # Removed
#     # Uncomment for console logging during development # Removed
#     # sh = logging.StreamHandler() # Removed
#     # sh.setLevel(logging.INFO) # Or DEBUG # Removed
#     # sh.setFormatter(formatter) # Removed
#     # _logger.addHandler(sh) # Removed

metadata_lock = threading.Lock()

DOMAIN_HEADERS = {
    'imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
    'i.imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
}

# --- Helper Functions ---

def detect_encoding(content: bytes) -> str:
    """Detects the encoding of a byte string."""
    # _logger.debug("Detecting encoding for content.") # Removed
    result = chardet.detect(content)
    return result['encoding'] if result['encoding'] else 'utf-8'

@lru_cache(maxsize=1000)
def is_valid_url(url: str, base_domain: Optional[str] = None) -> bool:
    """Checks if a URL is syntactically valid and uses http/https."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return False
    if parsed.scheme not in {'http', 'https'}:
        return False
    return True

def extract_urls_from_css(css_content: str) -> List[str]:
    """Extracts URLs from CSS 'url()' declarations."""
    urls = re.findall(r'url\((?:\'|"|)(.*?)(?:\'|"|)\)', css_content)
    return urls

def is_local_resource(src: str, base_url: str) -> bool:
    """
    Determines if a resource URL (src) is local relative to a base_url.
    'Local' means it's on the same domain or a relative path.
    Data URIs are considered not local for downloading purposes.
    """
    src_stripped = src.strip()
    if src_stripped.startswith('data:'):
        return False
    if not src_stripped: # Empty src="" is considered local (relative to base_url)
        return True

    parsed_src = urlparse(src_stripped)
    parsed_base = urlparse(base_url)

    # If src has a scheme and netloc, it's an absolute URL
    if parsed_src.scheme and parsed_src.netloc:
        return parsed_src.netloc == parsed_base.netloc

    # If src starts with '//', it's protocol-relative
    if src_stripped.startswith('//'):
        scheme_to_use = parsed_base.scheme if parsed_base.scheme else 'http'
        try:
            parsed_protocol_relative = urlparse(f"{scheme_to_use}:{src_stripped}")
            # Handle cases like file:/// where netloc might be empty
            if not parsed_protocol_relative.netloc and not parsed_base.netloc:
                 return True
            return parsed_protocol_relative.netloc == parsed_base.netloc
        except ValueError:
            # _logger.warning(f"ValueError parsing protocol-relative URL: {src_stripped} with scheme {scheme_to_use}") # Removed
            return False # Treat as non-local on error

    # All other cases (e.g., "images/pic.png", "./style.css", "script.js") are relative paths
    return True

def sanitize_filename_component(name_part: str) -> str:
    """Removes or replaces invalid characters for path components or filenames."""
    name_part = unquote(name_part) # Decode URL-encoding like %20
    name_part = re.sub(r'[<>:"/\\|?*\s]', '_', name_part) # Replace invalid chars and whitespace
    return name_part[:200] # Limit length

def enumerate_project_resources(data: any,
                                known_resource_dirs: Optional[List[str]] = None):
    """
    Recursively enumerates potential relative resource paths from JSON data.
    Yields string values that are likely relative paths to game assets.
    """
    if known_resource_dirs is None:
        known_resource_dirs = ['images', 'img', 'music', 'audio', 'sounds', 'videos', 'fonts', 'css', 'js', 'assets', 'data', 'downloaded_external_images']

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                val_stripped = value.strip()
                # _logger.debug(f"Enum checking in dict - key: '{key}', value: '{val_stripped}'") # Removed

                # A potential resource path is:
                # 1. Not empty
                # 2. Not a data: URI
                # 3. Not an absolute URL (i.e., does not have scheme AND netloc)
                #    (allows for relative paths like 'file.png' or 'subdir/file.png' or '//same.domain/file.png' which is_local_resource handles)
                
                is_not_data_uri = not val_stripped.startswith('data:')
                parsed_val = urlparse(val_stripped)
                is_relative_or_protocol_relative_on_same_domain = not (parsed_val.scheme and parsed_val.netloc) or \
                                                                 val_stripped.startswith('//') # is_local_resource will verify domain for '//'

                if val_stripped and is_not_data_uri and is_relative_or_protocol_relative_on_same_domain:
                    # Now, determine if it's something we should try to fetch.
                    # It's a resource if:
                    # a) It has a common file extension, OR
                    # b) It starts with one of the known_resource_dirs
                    path_obj = Path(val_stripped)
                    has_common_extension = path_obj.suffix.lower() in {
                        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico', # images
                        '.mp3', '.wav', '.ogg', '.m4a', # audio
                        '.mp4', '.webm', '.ogv', # video
                        '.ttf', '.otf', '.woff', '.woff2', # fonts
                        '.css', '.js', '.json', # styles, scripts, data
                        '.txt', '.xml', '.md' # text
                    }
                    # Check if path starts with any of the known_resource_dirs elements + "/"
                    # e.g. "images/char.png" starts with "images/"
                    # Important: "image.png" does NOT start with "images/"
                    starts_with_known_dir = any(val_stripped.startswith(f"{d}/") for d in known_resource_dirs)

                    if has_common_extension or starts_with_known_dir:
                        # _logger.info(f"Yielding resource from project.json (enum): '{val_stripped}' (Key: '{key}')") # Removed
                        yield val_stripped
                    # else: # Removed
                        # _logger.debug(f"Skipping path '{val_stripped}' (Key: '{key}') from project.json (enum) - no common extension and not in known dirs.") # Removed
                # else:
                    # _logger.debug(f"Value '{val_stripped}' (Key: '{key}') is not a potential relative path for enumeration.")

            elif isinstance(value, (dict, list)):
                yield from enumerate_project_resources(value, known_resource_dirs)
    elif isinstance(data, list):
        for item in data:
            yield from enumerate_project_resources(item, known_resource_dirs)


def get_headers_for_url(url: str) -> dict:
    """Returns custom headers for the URL or default ones."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        if domain and domain in DOMAIN_HEADERS: # Check if domain is not None
            # _logger.debug(f"Using custom headers for domain: {domain}") # Removed
            return DOMAIN_HEADERS[domain]
        # Default headers for requests
        return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1", # For HTML main page
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none", # or "cross-site" if applicable
                "Sec-Fetch-User": "?1"
                }
    except Exception as e:
        # _logger.warning(f"Error parsing URL '{url}' for custom headers: {e}") # Removed
        return {"User-Agent": "Mozilla/5.0", "Accept": "*/*"} # Minimal fallback

def get_iframe_url_from_cyoa_cafe(game_url: str, session: requests.Session) -> Optional[str]:
    """Extracts the iframe URL from a cyoa.cafe page using their API or HTML."""
    if 'cyoa.cafe/game/' not in game_url:
        return None

    # _logger.info(f"Detected cyoa.cafe URL: {game_url}. Attempting to find iframe URL.") # Removed
    try:
        parsed_url = urlparse(game_url)
        path_parts = parsed_url.path.strip('/').split('/')

        if len(path_parts) < 2 or path_parts[0] != 'game':
            # _logger.error(f"Invalid cyoa.cafe game URL format: {game_url}") # Removed
            return None
        game_id = path_parts[1]
        api_url = f"https://cyoa.cafe/api/collections/games/records/{game_id}"

        # Use specific headers for API if needed, or session's default
        response = session.get(api_url, timeout=15)
        response.raise_for_status()
        data = response.json()
        iframe_url = data.get('iframe_url')

        if iframe_url:
            # _logger.info(f"Found iframe URL via API: {iframe_url}") # Removed
            return iframe_url
        else:
            # _logger.warning(f"'iframe_url' not found in API response for cyoa.cafe game ID: {game_id}. Trying HTML.") # Removed
            # Fallback: try to find the iframe directly on the game's HTML page
            page_response = session.get(game_url, timeout=15) # Use session for HTML page too
            page_response.raise_for_status()
            soup = BeautifulSoup(page_response.content, 'html.parser')
            iframe_tag = soup.find('iframe', src=True) # Ensure src attribute exists
            if iframe_tag and iframe_tag['src']:
                iframe_url = iframe_tag['src']
                # _logger.info(f"Found iframe URL from HTML source: {iframe_url}") # Removed
                return iframe_url
            else:
                # _logger.error(f"Could not find iframe_url via API or HTML for {game_url}") # Removed
                return None

    except requests.RequestException as e:
        # _logger.error(f"HTTP request failed while fetching from cyoa.cafe: {e}") # Removed
        return None
    except (json.JSONDecodeError, KeyError) as e:
        # _logger.error(f"Error parsing cyoa.cafe API response: {e}") # Removed
        return None

def create_session() -> requests.Session:
    """Creates a requests session with retry strategy and default headers."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504], # Retry on these status codes
        allowed_methods=["HEAD", "GET", "OPTIONS"] # Retry for these methods
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=50, # Adjusted pool sizes
        pool_maxsize=50,
        pool_block=False
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update(get_headers_for_url("http://example.com")) # Set some default modern headers
    return session

def download_file(url: str, path: Path, session: requests.Session, base_domain: str,
                  metadata_path: Path, request_delay: float = 0.05,
                  progress_callback: Optional[Callable[[str, str], None]] = None) -> Tuple[bool, bool]:
    """Downloads a single file, with ETag checking. Returns (success, was_downloaded_or_modified)."""
    if url.startswith('data:'): # Also skip favicons if they are data URIs
        # _logger.debug(f"Skipping data URI: {url[:60]}...") # Removed
        if progress_callback: progress_callback("skipped_data_uri", url)
        return True, False # Success (nothing to do), not downloaded

    # Common practice: skip downloading favicons unless explicitly needed.
    # Many sites have them, but they aren't critical game assets.
    if Path(urlparse(url).path).name.lower() == 'favicon.ico':
        # _logger.debug(f"Skipping favicon.ico: {url}") # Removed
        if progress_callback: progress_callback("skipped_favicon", url)
        return True, False


    metadata = {}
    if metadata_path.exists():
        try:
            with metadata_path.open('r', encoding='utf-8') as f:
                metadata = json.load(f)
        except Exception as e:
            pass
            # _logger.warning(f"Could not load metadata from {metadata_path}: {e}") # Removed

    file_metadata = metadata.get(url, {})
    local_etag = file_metadata.get('ETag')
    request_specific_headers = get_headers_for_url(url) # Get headers for this specific URL

    if path.exists() and local_etag:
        # _logger.debug(f"File exists, checking ETag for: {url}. Local ETag: {local_etag}") # Removed
        head_headers = request_specific_headers.copy()
        head_headers['If-None-Match'] = local_etag
        try:
            head_response = session.head(url, allow_redirects=True, timeout=10, headers=head_headers)
            # No raise_for_status() here, 304 is a valid success for this check
            if head_response.status_code == 304:
                # _logger.info(f"File up to date (304 Not Modified): {path.name}") # Removed
                if progress_callback: progress_callback("up-to-date", url)
                return True, False # Success, file not modified
            # If not 304, check server ETag from HEAD if available
            server_etag_from_head = head_response.headers.get('ETag')
            if server_etag_from_head and server_etag_from_head == local_etag:
                # _logger.info(f"File ETag matches (from HEAD): {path.name}") # Removed
                if progress_callback: progress_callback("up-to-date", url)
                return True, False
        except requests.RequestException as e:
            pass
            # _logger.warning(f"HEAD request for ETag check failed for {url}: {e}. Proceeding to download.") # Removed
        except Exception as e: # Catch other potential errors from session.head
            pass
            # _logger.warning(f"Unexpected error during HEAD for ETag check {url}: {e}. Proceeding to download.") # Removed


    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # _logger.debug(f"Attempting GET for {url}") # Removed
        with session.get(url, stream=True, timeout=30, headers=request_specific_headers) as response:
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            content_type = response.headers.get('Content-Type', '')
            server_etag_from_get = response.headers.get('ETag') # ETag from the GET request

            is_text_file = (
                path.suffix.lower() in {'.html', '.htm', '.js', '.css', '.json', '.txt', '.xml', '.svg'} or
                'text' in content_type or 'javascript' in content_type or 'json' in content_type
            )

            if is_text_file:
                content_bytes = response.content # Read all content at once for text files to use chardet
                encoding = detect_encoding(content_bytes)
                text_content = content_bytes.decode(encoding, errors='replace')
                path.write_text(text_content, encoding='utf-8') # Always save as UTF-8
            else:
                with path.open('wb') as f:
                    for chunk in response.iter_content(chunk_size=8192 * 4): # Increased chunk size
                        if chunk:
                            f.write(chunk)

            # Update metadata with the new ETag from the GET request
            if server_etag_from_get:
                with metadata_lock:
                    # Re-read metadata in case another thread modified it
                    if metadata_path.exists():
                        try:
                            with metadata_path.open('r', encoding='utf-8') as f_meta_read:
                                current_metadata_on_disk = json.load(f_meta_read)
                        except Exception: current_metadata_on_disk = {} # Fallback if read fails
                    else:
                        current_metadata_on_disk = {}
                    
                    current_metadata_on_disk[url] = {'ETag': server_etag_from_get}
                    metadata_path.parent.mkdir(parents=True, exist_ok=True) # Ensure dir exists
                    with metadata_path.open('w', encoding='utf-8') as f_meta_write:
                        json.dump(current_metadata_on_disk, f_meta_write, indent=2)

            # _logger.info(f"Downloaded: {path.name} (from {url})") # Removed
            if progress_callback: progress_callback("downloaded", url)
            if request_delay > 0: sleep(request_delay)
            return True, True # Success, downloaded/modified
    except requests.exceptions.RequestException as e: # More specific exception
        # _logger.error(f"Failed to download {url} due to RequestException: {e}") # Removed
        if progress_callback: progress_callback("failed", url)
        return False, False
    except Exception as e: # Catch-all for other unexpected errors
        # _logger.error(f"Unexpected error downloading {url}: {e}", exc_info=True) # Removed
        if progress_callback: progress_callback("failed", url)
        return False, False

# --- Resource Parsing Functions (parse_html_for_resources, parse_css_for_resources) ---
# These seem mostly okay, ensure _logger is used.

def parse_html_for_resources(html_content: str, base_url: str, base_domain: str) -> set[str]:
    """Parses HTML content for local resources (scripts, styles, images, etc.)."""
    soup = BeautifulSoup(html_content, 'html.parser')
    resources = set()
    # Common tags and attributes for resources
    tags_attrs = {
        'link': 'href', 'script': 'src', 'img': 'src',
        'video': 'src', 'audio': 'src', 'source': 'src',
        'iframe': 'src', # iframes can also point to local HTML documents
        'object': 'data',
        'embed': 'src',
        'image': 'xlink:href' # For SVG <image>
    }

    for tag_name, attr_name in tags_attrs.items():
        for tag in soup.find_all(tag_name, **{attr_name: True}): # Find tags that have the attribute
            src_val = tag[attr_name]
            if isinstance(src_val, list): # Some attributes like srcset can be lists
                src_val = src_val[0] # Take the first one for simplicity, or parse srcset properly

            if src_val and isinstance(src_val, str):
                src_cleaned = src_val.replace('\\', '/').strip()
                if is_local_resource(src_cleaned, base_url):
                    full_url = urljoin(base_url, src_cleaned)
                    if is_valid_url(full_url, base_domain):
                        resources.add(full_url)
                        # _logger.debug(f"HTML parser found local resource: {full_url}") # Removed
                    # else: # Removed
                        # _logger.debug(f"Skipping invalid local URL from HTML ({tag_name}): {full_url}") # Removed
                # else: # External or data URI
                    # _logger.debug(f"Skipping non-local/data URI from HTML ({tag_name}): {src_cleaned}")

    # Inline styles in <style> tags
    for style_tag in soup.find_all('style'):
        if style_tag.string:
            css_urls = extract_urls_from_css(style_tag.string)
            for item_url in css_urls:
                item_url_cleaned = item_url.replace('\\', '/').strip()
                if is_local_resource(item_url_cleaned, base_url): # base_url for inline CSS is the HTML page's URL
                    full_url = urljoin(base_url, item_url_cleaned)
                    if is_valid_url(full_url, base_domain): resources.add(full_url)
                    # else: _logger.debug(f"Skipping invalid local URL from inline CSS: {full_url}") # Removed

    # Inline styles in style="..." attributes
    for tag_with_style_attr in soup.find_all(style=True):
        style_content = tag_with_style_attr['style']
        css_urls = extract_urls_from_css(style_content)
        for item_url in css_urls:
            item_url_cleaned = item_url.replace('\\', '/').strip()
            if is_local_resource(item_url_cleaned, base_url): # base_url for style attrs is HTML page's URL
                full_url = urljoin(base_url, item_url_cleaned)
                if is_valid_url(full_url, base_domain): resources.add(full_url)
                # else: _logger.debug(f"Skipping invalid local URL from style attribute: {full_url}") # Removed
    
    # URLs embedded in JavaScript strings (basic regex, might have false positives/negatives)
    for script_tag in soup.find_all('script'):
        if script_tag.string:
            # This regex is very broad, use with caution or refine it
            # It looks for strings that look like paths ending with common extensions
            js_like_urls = re.findall(
                r"""['"`]([^'"\s`]+?\.(?:js|json|css|png|jpg|jpeg|gif|webp|svg|mp3|ogg|wav|mp4|webm|ttf|woff|woff2)(?:\?[^'"\s`]*)?)['"`]""",
                script_tag.string, re.IGNORECASE
            )
            for js_url in js_like_urls:
                js_url_cleaned = js_url.replace('\\', '/').strip()
                if is_local_resource(js_url_cleaned, base_url):
                    full_url = urljoin(base_url, js_url_cleaned)
                    if is_valid_url(full_url, base_domain): resources.add(full_url)
                    # else: _logger.debug(f"Skipping invalid local JS-like URL from inline script: {full_url}") # Removed
    return resources


def parse_css_for_resources(css_content: str, base_css_url: str, base_domain: str) -> set[str]:
    """Parses CSS content for local resources, relative to the CSS file's URL."""
    resources = set()
    urls_from_css = extract_urls_from_css(css_content)
    for item_url in urls_from_css:
        item_url_cleaned = item_url.replace('\\', '/').strip()
        if is_local_resource(item_url_cleaned, base_css_url):
            full_url = urljoin(base_css_url, item_url_cleaned) # Resolve relative to the CSS file's URL
            if is_valid_url(full_url, base_domain):
                resources.add(full_url)
                # _logger.debug(f"CSS parser found local resource: {full_url} (base CSS: {base_css_url})") # Removed
            # else: # Removed
                # _logger.debug(f"Skipping invalid local URL from CSS ({base_css_url}): {full_url}") # Removed
    return resources

# --- project.json Image Processing ---
def _recursive_process_json_images(
    data_node: any, game_base_url: str, game_save_path: Path, session: requests.Session,
    metadata_path: Path, embed_external_images: bool, base_domain_of_game: str,
    progress_callback: Optional[Callable[[str, str], None]] = None
):
    """
    Recursively traverses JSON, finds image URLs, and processes external URLs.
    Modifies data_node "in place".
    """
    image_keys = ['image', 'icon', 'background', 'thumbnail', 'pic', 'img', 'sprite', 'asset', 'source', 'url', 'cover']
    image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.tiff', '.avif', '.ico']

    if isinstance(data_node, dict):
        for key, value in list(data_node.items()): # Use list() for safe modification
            if isinstance(value, str) and key.lower() in image_keys:
                current_value_str = value.strip()
                # _logger.debug(f"JSON Img Proc - Key: '{key}', Value: '{current_value_str[:70]}...'") # Removed

                if not current_value_str or current_value_str.startswith('data:') or current_value_str in ["./", "/"]:
                    # _logger.debug(f"Skipping JSON value: '{current_value_str}' (empty, data URI, or root-like).") # Removed
                    continue

                is_external = not is_local_resource(current_value_str, game_base_url)

                if is_external:
                    # _logger.info(f"External URL found in JSON - Key: '{key}', Value: '{current_value_str}'. Processing...") # Removed
                    # Construct full URL if current_value_str is protocol-relative (e.g., //example.com/img.png)
                    full_external_url = urljoin(game_base_url, current_value_str) if not urlparse(current_value_str).scheme else current_value_str

                    # Confirm it's an image before proceeding
                    is_confirmed_image = any(urlparse(full_external_url).path.lower().endswith(ext) for ext in image_extensions)
                    if not is_confirmed_image:
                        # _logger.debug(f"URL '{full_external_url}' lacks image extension. Checking Content-Type...") # Removed
                        try:
                            img_check_headers = get_headers_for_url(full_external_url) # Use specific headers
                            head_resp = session.head(full_external_url, timeout=10, allow_redirects=True, headers=img_check_headers)
                            head_resp.raise_for_status()
                            content_type = head_resp.headers.get('Content-Type', '').lower()
                            if content_type.startswith('image/'):
                                is_confirmed_image = True
                                # _logger.info(f"URL '{full_external_url}' confirmed as image by Content-Type: {content_type}.") # Removed
                            else:
                                # _logger.info(f"URL '{full_external_url}' NOT an image (Content-Type: {content_type}). Skipping.") # Removed
                                continue
                        except requests.RequestException as e:
                            # _logger.warning(f"HEAD for Content-Type check failed for '{full_external_url}': {e}. Skipping unless key is very specific.") # Removed
                            if key.lower() not in ['image', 'icon', 'background', 'thumbnail', 'pic', 'img', 'sprite', 'cover']:
                                continue # Skip if key is generic and HEAD failed
                            is_confirmed_image = True # Assume image for specific keys if HEAD fails

                    if not is_confirmed_image: continue # Skip if still not confirmed

                    if embed_external_images:
                        # _logger.debug(f"Attempting to embed external image: {full_external_url}") # Removed
                        try:
                            img_embed_headers = get_headers_for_url(full_external_url)
                            response = session.get(full_external_url, timeout=30, headers=img_embed_headers)
                            response.raise_for_status()
                            img_content = response.content
                            mime_type = response.headers.get('Content-Type', '').split(';')[0].strip()
                            if not mime_type or not mime_type.startswith('image/'):
                                guessed_mime, _ = mimetypes.guess_type(full_external_url)
                                mime_type = guessed_mime if guessed_mime and guessed_mime.startswith('image/') else 'application/octet-stream'
                            
                            base64_data = base64.b64encode(img_content).decode('utf-8')
                            data_node[key] = f'data:{mime_type};base64,{base64_data}'
                            # _logger.info(f"Embedded external image: {full_external_url[:70]}...") # Removed
                            if progress_callback: progress_callback("embedded_json_image", full_external_url)
                        except Exception as e:
                            # _logger.error(f"Failed to embed external image {full_external_url}: {e}") # Removed
                            if progress_callback: progress_callback("failed_embed_json_image", full_external_url)
                            # Leave original URL on failure
                    else: # Download and replace with local path
                        # _logger.debug(f"Attempting to download external image for JSON: {full_external_url}") # Removed
                        ext_img_dir = game_save_path / "downloaded_external_images"
                        ext_img_dir.mkdir(parents=True, exist_ok=True)
                        
                        original_fname_from_url = Path(urlparse(full_external_url).path).name
                        if not original_fname_from_url: # Generate a name if URL has no filename part
                            original_fname_from_url = "ext_img_" + base64.urlsafe_b64encode(full_external_url.encode()).decode().rstrip("=")[:10]

                        # Determine extension
                        img_ext = Path(original_fname_from_url).suffix.lower()
                        if not img_ext or img_ext not in image_extensions : # If no/invalid ext from URL, try MIME
                            try:
                                temp_head_hdrs = get_headers_for_url(full_external_url)
                                head_ext_resp = session.head(full_external_url, timeout=10, allow_redirects=True, headers=temp_head_hdrs)
                                head_ext_resp.raise_for_status()
                                ct_for_ext = head_ext_resp.headers.get('Content-Type', '').lower().split(';')[0].strip()
                                guessed_ext = mimetypes.guess_extension(ct_for_ext) if ct_for_ext else None
                                if guessed_ext and guessed_ext in image_extensions: img_ext = guessed_ext
                                else: img_ext = '.png' # Fallback extension
                            except Exception: img_ext = '.png' # Fallback on HEAD error

                        sanitized_base = sanitize_filename_component(Path(original_fname_from_url).stem)
                        counter = 0
                        local_img_fname = f"{sanitized_base}{img_ext}"
                        local_img_path_abs = ext_img_dir / local_img_fname
                        while local_img_path_abs.exists(): # Avoid overwriting
                            counter += 1
                            local_img_fname = f"{sanitized_base}_{counter}{img_ext}"
                            local_img_path_abs = ext_img_dir / local_img_fname
                        
                        # Pass the existing progress_callback to download_file
                        dl_success, _ = download_file(full_external_url, local_img_path_abs, session, base_domain_of_game, metadata_path, progress_callback=progress_callback)
                        if dl_success:
                            local_rel_path = f"downloaded_external_images/{local_img_fname}"
                            data_node[key] = local_rel_path.replace('\\', '/') # Ensure POSIX paths
                            # _logger.info(f"Downloaded external JSON image: {full_external_url[:70]}... to {local_rel_path}") # Removed
                        else:
                            pass
                            # _logger.error(f"Failed to download external JSON image: {full_external_url}") # Removed
                            # Leave original URL on failure

            elif isinstance(value, (dict, list)): # Recursive call for nested structures
                _recursive_process_json_images(value, game_base_url, game_save_path, session, metadata_path, embed_external_images, base_domain_of_game, progress_callback)
    
    elif isinstance(data_node, list):
        for item in data_node:
            if isinstance(item, (dict, list)): # If list item is a collection
                _recursive_process_json_images(item, game_base_url, game_save_path, session, metadata_path, embed_external_images, base_domain_of_game, progress_callback)


# --- Main Resource Handler (called by ThreadPoolExecutor) ---
def handle_resource(
    full_url: str, session: requests.Session, base_save_path: Path,
    base_url_of_game_path_part: str, base_domain_of_game: str, metadata_path: Path,
    progress_callback: Optional[Callable[[str, str], None]] = None
) -> Tuple[bool, bool]:
    """Handles downloading a single resource and its nested CSS resources."""
    parsed_url = urlparse(full_url)
    # Path of the resource relative to its domain (e.g., "game/assets/style.css")
    path_from_url_resource = parsed_url.path.lstrip('/')

    # Normalize base_url_of_game_path_part to ensure it's a directory path string
    # This part represents the "root directory" of the game on the server
    # e.g. if game is at http://site.com/mygame/index.html, this is "/mygame/"
    # e.g. if game is at http://site.com/index.html, this is "/"
    current_game_dir_on_server = base_url_of_game_path_part
    if not current_game_dir_on_server.endswith('/'):
        current_game_dir_on_server = str(Path(current_game_dir_on_server).parent) + '/'
    current_game_dir_on_server = current_game_dir_on_server.lstrip('/') # e.g., "mygame/" or "" if root

    # Determine the local save path relative to base_save_path
    if path_from_url_resource.startswith(current_game_dir_on_server) and current_game_dir_on_server:
        # Resource is inside or at the same level as the game's server directory
        # e.g., path_from_url = "mygame/css/style.css", current_game_dir_on_server = "mygame/"
        # relative_save_path = "css/style.css"
        relative_save_path_str = path_from_url_resource[len(current_game_dir_on_server):].lstrip('/')
    else:
        # Resource is outside (e.g. /common.js when game is /mygame/) or game is at root
        # e.g., path_from_url = "css/style.css", current_game_dir_on_server = ""
        # relative_save_path = "css/style.css"
        relative_save_path_str = path_from_url_resource
    
    if not relative_save_path_str: # Should not happen for valid resources other than root index
        # _logger.warning(f"Calculated empty relative_save_path for {full_url} (base_game_path: {current_game_dir_on_server}). Skipping.") # Removed
        if progress_callback: progress_callback("skipped_empty_path", full_url)
        return False, False

    file_path_to_save_abs = base_save_path / relative_save_path_str
    # _logger.debug(f"Resource {full_url[:70]}... maps to local path: '{file_path_to_save_abs}'") # Removed

    # Double check validity (should have been done before adding to queue)
    if not is_valid_url(full_url, base_domain_of_game):
        # _logger.warning(f"handle_resource: Invalid URL provided: {full_url}") # Removed
        if progress_callback: progress_callback("skipped_invalid_url", full_url)
        return False, False

    success, downloaded = download_file(full_url, file_path_to_save_abs, session, base_domain_of_game, metadata_path, progress_callback=progress_callback)

    if not success:
        return False, downloaded # Return immediately if the main download failed

    # If a CSS file was downloaded, parse it for more resources
    if file_path_to_save_abs.suffix.lower() == '.css' and file_path_to_save_abs.exists():
        # _logger.debug(f"CSS file downloaded: {file_path_to_save_abs.name}. Parsing for nested resources.") # Removed
        try:
            css_bytes = file_path_to_save_abs.read_bytes()
            css_text_content = css_bytes.decode(detect_encoding(css_bytes), errors='replace')
            
            # base_url for resources inside this CSS file is the URL of the CSS file itself
            nested_css_resources = parse_css_for_resources(css_text_content, full_url, base_domain_of_game)
            
            if nested_css_resources:
                # _logger.info(f"Found {len(nested_css_resources)} nested resources in CSS: {file_path_to_save_abs.name}") # Removed
                # These should be added back to a central queue ideally, or handled recursively with care
                # For now, handle them directly (can lead to deep recursion if not careful)
                nested_success_count = 0
                for css_res_url in nested_css_resources:
                    # The base_save_path and base_url_of_game_path_part remain the same as for the parent game
                    res_success, _ = handle_resource(
                        css_res_url, session, base_save_path,
                        base_url_of_game_path_part, base_domain_of_game, metadata_path,
                        progress_callback=progress_callback
                    )
                    if res_success: nested_success_count += 1
                # _logger.debug(f"Finished handling {nested_success_count}/{len(nested_css_resources)} nested resources from {file_path_to_save_abs.name}") # Removed
        except Exception as e:
            pass
            # _logger.error(f"Error parsing CSS file {file_path_to_save_abs.name} (from URL {full_url}): {e}", exc_info=True) # Removed
            # Don't mark the main CSS download as failed due to parsing error of its content

    return success, downloaded


# --- Main Download Orchestration Function ---
def start_project_download(
    initial_url: str,
    target_base_save_dir_str: str, # e.g., "downloaded_games"
    embed_external_images_in_json: bool = False,
    max_workers: int = 10,
    progress_callback: Optional[Callable[[str, dict], None]] = None
) -> Tuple[Optional[str], str]:
    """
    Main function to download a CYOA project.
    Returns (path_to_index_html_or_None, status_summary_message).
    """
    session = create_session()

    def _notify_progress(type: str, data: dict):
        if progress_callback:
            try:
                progress_callback(type, data)
            except Exception as e_cb:
                pass
                # _logger.error(f"Error in progress_callback ({type}, {data}): {e_cb}") # Removed

    _notify_progress("status", {"message": f"Starting download for: {initial_url}"})

    # Handle cyoa.cafe redirection/iframe
    cafe_iframe_url = get_iframe_url_from_cyoa_cafe(initial_url, session)
    actual_game_entry_url = cafe_iframe_url if cafe_iframe_url else initial_url
    # _logger.info(f"Effective game entry URL: {actual_game_entry_url}") # Removed
    _notify_progress("status", {"message": f"Effective game URL: {actual_game_entry_url[:80]}..."})
    
    # Determine game folder name and full save path
    parsed_entry_url = urlparse(actual_game_entry_url)
    path_segment_for_name = parsed_entry_url.path.replace('/', '_').strip('_')
    game_folder_name_base = f"{parsed_entry_url.netloc}_{path_segment_for_name}" if path_segment_for_name else parsed_entry_url.netloc
    game_folder_name_final = sanitize_filename_component(game_folder_name_base)
    
    game_specific_save_path = Path(target_base_save_dir_str) / game_folder_name_final
    game_specific_save_path.mkdir(parents=True, exist_ok=True)
    # _logger.info(f"Game will be saved to: {game_specific_save_path}") # Removed
    _notify_progress("status", {"message": f"Saving to: {game_specific_save_path}"})
    
    metadata_file_path = game_specific_save_path / 'metadata.json'
    game_domain = parsed_entry_url.netloc
    # This is the URL from which relative paths in HTML/CSS/JS will be resolved
    # It's typically the URL of the index.html page or its containing directory.
    base_url_for_link_resolution = actual_game_entry_url
    # This is the path part of the game's URL, used to structure saved files correctly.
    # E.g., if game is at http://site.com/mygame/index.html, this is "/mygame/index.html" or "/mygame/"
    game_path_on_server_for_saving = parsed_entry_url.path
    
    # Determine the name of the main HTML file
    index_file_name = "index.html" # Default
    if Path(parsed_entry_url.path).suffix.lower() in ['.html', '.htm']:
        index_file_name = Path(parsed_entry_url.path).name
    local_index_html_path = game_specific_save_path / index_file_name

    def _resource_progress_cb_adapter(type_str: str, url_str: str): # Adapts simple (type, url) to (type, {data})
        _notify_progress("progress_resource", {"type": type_str, "url": url_str})

    # Download the main HTML file
    _notify_progress("status", {"message": f"Downloading main page: {index_file_name}"})
    index_dl_success, index_was_downloaded = download_file(
        actual_game_entry_url, local_index_html_path, session, game_domain, metadata_file_path,
        progress_callback=_resource_progress_cb_adapter
    )

    # Initialize download statistics
    s_attempts, s_success_dl_or_utd, s_failed = 0, 0, 0

    if not index_dl_success:
        msg = f"Failed to download main HTML: {actual_game_entry_url}"
        # _logger.error(msg) # Removed
        s_failed +=1
        _notify_progress("error", {"message": msg})
        _notify_progress("finished", {"index_html_path": None, "summary_message": msg})
        return None, msg
    
    s_attempts += 1
    if index_was_downloaded or index_dl_success: s_success_dl_or_utd += 1
    
    resources_to_process_queue = set()

    # Parse main HTML for resources
    if local_index_html_path.exists():
        # _logger.info(f"Parsing main HTML: {local_index_html_path.name}") # Removed
        _notify_progress("status", {"message": f"Parsing {local_index_html_path.name}..."})
        try:
            html_bytes = local_index_html_path.read_bytes()
            html_text = html_bytes.decode(detect_encoding(html_bytes), errors='replace')
            html_found_resources = parse_html_for_resources(html_text, base_url_for_link_resolution, game_domain)
            resources_to_process_queue.update(html_found_resources)
            # _logger.info(f"Found {len(html_found_resources)} resources in main HTML.") # Removed
            _notify_progress("status", {"message": f"Found {len(html_found_resources)} resources in HTML."})
        except Exception as e_html_parse:
            # _logger.error(f"Error parsing main HTML content from {local_index_html_path}: {e_html_parse}", exc_info=True) # Removed
            _notify_progress("error", {"message": f"Error parsing HTML: {e_html_parse}"})

    # Handle project.json
    project_json_filename = 'project.json' # Common name
    project_json_server_url = urljoin(base_url_for_link_resolution, project_json_filename)
    project_json_local_path = game_specific_save_path / project_json_filename

    _notify_progress("status", {"message": "Checking for project.json..."})
    pj_dl_success, pj_was_downloaded = download_file(
        project_json_server_url, project_json_local_path, session, game_domain, metadata_file_path,
        progress_callback=_resource_progress_cb_adapter
    )

    if pj_dl_success:
        s_attempts += 1
        if pj_was_downloaded or pj_dl_success: s_success_dl_or_utd += 1
        # _logger.info(f"project.json downloaded/verified: {project_json_server_url}") # Removed
        _notify_progress("status", {"message": "Processing project.json..."})
        if project_json_local_path.exists():
            try:
                pj_text = project_json_local_path.read_text(encoding='utf-8') # Assume UTF-8 for JSON
                project_data_obj = json.loads(pj_text)

                # Process images within project.json (embed or download external)
                _recursive_process_json_images(
                    project_data_obj, base_url_for_link_resolution, game_specific_save_path,
                    session, metadata_file_path, embed_external_images_in_json, game_domain,
                    progress_callback=_resource_progress_cb_adapter
                )
                # Save potentially modified project.json
                project_json_local_path.write_text(json.dumps(project_data_obj, indent=2, ensure_ascii=False), encoding='utf-8')
                # _logger.info("Re-saved project.json after image processing.") # Removed

                # Enumerate resources from the (potentially modified) project.json
                json_found_resources_relative = list(enumerate_project_resources(project_data_obj))
                for rel_path_from_json in json_found_resources_relative:
                    # Convert relative path from JSON to full URL for downloading
                    full_url_from_json = urljoin(base_url_for_link_resolution, rel_path_from_json)
                    # Sanity check: is it still considered a local resource for this game?
                    if is_valid_url(full_url_from_json, game_domain) and \
                       is_local_resource(rel_path_from_json, base_url_for_link_resolution):
                        resources_to_process_queue.add(full_url_from_json)
                        # _logger.debug(f"Added resource from project.json to queue: {full_url_from_json} (from relative: {rel_path_from_json})") # Removed
                # _logger.info(f"Found {len(json_found_resources_relative)} resource paths in project.json.") # Removed
                _notify_progress("status", {"message": f"Found {len(json_found_resources_relative)} paths in project.json."})

            except json.JSONDecodeError as e_json:
                # _logger.error(f"Error decoding project.json from {project_json_server_url}: {e_json}") # Removed
                _notify_progress("error", {"message": f"Invalid project.json: {e_json}"})
            except Exception as e_pj_proc:
                # _logger.error(f"Error processing project.json from {project_json_server_url}: {e_pj_proc}", exc_info=True) # Removed
                _notify_progress("error", {"message": f"Error with project.json: {e_pj_proc}"})
    else:
        # _logger.warning(f"project.json not found or failed to download at {project_json_server_url}") # Removed
        _notify_progress("status", {"message": "project.json not found or failed."})


    # _logger.info(f"Total unique resources in queue for download/check: {len(resources_to_process_queue)}") # Removed
    _notify_progress("status", {"message": f"Downloading {len(resources_to_process_queue)} additional assets..."})
    
    # For overall progress reporting
    num_queued_resources = len(resources_to_process_queue)
    processed_queued_count = 0

    # Download all other found resources using a thread pool
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url_map = {
            executor.submit(
                handle_resource, res_url_to_dl, session, game_specific_save_path,
                game_path_on_server_for_saving, game_domain, metadata_file_path,
                progress_callback=_resource_progress_cb_adapter
            ): res_url_to_dl for res_url_to_dl in resources_to_process_queue
        }

        for future_task in as_completed(future_to_url_map):
            completed_url = future_to_url_map[future_task]
            s_attempts += 1
            processed_queued_count += 1
            try:
                res_dl_success, res_was_downloaded = future_task.result()
                if res_dl_success:
                    if res_was_downloaded or res_dl_success: s_success_dl_or_utd += 1
                else:
                    s_failed += 1
                    # _logger.warning(f"Failed to handle queued resource: {completed_url}") # Removed
                
                if num_queued_resources > 0: # Avoid division by zero if queue was empty
                    _notify_progress("progress_overall", {
                        "processed": processed_queued_count,
                        "total_expected": num_queued_resources,
                        "current_url_status_type": "success" if res_dl_success else "failure",
                        "current_url": completed_url
                    })
            except Exception as e_future:
                s_failed += 1
                # _logger.error(f"Exception processing queued resource {completed_url}: {e_future}", exc_info=True) # Removed
                if num_queued_resources > 0:
                     _notify_progress("progress_overall", {
                        "processed": processed_queued_count,
                        "total_expected": num_queued_resources,
                        "current_url_status_type": "exception",
                        "current_url": completed_url
                    })

    summary_final_msg = (f"Download finished. Attempts: {s_attempts}, "
                         f"Succeeded/Up-to-date: {s_success_dl_or_utd}, "
                         f"Failed: {s_failed}")
    # _logger.info(summary_final_msg) # Removed
    
    result_index_path_str = str(local_index_html_path) if local_index_html_path.exists() else None
    if not result_index_path_str and s_success_dl_or_utd == 0 : # If index.html failed and nothing else was good
        summary_final_msg = f"Critical failure: Main page and all resources failed. {summary_final_msg}"

    _notify_progress("finished", {"index_html_path": result_index_path_str, "summary_message": summary_final_msg})
    
    return result_index_path_str, summary_final_msg

# No if __name__ == "__main__": block needed, as this is a module