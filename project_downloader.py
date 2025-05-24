# project_downloader.py (Corrected and Complete with failure URL reporting)

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
metadata_lock = threading.Lock()

DOMAIN_HEADERS = {
    'imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
    'i.imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
}

# --- Helper Functions ---

def detect_encoding(content: bytes) -> str:
    """Detects the encoding of a byte string."""
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
            if not parsed_protocol_relative.netloc and not parsed_base.netloc:
                 return True
            return parsed_protocol_relative.netloc == parsed_base.netloc
        except ValueError:
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
                is_not_data_uri = not val_stripped.startswith('data:')
                parsed_val = urlparse(val_stripped)
                is_relative_or_protocol_relative_on_same_domain = not (parsed_val.scheme and parsed_val.netloc) or \
                                                                 val_stripped.startswith('//')

                if val_stripped and is_not_data_uri and is_relative_or_protocol_relative_on_same_domain:
                    path_obj = Path(val_stripped)
                    has_common_extension = path_obj.suffix.lower() in {
                        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico',
                        '.mp3', '.wav', '.ogg', '.m4a',
                        '.mp4', '.webm', '.ogv',
                        '.ttf', '.otf', '.woff', '.woff2',
                        '.css', '.js', '.json',
                        '.txt', '.xml', '.md'
                    }
                    starts_with_known_dir = any(val_stripped.startswith(f"{d}/") for d in known_resource_dirs)

                    if has_common_extension or starts_with_known_dir:
                        yield val_stripped
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
            return DOMAIN_HEADERS[domain]
        return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1"
                }
    except Exception:
        return {"User-Agent": "Mozilla/5.0", "Accept": "*/*"} # Minimal fallback

# Removed get_iframe_url_from_cyoa_cafe as it's moved to url_utils.py

def create_session() -> requests.Session:
    """Creates a requests session with retry strategy and default headers."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=50,
        pool_maxsize=50,
        pool_block=False
    )
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update(get_headers_for_url("http://example.com"))
    return session

def download_file(url: str, path: Path, session: requests.Session, base_domain: str,
                  metadata_path: Path, request_delay: float = 0.05,
                  progress_callback: Optional[Callable[[str, str], None]] = None) -> Tuple[bool, bool]:
    """Downloads a single file, with ETag checking. Returns (success, was_downloaded_or_modified)."""
    if url.startswith('data:'):
        if progress_callback: progress_callback("skipped_data_uri", url)
        return True, False

    if Path(urlparse(url).path).name.lower() == 'favicon.ico':
        if progress_callback: progress_callback("skipped_favicon", url)
        return True, False

    metadata = {}
    if metadata_path.exists():
        try:
            with metadata_path.open('r', encoding='utf-8') as f:
                metadata = json.load(f)
        except Exception:
            pass

    file_metadata = metadata.get(url, {})
    local_etag = file_metadata.get('ETag')
    request_specific_headers = get_headers_for_url(url)

    if path.exists() and local_etag:
        head_headers = request_specific_headers.copy()
        head_headers['If-None-Match'] = local_etag
        try:
            head_response = session.head(url, allow_redirects=True, timeout=10, headers=head_headers)
            if head_response.status_code == 304:
                if progress_callback: progress_callback("up-to-date", url)
                return True, False
            server_etag_from_head = head_response.headers.get('ETag')
            if server_etag_from_head and server_etag_from_head == local_etag:
                if progress_callback: progress_callback("up-to-date", url)
                return True, False
        except requests.RequestException:
            pass
        except Exception:
            pass

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with session.get(url, stream=True, timeout=30, headers=request_specific_headers) as response:
            response.raise_for_status()
            content_type = response.headers.get('Content-Type', '')
            server_etag_from_get = response.headers.get('ETag')

            is_text_file = (
                path.suffix.lower() in {'.html', '.htm', '.js', '.css', '.json', '.txt', '.xml', '.svg'} or
                'text' in content_type or 'javascript' in content_type or 'json' in content_type
            )

            if is_text_file:
                content_bytes = response.content
                encoding = detect_encoding(content_bytes)
                text_content = content_bytes.decode(encoding, errors='replace')
                path.write_text(text_content, encoding='utf-8')
            else:
                with path.open('wb') as f:
                    for chunk in response.iter_content(chunk_size=8192 * 4):
                        if chunk:
                            f.write(chunk)

            if server_etag_from_get:
                with metadata_lock:
                    if metadata_path.exists():
                        try:
                            with metadata_path.open('r', encoding='utf-8') as f_meta_read:
                                current_metadata_on_disk = json.load(f_meta_read)
                        except Exception: current_metadata_on_disk = {}
                    else:
                        current_metadata_on_disk = {}

                    current_metadata_on_disk[url] = {'ETag': server_etag_from_get}
                    metadata_path.parent.mkdir(parents=True, exist_ok=True)
                    with metadata_path.open('w', encoding='utf-8') as f_meta_write:
                        json.dump(current_metadata_on_disk, f_meta_write, indent=2)

            if progress_callback: progress_callback("downloaded", url)
            if request_delay > 0: sleep(request_delay)
            return True, True
    except requests.exceptions.RequestException:
        if progress_callback: progress_callback("failed", url)
        return False, False
    except Exception:
        if progress_callback: progress_callback("failed", url)
        return False, False


def parse_html_for_resources(html_content: str, base_url: str, base_domain: str) -> set[str]:
    """Parses HTML content for local resources (scripts, styles, images, etc.)."""
    soup = BeautifulSoup(html_content, 'html.parser')
    resources = set()
    tags_attrs = {
        'link': 'href', 'script': 'src', 'img': 'src',
        'video': 'src', 'audio': 'src', 'source': 'src',
        'iframe': 'src',
        'object': 'data',
        'embed': 'src',
        'image': 'xlink:href'
    }

    for tag_name, attr_name in tags_attrs.items():
        for tag in soup.find_all(tag_name, **{attr_name: True}):
            src_val = tag[attr_name]
            if isinstance(src_val, list):
                src_val = src_val[0]

            if src_val and isinstance(src_val, str):
                src_cleaned = src_val.replace('\\', '/').strip()
                if is_local_resource(src_cleaned, base_url):
                    full_url = urljoin(base_url, src_cleaned)
                    if is_valid_url(full_url, base_domain):
                        resources.add(full_url)

    for style_tag in soup.find_all('style'):
        if style_tag.string:
            css_urls = extract_urls_from_css(style_tag.string)
            for item_url in css_urls:
                item_url_cleaned = item_url.replace('\\', '/').strip()
                if is_local_resource(item_url_cleaned, base_url):
                    full_url = urljoin(base_url, item_url_cleaned)
                    if is_valid_url(full_url, base_domain): resources.add(full_url)

    for tag_with_style_attr in soup.find_all(style=True):
        style_content = tag_with_style_attr['style']
        css_urls = extract_urls_from_css(style_content)
        for item_url in css_urls:
            item_url_cleaned = item_url.replace('\\', '/').strip()
            if is_local_resource(item_url_cleaned, base_url):
                full_url = urljoin(base_url, item_url_cleaned)
                if is_valid_url(full_url, base_domain): resources.add(full_url)

    for script_tag in soup.find_all('script'):
        if script_tag.string:
            js_like_urls = re.findall(
                r"""['"`]([^'"\s`]+?\.(?:js|json|css|png|jpg|jpeg|gif|webp|svg|mp3|ogg|wav|mp4|webm|ttf|woff|woff2)(?:\?[^'"\s`]*)?)['"`]""",
                script_tag.string, re.IGNORECASE
            )
            for js_url in js_like_urls:
                js_url_cleaned = js_url.replace('\\', '/').strip()
                if is_local_resource(js_url_cleaned, base_url):
                    full_url = urljoin(base_url, js_url_cleaned)
                    if is_valid_url(full_url, base_domain): resources.add(full_url)
    return resources


def parse_css_for_resources(css_content: str, base_css_url: str, base_domain: str) -> set[str]:
    """Parses CSS content for local resources, relative to the CSS file's URL."""
    resources = set()
    urls_from_css = extract_urls_from_css(css_content)
    for item_url in urls_from_css:
        item_url_cleaned = item_url.replace('\\', '/').strip()
        if is_local_resource(item_url_cleaned, base_css_url):
            full_url = urljoin(base_css_url, item_url_cleaned)
            if is_valid_url(full_url, base_domain):
                resources.add(full_url)
    return resources

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
        for key, value in list(data_node.items()):
            if isinstance(value, str) and key.lower() in image_keys:
                current_value_str = value.strip()

                if not current_value_str or current_value_str.startswith('data:') or current_value_str in ["./", "/"]:
                    continue

                is_external = not is_local_resource(current_value_str, game_base_url)

                if is_external:
                    full_external_url = urljoin(game_base_url, current_value_str) if not urlparse(current_value_str).scheme else current_value_str

                    is_confirmed_image = any(urlparse(full_external_url).path.lower().endswith(ext) for ext in image_extensions)
                    if not is_confirmed_image:
                        try:
                            img_check_headers = get_headers_for_url(full_external_url)
                            head_resp = session.head(full_external_url, timeout=10, allow_redirects=True, headers=img_check_headers)
                            head_resp.raise_for_status()
                            content_type = head_resp.headers.get('Content-Type', '').lower()
                            if content_type.startswith('image/'):
                                is_confirmed_image = True
                            else:
                                continue
                        except requests.RequestException:
                            if key.lower() not in ['image', 'icon', 'background', 'thumbnail', 'pic', 'img', 'sprite', 'cover']:
                                continue
                            is_confirmed_image = True

                    if not is_confirmed_image: continue

                    if embed_external_images:
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
                            if progress_callback: progress_callback("embedded_json_image", full_external_url)
                        except Exception:
                            if progress_callback: progress_callback("failed_embed_json_image", full_external_url)
                    else:
                        ext_img_dir = game_save_path / "downloaded_external_images"
                        ext_img_dir.mkdir(parents=True, exist_ok=True)

                        original_fname_from_url = Path(urlparse(full_external_url).path).name
                        if not original_fname_from_url:
                            original_fname_from_url = "ext_img_" + base64.urlsafe_b64encode(full_external_url.encode()).decode().rstrip("=")[:10]

                        img_ext = Path(original_fname_from_url).suffix.lower()
                        if not img_ext or img_ext not in image_extensions :
                            try:
                                temp_head_hdrs = get_headers_for_url(full_external_url)
                                head_ext_resp = session.head(full_external_url, timeout=10, allow_redirects=True, headers=temp_head_hdrs)
                                head_ext_resp.raise_for_status()
                                ct_for_ext = head_ext_resp.headers.get('Content-Type', '').lower().split(';')[0].strip()
                                guessed_ext = mimetypes.guess_extension(ct_for_ext) if ct_for_ext else None
                                if guessed_ext and guessed_ext in image_extensions: img_ext = guessed_ext
                                else: img_ext = '.png'
                            except Exception: img_ext = '.png'

                        sanitized_base = sanitize_filename_component(Path(original_fname_from_url).stem)
                        counter = 0
                        local_img_fname = f"{sanitized_base}{img_ext}"
                        local_img_path_abs = ext_img_dir / local_img_fname
                        while local_img_path_abs.exists():
                            counter += 1
                            local_img_fname = f"{sanitized_base}_{counter}{img_ext}"
                            local_img_path_abs = ext_img_dir / local_img_fname

                        dl_success, _ = download_file(full_external_url, local_img_path_abs, session, base_domain_of_game, metadata_path, progress_callback=progress_callback)
                        if dl_success:
                            local_rel_path = f"downloaded_external_images/{local_img_fname}"
                            data_node[key] = local_rel_path.replace('\\', '/')

            elif isinstance(value, (dict, list)):
                _recursive_process_json_images(value, game_base_url, game_save_path, session, metadata_path, embed_external_images, base_domain_of_game, progress_callback)

    elif isinstance(data_node, list):
        for item in data_node:
            if isinstance(item, (dict, list)):
                _recursive_process_json_images(item, game_base_url, game_save_path, session, metadata_path, embed_external_images, base_domain_of_game, progress_callback)


def handle_resource(
    full_url: str, session: requests.Session, base_save_path: Path,
    base_url_of_game_path_part: str, base_domain_of_game: str, metadata_path: Path,
    progress_callback: Optional[Callable[[str, str], None]] = None
) -> Tuple[bool, bool]:
    """Handles downloading a single resource and its nested CSS resources."""
    parsed_url = urlparse(full_url)
    path_from_url_resource = parsed_url.path.lstrip('/')

    current_game_dir_on_server = base_url_of_game_path_part
    if not current_game_dir_on_server.endswith('/'):
        current_game_dir_on_server = str(Path(current_game_dir_on_server).parent) + '/'
    current_game_dir_on_server = current_game_dir_on_server.lstrip('/')

    if path_from_url_resource.startswith(current_game_dir_on_server) and current_game_dir_on_server:
        relative_save_path_str = path_from_url_resource[len(current_game_dir_on_server):].lstrip('/')
    else:
        relative_save_path_str = path_from_url_resource

    if not relative_save_path_str:
        if progress_callback: progress_callback("skipped_empty_path", full_url)
        return False, False

    file_path_to_save_abs = base_save_path / relative_save_path_str

    if not is_valid_url(full_url, base_domain_of_game):
        if progress_callback: progress_callback("skipped_invalid_url", full_url)
        return False, False

    success, downloaded = download_file(full_url, file_path_to_save_abs, session, base_domain_of_game, metadata_path, progress_callback=progress_callback)

    if not success:
        return False, downloaded

    if file_path_to_save_abs.suffix.lower() == '.css' and file_path_to_save_abs.exists():
        try:
            css_bytes = file_path_to_save_abs.read_bytes()
            css_text_content = css_bytes.decode(detect_encoding(css_bytes), errors='replace')

            nested_css_resources = parse_css_for_resources(css_text_content, full_url, base_domain_of_game)

            if nested_css_resources:
                nested_success_count = 0
                for css_res_url in nested_css_resources:
                    res_success, _ = handle_resource(
                        css_res_url, session, base_save_path,
                        base_url_of_game_path_part, base_domain_of_game, metadata_path,
                        progress_callback=progress_callback
                    )
                    if res_success: nested_success_count += 1
        except Exception:
            pass
            
    return success, downloaded


# --- Main Download Orchestration Function ---
def start_project_download(
    initial_url_for_downloader: str, # Renamed to avoid confusion with internal 'initial_url'
    target_base_save_dir_str: str,
    embed_external_images_in_json: bool = False,
    max_workers: int = 10,
    progress_callback: Optional[Callable[[str, dict], None]] = None
) -> Tuple[Optional[str], str]:
    """
    Main function to download a CYOA project.
    Returns (path_to_index_html_or_None, status_summary_message).
    """
    session = create_session()
    failed_urls = [] # MODIFIED: Initialize list to store failed URLs

    def _notify_progress(type_str: str, data: dict): # Changed type to type_str
        if progress_callback:
            try:
                progress_callback(type_str, data)
            except Exception:
                pass

    _notify_progress("status", {"message": f"Starting download for: {initial_url_for_downloader}"})

    # The initial_url_for_downloader is already pre-processed and resolved (if from catalog)
    # by the launcher before calling this function.
    actual_game_entry_url = initial_url_for_downloader
    
    _notify_progress("status", {"message": f"Effective game URL: {actual_game_entry_url[:80]}..."})

    parsed_entry_url = urlparse(actual_game_entry_url)
    path_segment_for_name = parsed_entry_url.path.replace('/', '_').strip('_')
    game_folder_name_base = f"{parsed_entry_url.netloc}_{path_segment_for_name}" if path_segment_for_name else parsed_entry_url.netloc
    game_folder_name_final = sanitize_filename_component(game_folder_name_base)

    game_specific_save_path = Path(target_base_save_dir_str) / game_folder_name_final
    game_specific_save_path.mkdir(parents=True, exist_ok=True)
    _notify_progress("status", {"message": f"Saving to: {game_specific_save_path}"})

    metadata_file_path = game_specific_save_path / 'metadata.json'
    game_domain = parsed_entry_url.netloc
    base_url_for_link_resolution = actual_game_entry_url
    game_path_on_server_for_saving = parsed_entry_url.path

    index_file_name = "index.html"
    if Path(parsed_entry_url.path).suffix.lower() in ['.html', '.htm']:
        # Ensure we don't take "index.html" from "/game/ID/index.html" if ID is like "foo.html"
        # The actual file name is the last part of the path.
        path_name = Path(parsed_entry_url.path).name
        if path_name: # If path is just "/" or "/game/", name would be empty
             index_file_name = path_name

    local_index_html_path = game_specific_save_path / index_file_name


    def _resource_progress_cb_adapter(type_str_cb: str, url_str_cb: str): # Changed type to type_str_cb, url to url_str_cb
        _notify_progress("progress_resource", {"type": type_str_cb, "url": url_str_cb})

    # Initialize download statistics
    s_attempts, s_success_dl_or_utd, s_failed = 0, 0, 0

    _notify_progress("status", {"message": f"Downloading main page: {index_file_name}"})
    index_dl_success, index_was_downloaded = download_file(
        actual_game_entry_url, local_index_html_path, session, game_domain, metadata_file_path,
        progress_callback=_resource_progress_cb_adapter
    )
    s_attempts += 1 # Main page is an attempt

    if not index_dl_success:
        s_failed +=1
        msg = f"Failed to download main HTML: {actual_game_entry_url}" # MODIFIED: Use actual URL in message
        _notify_progress("error", {"message": msg})
        _notify_progress("finished", {"index_html_path": None, "summary_message": msg})
        return None, msg

    if index_was_downloaded or index_dl_success : s_success_dl_or_utd += 1

    resources_to_process_queue = set()

    if local_index_html_path.exists():
        _notify_progress("status", {"message": f"Parsing {local_index_html_path.name}..."})
        try:
            html_bytes = local_index_html_path.read_bytes()
            html_text = html_bytes.decode(detect_encoding(html_bytes), errors='replace')
            html_found_resources = parse_html_for_resources(html_text, base_url_for_link_resolution, game_domain)
            resources_to_process_queue.update(html_found_resources)
            _notify_progress("status", {"message": f"Found {len(html_found_resources)} resources in HTML."})
        except Exception as e_html_parse:
            _notify_progress("error", {"message": f"Error parsing HTML: {e_html_parse}"})

    project_json_filename = 'project.json'
    project_json_server_url = urljoin(base_url_for_link_resolution, project_json_filename)
    project_json_local_path = game_specific_save_path / project_json_filename

    _notify_progress("status", {"message": "Checking for project.json..."})

    s_attempts += 1 # Attempting to download project.json
    pj_dl_success, pj_was_downloaded = download_file(
        project_json_server_url, project_json_local_path, session, game_domain, metadata_file_path,
        progress_callback=_resource_progress_cb_adapter
    )

    if pj_dl_success:
        if pj_was_downloaded or pj_dl_success: s_success_dl_or_utd += 1
        _notify_progress("status", {"message": "Processing project.json..."})
        if project_json_local_path.exists():
            try:
                pj_text = project_json_local_path.read_text(encoding='utf-8')
                project_data_obj = json.loads(pj_text)

                _recursive_process_json_images(
                    project_data_obj, base_url_for_link_resolution, game_specific_save_path,
                    session, metadata_file_path, embed_external_images_in_json, game_domain,
                    progress_callback=_resource_progress_cb_adapter
                )
                project_json_local_path.write_text(json.dumps(project_data_obj, indent=2, ensure_ascii=False), encoding='utf-8')

                json_found_resources_relative = list(enumerate_project_resources(project_data_obj))
                for rel_path_from_json in json_found_resources_relative:
                    full_url_from_json = urljoin(base_url_for_link_resolution, rel_path_from_json)
                    if is_valid_url(full_url_from_json, game_domain) and \
                       is_local_resource(rel_path_from_json, base_url_for_link_resolution):
                        resources_to_process_queue.add(full_url_from_json)
                _notify_progress("status", {"message": f"Found {len(json_found_resources_relative)} paths in project.json."})

            except json.JSONDecodeError as e_json:
                _notify_progress("error", {"message": f"Invalid project.json: {e_json}"})
            except Exception as e_pj_proc:
                _notify_progress("error", {"message": f"Error with project.json: {e_pj_proc}"})
    else: # project.json download failed
        s_failed += 1
        failed_urls.append(project_json_server_url) # MODIFIED: Add to failed_urls list
        _notify_progress("status", {"message": f"project.json not found or download failed: {project_json_server_url}"}) # MODIFIED: Enhanced status message


    _notify_progress("status", {"message": f"Downloading {len(resources_to_process_queue)} additional assets..."})

    num_queued_resources = len(resources_to_process_queue)
    processed_queued_count = 0

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
                res_dl_success, res_was_downloaded_task = future_task.result() # Renamed res_was_downloaded
                if res_dl_success:
                    if res_was_downloaded_task or res_dl_success: s_success_dl_or_utd += 1
                else:
                    s_failed += 1
                    failed_urls.append(completed_url)

                if num_queued_resources > 0:
                    _notify_progress("progress_overall", {
                        "processed": processed_queued_count,
                        "total_expected": num_queued_resources,
                        "current_url_status_type": "success" if res_dl_success else "failure",
                        "current_url": completed_url
                    })
            except Exception:
                s_failed += 1
                failed_urls.append(completed_url)
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

    if s_failed > 0 and failed_urls:
        failed_urls_display = []
        for i, url_item in enumerate(failed_urls):
            if i < 5: # Show up to 5 failed URLs
                failed_urls_display.append(f"- {url_item}")
            else:
                failed_urls_display.append(f"...and {len(failed_urls) - 5} more failed URL(s).")
                break
        summary_final_msg += "\n\nFailed URL(s):\n" + "\n".join(failed_urls_display)

    result_index_path_str = str(local_index_html_path) if local_index_html_path.exists() else None

    if not result_index_path_str and s_success_dl_or_utd == 0 and s_attempts > 1 :
        critical_failure_msg_prefix = "Critical failure: Main page may be invalid or missing, and other resources failed."
        if s_failed > 0 and failed_urls:
             summary_final_msg = f"{critical_failure_msg_prefix}\n{summary_final_msg}"
        else:
             summary_final_msg = f"{critical_failure_msg_prefix} Overall status: {summary_final_msg}"

    _notify_progress("finished", {"index_html_path": result_index_path_str, "summary_message": summary_final_msg})

    return result_index_path_str, summary_final_msg