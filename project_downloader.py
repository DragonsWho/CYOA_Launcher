# project_downloader.py

import os
import re
import json
import sys 
from urllib.parse import urljoin, urlparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
# from time import sleep # Removed 'time' as it was unused
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
from typing import Optional, List, Tuple, Callable, Dict, Any, Set 

# --- Global variables and settings ---
metadata_lock = threading.Lock() # Used for main_metadata_object modifications and file I/O

DOMAIN_HEADERS = {
    'imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
    'i.imgur.com': {"user-agent": "curl/8.1.1", "accept": "*/*"},
}

REGEX_XHR_JSON = re.compile(
    r"""\.open\s*\(\s*["']GET["']\s*,\s*["']([^"']+\.json(?:\?[^"']*)?)["']"""
)
REGEX_FETCH_JSON = re.compile(
    r"""fetch\s*\(\s*["']([^"']+\.json(?:\?[^"']*)?)["']"""
)

game_domain: Optional[str] = None

# --- Helper Functions ---

def detect_encoding(content: bytes) -> str:
    result = chardet.detect(content)
    return result['encoding'] if result['encoding'] else 'utf-8'

@lru_cache(maxsize=1000)
def is_valid_url(url: str, base_domain_check: Optional[str] = None) -> bool:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return True if not base_domain_check else False
    if parsed.scheme not in {'http', 'https'}:
        return False
    if base_domain_check:
        return parsed.netloc == base_domain_check
    return True


def extract_urls_from_css(css_content: str) -> List[str]:
    urls = re.findall(r'url\((?:\'|"|)(.*?)(?:\'|"|)\)', css_content)
    return urls

def is_local_resource(src: str, base_url: str) -> bool:
    src_stripped = src.strip()
    if src_stripped.startswith('data:'):
        return False
    if not src_stripped: 
        return True

    parsed_src = urlparse(src_stripped)
    parsed_base = urlparse(base_url)

    if parsed_src.scheme and parsed_src.netloc:
        return parsed_src.netloc == parsed_base.netloc

    if src_stripped.startswith('//'):
        scheme_to_use = parsed_base.scheme if parsed_base.scheme else 'http'
        try:
            temp_abs_url = f"{scheme_to_use}:{src_stripped}" 
            parsed_protocol_relative = urlparse(temp_abs_url)
            if not parsed_protocol_relative.netloc:
                 return False
            return parsed_protocol_relative.netloc == parsed_base.netloc
        except ValueError:
            return False 

    return True

def sanitize_filename_component(name_part: str) -> str:
    name_part = unquote(name_part) 
    name_part = re.sub(r'[<>:"/\\|?*\s]', '_', name_part) 
    name_part = re.sub(r'_+', '_', name_part) 
    name_part = name_part.strip('_') 
    return name_part[:200] 

def enumerate_project_resources(data: Any,
                                known_resource_dirs: Optional[List[str]] = None) -> List[str]:
    found_paths: List[str] = [] 
    if known_resource_dirs is None:
        known_resource_dirs = ['images', 'img', 'music', 'audio', 'sounds', 'videos', 'fonts', 'css', 'js', 'assets', 'data', 'downloaded_external_images']

    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                val_stripped = value.strip()
                is_not_data_uri = not val_stripped.startswith('data:')
                parsed_val = urlparse(val_stripped)
                is_potentially_local = not (parsed_val.scheme and parsed_val.netloc) or \
                                     val_stripped.startswith('//')

                if val_stripped and is_not_data_uri and is_potentially_local:
                    path_obj = Path(unquote(parsed_val.path))
                    has_common_extension = path_obj.suffix.lower() in {
                        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.ico',
                        '.mp3', '.wav', '.ogg', '.m4a',
                        '.mp4', '.webm', '.ogv',
                        '.ttf', '.otf', '.woff', '.woff2',
                        '.css', '.js', '.json',
                        '.txt', '.xml', '.md'
                    }
                    starts_with_known_dir = any(unquote(val_stripped).startswith(f"{d}/") for d in known_resource_dirs)

                    if has_common_extension or starts_with_known_dir:
                        found_paths.append(val_stripped) 
            elif isinstance(value, (dict, list)):
                found_paths.extend(enumerate_project_resources(value, known_resource_dirs)) 
    elif isinstance(data, list):
        for item in data:
            found_paths.extend(enumerate_project_resources(item, known_resource_dirs)) 
    return found_paths


def get_headers_for_url(url: str) -> dict:
    try:
        parsed_url = urlparse(url)
        domain_from_url = parsed_url.hostname 
        if domain_from_url and domain_from_url in DOMAIN_HEADERS: 
            return DOMAIN_HEADERS[domain_from_url]
        return {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8", 
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "image", 
            "Sec-Fetch-Mode": "no-cors", 
            "Sec-Fetch-Site": "same-origin", 
        }
    except Exception:
        return {"User-Agent": "Mozilla/5.0", "Accept": "*/*"} 


def create_session() -> requests.Session:
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
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1"
    })
    return session

def download_file(url: str, path: Path, session: requests.Session, 
                  all_project_metadata: Dict[str, Any], 
                  progress_callback: Optional[Callable[[str, str], None]] = None) -> Tuple[bool, bool]:
    """Downloads a single file, with ETag checking. Updates ETags in all_project_metadata."""
    if url.startswith('data:'):
        if progress_callback: progress_callback("skipped_data_uri", url)
        return True, False

    if Path(urlparse(url).path).name.lower() == 'favicon.ico':
        if progress_callback: progress_callback("skipped_favicon", url)
        return True, False

    etags_map = all_project_metadata.setdefault('ETags', {})
    file_etag_data = etags_map.get(url, {})
    local_etag = file_etag_data.get('ETag')
    
    request_specific_headers = get_headers_for_url(url) 

    if path.exists() and local_etag:
        head_headers = request_specific_headers.copy()
        head_headers['If-None-Match'] = local_etag
        try:
            head_response = session.head(url, allow_redirects=True, timeout=10, headers=head_headers)
            if head_response.status_code == 304:
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
                    etags_map[url] = {'ETag': server_etag_from_get}

            if progress_callback: progress_callback("downloaded", url)
            return True, True
    except requests.exceptions.RequestException as e_req:
        if progress_callback: progress_callback("failed", f"{url} (RequestException: {type(e_req).__name__})")
        return False, False
    except Exception as e_other:
        if progress_callback: progress_callback("failed", f"{url} (Exception: {type(e_other).__name__})")
        return False, False

def find_json_links_in_js(js_content: str) -> List[str]:
    found_json_files = set()
    for match in REGEX_XHR_JSON.finditer(js_content):
        json_path = match.group(1).strip()
        if json_path: found_json_files.add(json_path)
    for match in REGEX_FETCH_JSON.finditer(js_content):
        json_path = match.group(1).strip()
        if json_path: found_json_files.add(json_path)
    return list(found_json_files)

def parse_html_for_resources(html_content: str, base_url: str, base_domain_for_parse: str) -> Tuple[Set[str], List[str]]:
    soup = BeautifulSoup(html_content, 'html.parser')
    resources_urls: Set[str] = set() 
    inline_js_content_list: List[str] = [] 
    tags_attrs = {
        'link': 'href', 'script': 'src', 'img': 'src',
        'video': 'src', 'audio': 'src', 'source': 'src',
        'iframe': 'src', 'object': 'data', 'embed': 'src',
        'image': 'xlink:href'
    }
    for tag_name, attr_name in tags_attrs.items():
        for tag in soup.find_all(tag_name):
            src_val = tag.get(attr_name)
            if isinstance(src_val, list): src_val = src_val[0] if src_val else None
            if src_val and isinstance(src_val, str):
                src_cleaned = src_val.replace('\\', '/').strip()
                if is_local_resource(src_cleaned, base_url):
                    full_url = urljoin(base_url, src_cleaned)
                    if is_valid_url(full_url, base_domain_check=base_domain_for_parse):
                        resources_urls.add(full_url)
    for style_tag in soup.find_all('style'):
        if style_tag.string:
            css_urls_relative = extract_urls_from_css(style_tag.string)
            for item_url_rel in css_urls_relative:
                item_url_cleaned = item_url_rel.replace('\\', '/').strip()
                if is_local_resource(item_url_cleaned, base_url):
                    full_url = urljoin(base_url, item_url_cleaned)
                    if is_valid_url(full_url, base_domain_check=base_domain_for_parse):
                        resources_urls.add(full_url)
    for tag_with_style_attr in soup.find_all(style=True):
        style_content = tag_with_style_attr['style']
        css_urls_relative = extract_urls_from_css(style_content)
        for item_url_rel in css_urls_relative:
            item_url_cleaned = item_url_rel.replace('\\', '/').strip()
            if is_local_resource(item_url_cleaned, base_url):
                full_url = urljoin(base_url, item_url_cleaned)
                if is_valid_url(full_url, base_domain_check=base_domain_for_parse):
                    resources_urls.add(full_url)
    for script_tag in soup.find_all('script'):
        if script_tag.string: 
            inline_js_content_list.append(script_tag.string)
    return resources_urls, inline_js_content_list

def parse_css_for_resources(css_content: str, base_css_url: str, base_domain_for_parse: str) -> Set[str]:
    resources: Set[str] = set() 
    urls_from_css_relative = extract_urls_from_css(css_content)
    for item_url_rel in urls_from_css_relative:
        item_url_cleaned = item_url_rel.replace('\\', '/').strip()
        if is_local_resource(item_url_cleaned, base_css_url):
            full_url = urljoin(base_css_url, item_url_cleaned)
            if is_valid_url(full_url, base_domain_check=base_domain_for_parse):
                resources.add(full_url)
    return resources

def _recursive_process_json_images(
    data_node: Any, game_base_url: str, game_save_path: Path, session: requests.Session,
    all_project_metadata: Dict[str, Any], 
    embed_external_images: bool, 
    progress_callback: Optional[Callable[[str, str], None]] = None
) -> List[Tuple[str, str]]: 
    image_keys = ['image', 'icon', 'background', 'thumbnail', 'pic', 'img', 'sprite', 'asset', 'source', 'url', 'cover', 'bg', 'picture']
    image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp', '.tiff', '.avif', '.ico']
    failed_external_image_downloads: List[Tuple[str, str]] = []
    
    external_mappings_ref = all_project_metadata.setdefault('external_mappings', {})

    if isinstance(data_node, dict):
        for key, value in list(data_node.items()): 
            if isinstance(value, str):
                original_json_string = value.strip() 
                if not original_json_string or original_json_string.startswith('data:') or original_json_string in ["./", "/"]:
                    continue

                is_likely_image_field = key.lower() in image_keys or \
                                        any(urlparse(original_json_string).path.lower().endswith(ext) for ext in image_extensions)
                
                is_truly_external_url_syntax = bool(urlparse(original_json_string).scheme in ['http', 'https']) and \
                                               not is_local_resource(original_json_string, game_base_url)


                if is_likely_image_field and is_truly_external_url_syntax:
                    full_external_url_to_download = urljoin(game_base_url, original_json_string) if not urlparse(original_json_string).scheme else original_json_string
                    
                    is_confirmed_image = any(urlparse(full_external_url_to_download).path.lower().endswith(ext) for ext in image_extensions)
                    if not is_confirmed_image:
                        try:
                            img_check_headers = get_headers_for_url(full_external_url_to_download)
                            img_check_headers["Sec-Fetch-Dest"] = "image"
                            head_resp = session.head(full_external_url_to_download, timeout=5, allow_redirects=True, headers=img_check_headers)
                            head_resp.raise_for_status()
                            content_type = head_resp.headers.get('Content-Type', '').lower()
                            is_confirmed_image = content_type.startswith('image/')
                        except Exception: 
                            is_confirmed_image = key.lower() in image_keys 
                        if not is_confirmed_image: continue


                    if embed_external_images:
                        try:
                            img_embed_headers = get_headers_for_url(full_external_url_to_download)
                            img_embed_headers["Sec-Fetch-Dest"] = "image"
                            response = session.get(full_external_url_to_download, timeout=20, headers=img_embed_headers)
                            response.raise_for_status()
                            img_content = response.content
                            mime_type = response.headers.get('Content-Type', '').split(';')[0].strip()
                            if not mime_type or not mime_type.startswith('image/'):
                                guessed_mime, _ = mimetypes.guess_type(full_external_url_to_download)
                                mime_type = guessed_mime if guessed_mime and guessed_mime.startswith('image/') else 'application/octet-stream'
                            base64_data = base64.b64encode(img_content).decode('utf-8')
                            data_node[key] = f'data:{mime_type};base64,{base64_data}'
                            if progress_callback: progress_callback("embedded_json_image", full_external_url_to_download)
                        except Exception as e_embed:
                            if progress_callback: progress_callback("failed_embed_json_image", f"{full_external_url_to_download} (Original: '{original_json_string}', Error: {type(e_embed).__name__})")
                            failed_external_image_downloads.append((full_external_url_to_download, original_json_string))
                    else: 
                        ext_img_dir = game_save_path / "downloaded_external_images"
                        ext_img_dir.mkdir(parents=True, exist_ok=True)
                        original_fname_from_url = Path(unquote(urlparse(full_external_url_to_download).path)).name
                        if not original_fname_from_url: 
                            original_fname_from_url = "ext_img_" + base64.urlsafe_b64encode(full_external_url_to_download.encode()).decode().rstrip("=")[:16]
                        img_ext = Path(original_fname_from_url).suffix.lower()
                        if not img_ext or img_ext not in image_extensions: 
                            try:
                                temp_head_hdrs = get_headers_for_url(full_external_url_to_download)
                                temp_head_hdrs["Sec-Fetch-Dest"] = "image"
                                head_ext_resp = session.head(full_external_url_to_download, timeout=5, allow_redirects=True, headers=temp_head_hdrs)
                                head_ext_resp.raise_for_status()
                                ct_for_ext = head_ext_resp.headers.get('Content-Type', '').lower().split(';')[0].strip()
                                guessed_ext = mimetypes.guess_extension(ct_for_ext, strict=False) if ct_for_ext else None
                                img_ext = guessed_ext if guessed_ext and guessed_ext in image_extensions else '.png'
                            except Exception: img_ext = '.png'
                        sanitized_base = sanitize_filename_component(Path(original_fname_from_url).stem)
                        counter = 0
                        local_img_fname = f"{sanitized_base}{img_ext}"
                        local_img_path_abs = ext_img_dir / local_img_fname
                        while local_img_path_abs.exists(): 
                            counter += 1
                            local_img_fname = f"{sanitized_base}_{counter}{img_ext}"
                            local_img_path_abs = ext_img_dir / local_img_fname
                        
                        dl_success, _ = download_file(full_external_url_to_download, local_img_path_abs, session, all_project_metadata, progress_callback=progress_callback)
                        if dl_success:
                            local_rel_path = f"downloaded_external_images/{local_img_fname}"
                            data_node[key] = local_rel_path.replace('\\', '/') 
                            with metadata_lock: 
                                external_mappings_ref[local_rel_path] = original_json_string 
                        else:
                            if progress_callback: progress_callback("failed_dl_ext_json_image", f"{full_external_url_to_download} (Original: '{original_json_string}')")
                            failed_external_image_downloads.append((full_external_url_to_download, original_json_string))
                elif isinstance(value, (dict, list)): 
                    nested_failures = _recursive_process_json_images(value, game_base_url, game_save_path, session, all_project_metadata, embed_external_images, progress_callback)
                    failed_external_image_downloads.extend(nested_failures)

            elif isinstance(value, (dict, list)): 
                nested_failures = _recursive_process_json_images(value, game_base_url, game_save_path, session, all_project_metadata, embed_external_images, progress_callback)
                failed_external_image_downloads.extend(nested_failures)

    elif isinstance(data_node, list):
        for item in data_node: 
            if isinstance(item, (dict, list)):
                nested_failures = _recursive_process_json_images(item, game_base_url, game_save_path, session, all_project_metadata, embed_external_images, progress_callback)
                failed_external_image_downloads.extend(nested_failures)
    return failed_external_image_downloads


def handle_resource(
    full_url: str, session: requests.Session, base_save_path: Path,
    base_url_of_game_html_path_part: str,
    base_domain_of_game_res: str, 
    all_project_metadata: Dict[str, Any], 
    progress_callback: Optional[Callable[[str, str], None]] = None
) -> Tuple[bool, bool]:
    parsed_url = urlparse(full_url)
    path_from_url_resource = parsed_url.path.lstrip('/') if parsed_url.path else ""
    server_game_dir_path_obj = Path(base_url_of_game_html_path_part).parent
    server_game_dir = str(server_game_dir_path_obj).replace("\\", "/").lstrip('/')
    if server_game_dir and not server_game_dir.endswith('/'): server_game_dir += '/'
    if server_game_dir == "./" or server_game_dir == ".": server_game_dir = "" 
    relative_save_path_str: str
    if path_from_url_resource.startswith(server_game_dir) and server_game_dir:
        relative_save_path_str = path_from_url_resource[len(server_game_dir):].lstrip('/')
    else:
        relative_save_path_str = path_from_url_resource
    if not relative_save_path_str:
        relative_save_path_str = Path(unquote(parsed_url.path)).name if Path(unquote(parsed_url.path)).name else "downloaded_root_resource"
        if progress_callback: progress_callback("empty_path_fallback_name", f"{full_url} -> {relative_save_path_str}")
    file_path_to_save_abs = base_save_path / relative_save_path_str
    if not is_valid_url(full_url, base_domain_check=base_domain_of_game_res):
        if progress_callback: progress_callback("skipped_invalid_or_external_url", full_url)
        return False, False

    success, downloaded = download_file(full_url, file_path_to_save_abs, session, all_project_metadata, progress_callback=progress_callback)

    if not success:
        return False, downloaded
    if file_path_to_save_abs.suffix.lower() == '.css' and file_path_to_save_abs.exists():
        try:
            css_bytes = file_path_to_save_abs.read_bytes()
            css_text_content = css_bytes.decode(detect_encoding(css_bytes), errors='replace')
            nested_css_resources = parse_css_for_resources(css_text_content, full_url, base_domain_of_game_res)
            if nested_css_resources:
                for css_res_url in nested_css_resources:
                    handle_resource( 
                        css_res_url, session, base_save_path,
                        base_url_of_game_html_path_part, base_domain_of_game_res, 
                        all_project_metadata, 
                        progress_callback=progress_callback
                    )
        except Exception as e_css_parse:
            if progress_callback: progress_callback("css_parse_error", f"{full_url} ({type(e_css_parse).__name__})")
    return success, downloaded

# --- Main Download Orchestration Function --- 
def start_project_download(
    initial_url_for_downloader: str,
    target_base_save_dir_str: str,
    embed_external_images_in_json: bool = False,
    max_workers: int = 10,
    progress_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
) -> Tuple[Optional[str], str]:
    
    global game_domain 
    session = create_session()
    failed_url_details: Dict[str, str] = {} 

    def _notify_progress(type_str: str, data: Dict[str, Any]):
        if progress_callback:
            try: progress_callback(type_str, data)
            except Exception as e_prog: print(f"Error in progress_callback {type_str}: {e_prog}", file=sys.stderr)

    _notify_progress("status", {"message": f"Starting download for: {initial_url_for_downloader}"})
    actual_game_entry_url = initial_url_for_downloader
    _notify_progress("status", {"message": f"Effective game URL: {actual_game_entry_url[:80]}..."})
    parsed_entry_url = urlparse(actual_game_entry_url)
    game_domain = parsed_entry_url.netloc
    domain_part = parsed_entry_url.netloc
    path_part = parsed_entry_url.path.strip('/')
    sanitized_path_part = ""
    if path_part:
        path_part_underscored = path_part.replace('/', '_')
        sanitized_path_part = sanitize_filename_component(path_part_underscored)
        sanitized_path_part = re.sub(r'_+', '_', sanitized_path_part).strip('_')
    game_folder_name_base = f"{sanitize_filename_component(domain_part)}_{sanitized_path_part}" if sanitized_path_part else sanitize_filename_component(domain_part)
    game_folder_name_final = re.sub(r'_+', '_', game_folder_name_base).strip('_')
    game_specific_save_path = Path(target_base_save_dir_str) / game_folder_name_final
    game_specific_save_path.mkdir(parents=True, exist_ok=True)
    _notify_progress("status", {"message": f"Saving to: {game_specific_save_path}"})

    metadata_file_path = game_specific_save_path / '.metadata.json'
    all_project_metadata: Dict[str, Any] = {} 
    try:
        with metadata_lock:
            if metadata_file_path.exists():
                all_project_metadata = json.loads(metadata_file_path.read_text(encoding='utf-8'))
    except Exception as e_meta_load:
        _notify_progress("warning", {"message": f"Could not load metadata file {metadata_file_path}: {e_meta_load}. Starting fresh."})
        all_project_metadata = {} 

    all_project_metadata.setdefault('ETags', {})
    all_project_metadata.setdefault('external_mappings', {})

    base_url_for_link_resolution = actual_game_entry_url
    game_html_path_on_server = parsed_entry_url.path if parsed_entry_url.path else "/"
    index_file_name_from_url = Path(unquote(parsed_entry_url.path)).name
    index_file_name = "index.html" 
    if index_file_name_from_url and not parsed_entry_url.path.endswith('/'):
        index_file_name = index_file_name_from_url
    local_index_html_path = game_specific_save_path / index_file_name

    def _resource_progress_cb_adapter(type_str_cb: str, url_str_cb: str):
        _notify_progress("progress_resource", {"type": type_str_cb, "url": url_str_cb})

    s_attempts, s_success_dl_or_utd, s_failed = 0, 0, 0

    _notify_progress("status", {"message": f"Downloading main page: {index_file_name} from {actual_game_entry_url}"})
    index_dl_success, index_was_downloaded = download_file(
        actual_game_entry_url, local_index_html_path, session, 
        all_project_metadata, 
        progress_callback=_resource_progress_cb_adapter
    )
    s_attempts += 1
    if not index_dl_success:
        s_failed += 1
        failed_url_details[actual_game_entry_url] = actual_game_entry_url 
        msg = f"Failed to download main HTML: {actual_game_entry_url}"
        _notify_progress("error", {"message": msg})
        _notify_progress("finished", {"index_html_path": None, "summary_message": msg})
        session.close()
        return None, msg
    if index_was_downloaded or index_dl_success: s_success_dl_or_utd += 1

    html_discovered_resource_urls_queue: Set[str] = set()
    downloaded_js_file_local_paths: List[Path] = []
    all_js_code_to_scan: List[str] = []
    if local_index_html_path.exists():
        _notify_progress("status", {"message": f"Parsing {local_index_html_path.name}..."})
        try:
            html_bytes = local_index_html_path.read_bytes()
            html_text_content = html_bytes.decode(detect_encoding(html_bytes), errors='replace')
            html_found_urls, inline_js_scripts = parse_html_for_resources(html_text_content, base_url_for_link_resolution, game_domain)
            html_discovered_resource_urls_queue.update(html_found_urls)
            all_js_code_to_scan.extend(inline_js_scripts)
            _notify_progress("status", {"message": f"Found {len(html_found_urls)} URLs and {len(inline_js_scripts)} inline JS in HTML."})
        except Exception as e_html_parse:
            _notify_progress("error", {"message": f"Error parsing HTML {local_index_html_path.name}: {e_html_parse}"})

    initial_resource_futures_map: Dict[Any, str] = {} 
    if html_discovered_resource_urls_queue:
        _notify_progress("status", {"message": f"Downloading {len(html_discovered_resource_urls_queue)} initial linked resources..."})
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="InitialDownloader") as executor:
            for res_url in list(html_discovered_resource_urls_queue): 
                future = executor.submit(
                    handle_resource, res_url, session, game_specific_save_path,
                    game_html_path_on_server, game_domain, 
                    all_project_metadata, 
                    progress_callback=_resource_progress_cb_adapter
                )
                initial_resource_futures_map[future] = res_url
        processed_initial_count = 0
        for future_task in as_completed(initial_resource_futures_map):
            completed_url = initial_resource_futures_map[future_task] 
            s_attempts += 1; processed_initial_count +=1
            try:
                res_dl_success, _ = future_task.result()
                if res_dl_success:
                    s_success_dl_or_utd += 1
                    parsed_completed_url = urlparse(completed_url) 
                    path_from_url_res = parsed_completed_url.path.lstrip('/') if parsed_completed_url.path else ""
                    server_game_dir_path_obj_init = Path(game_html_path_on_server).parent
                    server_game_dir_init = str(server_game_dir_path_obj_init).replace("\\", "/").lstrip('/')
                    if server_game_dir_init and not server_game_dir_init.endswith('/'): server_game_dir_init += '/'
                    if server_game_dir_init == "./" or server_game_dir_init == ".": server_game_dir_init = ""
                    relative_save_path_str_init: str
                    if path_from_url_res.startswith(server_game_dir_init) and server_game_dir_init:
                        relative_save_path_str_init = path_from_url_res[len(server_game_dir_init):].lstrip('/')
                    else:
                        relative_save_path_str_init = path_from_url_res
                    if not relative_save_path_str_init: relative_save_path_str_init = Path(unquote(parsed_completed_url.path)).name if Path(unquote(parsed_completed_url.path)).name else "unknown_resource"
                    local_candidate_path = game_specific_save_path / relative_save_path_str_init 
                    if completed_url.lower().endswith(".js") and local_candidate_path.exists():
                        downloaded_js_file_local_paths.append(local_candidate_path)
                else:
                    s_failed += 1
                    failed_url_details[completed_url] = completed_url 
                _notify_progress("progress_overall", {"processed": processed_initial_count, "total_expected": len(initial_resource_futures_map), "current_url_status_type": "InitialRes", "current_url": completed_url, "success": res_dl_success})
            except Exception as e_fut_init:
                s_failed += 1; failed_url_details[completed_url] = completed_url 
                _notify_progress("error", {"message": f"Exception downloading initial resource {completed_url}: {e_fut_init}"})
                _notify_progress("progress_overall", {"processed": processed_initial_count, "total_expected": len(initial_resource_futures_map), "current_url_status_type": "InitialRes", "current_url": completed_url, "success": False, "exception": str(e_fut_init)})
    html_discovered_resource_urls_queue.clear()

    for js_local_path in downloaded_js_file_local_paths:
        try:
            js_bytes = js_local_path.read_bytes()
            js_content = js_bytes.decode(detect_encoding(js_bytes), errors='replace')
            all_js_code_to_scan.append(js_content)
        except Exception as e_read_js: _notify_progress("error", {"message": f"Error reading JS file {js_local_path.name}: {e_read_js}"})
    js_discovered_json_filenames_relative: List[str] = []
    if all_js_code_to_scan:
        _notify_progress("status", {"message": f"Scanning {len(all_js_code_to_scan)} JS blocks for JSON links..."})
        temp_js_found_set: Set[str] = set() 
        for js_block_content in all_js_code_to_scan:
            found_in_block = find_json_links_in_js(js_block_content)
            for item in found_in_block: temp_js_found_set.add(item)
        js_discovered_json_filenames_relative = sorted(list(temp_js_found_set))
        if js_discovered_json_filenames_relative: _notify_progress("status", {"message": f"Found JSON files in JS: {', '.join(js_discovered_json_filenames_relative)}"})

    project_data_obj = None
    main_project_json_local_path: Optional[Path] = None
    json_candidate_urls_to_try_map: Dict[str, str] = {} 
    std_proj_json_url = urljoin(base_url_for_link_resolution, 'project.json')
    json_candidate_urls_to_try_map[std_proj_json_url] = 'project.json' 
    for rel_json_path in js_discovered_json_filenames_relative:
        full_url_candidate = urljoin(base_url_for_link_resolution, rel_json_path)
        if full_url_candidate not in json_candidate_urls_to_try_map: json_candidate_urls_to_try_map[full_url_candidate] = rel_json_path
    _notify_progress("status", {"message": f"Attempting to download main data JSON from {len(json_candidate_urls_to_try_map)} candidates..."})
    json_candidates_actually_tried_for_failure_log: Dict[str, str] = {}
    for candidate_json_url, raw_json_ref in json_candidate_urls_to_try_map.items():
        json_candidates_actually_tried_for_failure_log[candidate_json_url] = raw_json_ref
        parsed_candidate_url = urlparse(candidate_json_url)
        candidate_filename_on_server = Path(unquote(parsed_candidate_url.path)).name or "data.json"
        current_project_json_local_path = game_specific_save_path / candidate_filename_on_server
        _notify_progress("status", {"message": f"Trying data JSON: {candidate_filename_on_server} from {candidate_json_url}"})
        s_attempts += 1 
        pj_dl_success, _ = download_file( 
            candidate_json_url, current_project_json_local_path, session, 
            all_project_metadata, 
            progress_callback=_resource_progress_cb_adapter
        )
        if pj_dl_success:
            s_success_dl_or_utd += 1
            _notify_progress("status", {"message": f"Downloaded candidate {candidate_filename_on_server}. Verifying..."})
            if current_project_json_local_path.exists():
                try:
                    pj_text = current_project_json_local_path.read_text(encoding='utf-8-sig')
                    project_data_obj_candidate = json.loads(pj_text)
                    if isinstance(project_data_obj_candidate, dict):
                        project_data_obj = project_data_obj_candidate
                        main_project_json_local_path = current_project_json_local_path
                        _notify_progress("status", {"message": f"Candidate {candidate_filename_on_server} parsed. Using as main JSON."})
                        json_candidates_actually_tried_for_failure_log.clear() 
                        break 
                    else: _notify_progress("warning", {"message": f"Candidate {candidate_filename_on_server} not a JSON object. Skipping."})
                except json.JSONDecodeError as e_json: _notify_progress("warning", {"message": f"Candidate {candidate_filename_on_server} not valid JSON: {e_json}. Skipping."})
                except Exception as e_pj_proc: _notify_progress("warning", {"message": f"Error processing {candidate_filename_on_server}: {e_pj_proc}. Skipping."})
        else: _notify_progress("status", {"message": f"Failed to download JSON candidate: {candidate_filename_on_server}"})

    json_linked_resource_urls_queue: Dict[str,str] = {} 
    if project_data_obj and main_project_json_local_path:
        _notify_progress("status", {"message": f"Processing images/resources in {main_project_json_local_path.name}..."})
        try:
            detailed_failures_from_json_images = _recursive_process_json_images(
                project_data_obj, base_url_for_link_resolution, game_specific_save_path,
                session, 
                all_project_metadata, 
                embed_external_images_in_json, 
                progress_callback=_resource_progress_cb_adapter
            )
            if detailed_failures_from_json_images:
                for res_url, raw_ref in detailed_failures_from_json_images:
                    failed_url_details[res_url] = raw_ref 
                s_failed += len(detailed_failures_from_json_images)
                s_attempts += len(detailed_failures_from_json_images) 

            main_project_json_local_path.write_text(json.dumps(project_data_obj, indent=2, ensure_ascii=False), encoding='utf-8')
            json_found_resources_relative = list(enumerate_project_resources(project_data_obj))
            if json_found_resources_relative:
                 _notify_progress("status", {"message": f"Found {len(json_found_resources_relative)} resource paths in {main_project_json_local_path.name}."})
                 for rel_path_from_json in json_found_resources_relative:
                    full_url_from_json = urljoin(base_url_for_link_resolution, rel_path_from_json)
                    if is_local_resource(rel_path_from_json, base_url_for_link_resolution) and \
                       is_valid_url(full_url_from_json, base_domain_check=game_domain) and \
                       not rel_path_from_json.startswith('data:'):
                        json_linked_resource_urls_queue[full_url_from_json] = rel_path_from_json 
        except Exception as e_final_pj_proc: _notify_progress("error", {"message": f"Error processing {main_project_json_local_path.name}: {e_final_pj_proc}"})
    elif not main_project_json_local_path and local_index_html_path.exists():
        _notify_progress("error", {"message": "Failed to find a valid main data JSON file."})
        if json_candidates_actually_tried_for_failure_log: 
            for tried_url, tried_raw_ref in json_candidates_actually_tried_for_failure_log.items():
                failed_url_details[tried_url] = tried_raw_ref
            s_failed += len(json_candidates_actually_tried_for_failure_log) 

    if json_linked_resource_urls_queue:
        _notify_progress("status", {"message": f"Downloading {len(json_linked_resource_urls_queue)} additional assets from JSON..."})
        final_resource_futures_map: Dict[Any, Tuple[str, str]] = {} 
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="FinalDownloader") as executor:
            for res_url, raw_ref in json_linked_resource_urls_queue.items(): 
                future = executor.submit(
                    handle_resource, res_url, session, game_specific_save_path,
                    game_html_path_on_server, game_domain, 
                    all_project_metadata, 
                    progress_callback=_resource_progress_cb_adapter
                )
                final_resource_futures_map[future] = (res_url, raw_ref)
        processed_final_count = 0
        for future_task in as_completed(final_resource_futures_map):
            completed_url, raw_reference_for_url = final_resource_futures_map[future_task]
            s_attempts += 1; processed_final_count +=1
            try:
                res_dl_success, _ = future_task.result()
                if res_dl_success: s_success_dl_or_utd += 1
                else:
                    s_failed += 1; failed_url_details[completed_url] = raw_reference_for_url
                _notify_progress("progress_overall", {"processed": processed_final_count, "total_expected": len(final_resource_futures_map), "current_url_status_type": "FinalRes", "current_url": completed_url, "success": res_dl_success})
            except Exception as e_fut_final:
                s_failed += 1; failed_url_details[completed_url] = raw_reference_for_url
                _notify_progress("error", {"message": f"Exception downloading final resource {completed_url}: {e_fut_final}"})
                _notify_progress("progress_overall", {"processed": processed_final_count, "total_expected": len(final_resource_futures_map), "current_url_status_type": "FinalRes", "current_url": completed_url, "success": False, "exception": str(e_fut_final)})
    
    try:
        with metadata_lock:
            metadata_file_path.parent.mkdir(parents=True, exist_ok=True)
            metadata_file_path.write_text(json.dumps(all_project_metadata, indent=2), encoding='utf-8')
    except Exception as e_meta_save:
        _notify_progress("error", {"message": f"Failed to save metadata file {metadata_file_path}: {e_meta_save}"})

    summary_final_msg = (f"Download finished. Attempts: {s_attempts}, "
                         f"Succeeded/Up-to-date: {s_success_dl_or_utd}, "
                         f"Failed: {s_failed}")

    if failed_url_details:
        failed_items_formatted = []
        current_external_mappings = all_project_metadata.get('external_mappings', {})
        
        # Map: url_to_show_for_user -> (type_of_failure_info, context_string_or_local_path)
        unique_failures_to_display: Dict[str, Tuple[str, str]] = {}

        for attempted_url, original_ref_in_file in sorted(failed_url_details.items()):
            url_to_show_for_user = attempted_url
            failure_type = "direct" # Possible types: "direct", "external_mapped"
            context_info = original_ref_in_file 

            if original_ref_in_file.startswith("downloaded_external_images/") and \
               original_ref_in_file in current_external_mappings:
                # This case means: project.json had "downloaded_external_images/foo.jpg",
                # we tried to download base_url + "downloaded_external_images/foo.jpg" (which is attempted_url), and it failed.
                # The *actual* resource the user needs is current_external_mappings[original_ref_in_file].
                url_to_show_for_user = current_external_mappings[original_ref_in_file]
                failure_type = "external_mapped"
                context_info = original_ref_in_file # This is the target local path, e.g., "downloaded_external_images/foo.jpg"
            
            if url_to_show_for_user not in unique_failures_to_display: # Keep first context if multiple failures lead to same display URL
                 unique_failures_to_display[url_to_show_for_user] = (failure_type, context_info)

        instruction_lines = []
        has_external_mapped_failures = any(ftype == "external_mapped" for ftype, _ in unique_failures_to_display.values())
        has_direct_failures = any(ftype == "direct" for ftype, _ in unique_failures_to_display.values())

        if has_external_mapped_failures:
            instruction_lines.append(
                "For images from external sites (listed below with 'Save as:' advice), "
                "please download them manually and save them into the 'downloaded_external_images' "
                "folder within the game's main downloaded directory, using the indicated local filename."
            )
        if has_direct_failures:
             instruction_lines.append(
                "For other game assets that failed (e.g., local images, CSS), "
                "please download them manually and save them to their expected local paths "
                "within the game's main downloaded directory (often shown as 'Original reference:')."
            )
        
        initial_instruction = "Some files failed to download."
        if not instruction_lines and unique_failures_to_display: # Fallback if logic above missed a case but there are failures
            instruction_lines.append("Please try to download the files listed below manually.")


        for url, (ftype, context) in sorted(unique_failures_to_display.items()):
            line = f"- {url}" # Main URL for user to download
            if ftype == "external_mapped":
                # context here is the intended local path like "downloaded_external_images/some_image.jpg"
                line += f"\n  (Save as: '{context}')"
            elif ftype == "direct":
                # context here is the original reference string from the source file (e.g. "images/pic.png" or an original URL)
                if url != context and not str(context).startswith('data:') and len(str(context)) < 150 : 
                    line += f"\n  (Original reference in source file: '{context}')"
            failed_items_formatted.append(line)

        if failed_items_formatted:
            full_instruction_text = initial_instruction
            if instruction_lines:
                full_instruction_text += "\n" + "\n".join(instruction_lines)
            summary_final_msg += "\n\n" + full_instruction_text + "\n" + "\n".join(failed_items_formatted)


    result_index_path_str = str(local_index_html_path) if local_index_html_path.exists() else None
    if not result_index_path_str and s_attempts > 0 and not index_dl_success : # More specific condition
        summary_final_msg = f"Critical failure: Main HTML page download failed.\n{summary_final_msg}"

    _notify_progress("finished", {"index_html_path": result_index_path_str, "summary_message": summary_final_msg})
    session.close()
    return result_index_path_str, summary_final_msg