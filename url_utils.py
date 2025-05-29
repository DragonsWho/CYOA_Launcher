# CYOA_Launcher - a tool for local fun with interactive CYOA.
# Copyright (C) 2025 DragonsWho <dragonswho@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.


# url_utils.py
import requests
import json
from urllib.parse import urlparse, urlunparse
from typing import Optional, Tuple, Callable, Dict

# PocketBase API constants for cyoa.cafe
POCKETBASE_HOST = "https://cyoa.cafe"
API_BASE_PATH = "/api/collections/"
GAMES_COLLECTION = "games"

def preprocess_url(raw_url: str) -> Optional[str]:
    """
    Cleans and standardizes a user-provided URL.
    Ensures it uses https, has a domain, and attempts to fix common issues.
    Adds a trailing slash to paths that look like directories (no extension).
    """
    if not raw_url:
        return None
    
    url = raw_url.strip()

    parsed_check_scheme = urlparse(url)
    if not parsed_check_scheme.scheme:
        url = "https://" + url
    elif parsed_check_scheme.scheme == "http":
        url = url.replace("http://", "https://", 1)
    elif parsed_check_scheme.scheme not in ["https"]:
        if "://" in url:
            _, rest_part = url.split("://", 1)
            url = "https://" + rest_part
        else:
            return None

    try:
        parsed = urlparse(url)
        if not parsed.scheme or parsed.scheme != "https" or not parsed.netloc:
            return None

        path = parsed.path
        is_cyoa_cafe_game_id_path = (
            parsed.netloc == "cyoa.cafe" and
            path.startswith('/game/') and
            len(path.split('/')) == 3 and
            path.split('/')[-1] != ""
        )

        if path and not path.endswith('/') and not is_cyoa_cafe_game_id_path:
            last_segment = path.split('/')[-1]
            if '.' not in last_segment:
                path += '/'
        
        if not path:
            path = '/'
        
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, parsed.query, parsed.fragment))

    except ValueError:
        return None


def _extract_game_id_from_catalog_url(url: str) -> Optional[str]:
    """
    Extracts the game ID from a cyoa.cafe game URL.
    """
    try:
        parsed = urlparse(url)
        if parsed.netloc == "cyoa.cafe":
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) == 2 and path_parts[0] == 'game' and path_parts[1]:
                return path_parts[1]
        return None
    except Exception:
        return None

def extract_game_url_from_catalog(
    catalog_page_url: str,
    # session: requests.Session, # We will not use the session for this specific API call
    progress_callback: Optional[Callable[[str, Dict[str, str]], None]] = None
) -> Tuple[Optional[str], Optional[str], bool]:
    """
    Fetches the iframe_url for a game from the cyoa.cafe API using a direct requests.get().
    If iframe_url is not found, assumes it's a static CYOA and returns the original catalog_page_url.

    Returns:
        Tuple[Optional[str], Optional[str], bool]:
        - URL to download (iframe_url or catalog_page_url). None on fatal error.
        - Message for UI/logging.
        - is_error: True if a fatal error occurred, False otherwise.
    """
    
    def _notify(message_type: str, message: str):
        if progress_callback:
            progress_callback(message_type, {"message": str(message)})

    game_id = _extract_game_id_from_catalog_url(catalog_page_url)
    if not game_id:
        msg = f"Could not extract game ID from URL: {catalog_page_url}"
        _notify("error", msg)
        return None, msg, True

    api_record_url = f"{POCKETBASE_HOST}{API_BASE_PATH}{GAMES_COLLECTION}/records/{game_id}"
    
    _notify("status", f"Querying catalog API (direct request): {api_record_url}")

    response_text_for_ui = "" 

    try:
        # Make a direct request, exactly like the test script. No session, no custom headers here.
        response = requests.get(api_record_url, timeout=15)
        response_text_for_ui = response.text 

        # Notify UI with summary
        _notify("status", f"API Response Status: {response.status_code}")
        _notify("status", f"API Response Content-Type: {response.headers.get('Content-Type')}")
        _notify("status", f"API Response Body (first 500 chars): {response_text_for_ui[:500]}") # Keep UI brief
        
        if response.status_code == 404:
            msg = "This game ID does not exist in the catalog!"
            _notify("error", msg)
            return None, msg, True
            
        response.raise_for_status()

        record_data = response.json() 
        iframe_url = record_data.get("iframe_url")

        if iframe_url and iframe_url.strip():
            _notify("status", f"Found iframe URL: {iframe_url[:70]}...")
            return iframe_url.strip(), "Successfully retrieved iframe URL from catalog.", False
        else:
            msg = "This is a static CYOA! The game page itself will be downloaded."
            _notify("status", msg)
            return catalog_page_url, msg, False

    except json.JSONDecodeError as jde:
        msg = (f"Catalog API JSON decode error: {jde}. "
               f"Response text (first 500 chars for UI): {response_text_for_ui[:500]}")
        _notify("error", msg)
        return None, msg, True
    except requests.exceptions.HTTPError as http_err:
        msg = (f"Catalog API HTTP error: {http_err}. "
               f"Response text (first 500 chars for UI): {response_text_for_ui[:500]}")
        _notify("error", msg)
        return None, msg, True
    except requests.exceptions.RequestException as req_err:
        msg = f"Catalog API connection error: {req_err}"
        _notify("error", msg)
        return None, msg, True
    except Exception as e:
        msg = (f"An unexpected error occurred with catalog API: {e}. "
               f"Response text (first 500 chars for UI): {response_text_for_ui[:500]}")
        _notify("error", msg)
        return None, msg, True