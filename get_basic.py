# -*- coding: utf-8 -*-
# ==============================================================================
# This script is designed to fetch basic video information from Douyin by 
# leveraging the existing project's constants and utility functions.
# It uses HeadersConfig, DeviceConfig from constants.py and BogusManager from utils.py
# ==============================================================================

import asyncio
import json
from urllib.parse import urlencode

try:
    import httpx
except ImportError:
    raise ImportError("The 'httpx' library is required. Please install it using 'pip install httpx'")

# --- Import configurations and utilities from the project ---
try:
    from constants import HeadersConfig, DeviceConfig, APIEndpoints
    from utils import BogusManager
except ImportError as e:
    print(f"Error: Failed to import from project files (constants.py, utils.py). {e}")
    print("Please ensure get_basic.py is in the root directory of the Douyin_TikTok_Download_API project.")
    exit(1)


async def fetch_one_video(aweme_id: str):
    """
    Fetches data for a single video from Douyin using its aweme_id.
    """
    print(f"Fetching video with aweme_id: {aweme_id}")

    # 1. Get headers and parameters from constants.py
    headers = HeadersConfig.get_headers()
    params = DeviceConfig.get_device_info()
    params['aweme_id'] = aweme_id

    # The endpoint for video details
    # Note: In a real scenario, this would also come from constants.py
    endpoint = "https://www.douyin.com/aweme/v1/web/aweme/detail/"

    # 2. Generate the a_bogus signature using BogusManager from utils.py
    # The ab_model_2_endpoint in utils.py handles the full logic including URL encoding
    a_bogus = BogusManager.ab_model_2_endpoint(params, headers["User-Agent"])
    print(f"Generated a_bogus: {a_bogus}")

    # 3. Construct the final URL
    query_string = urlencode(params)
    full_url = f"{endpoint}?{query_string}&a_bogus={a_bogus}"

    print(f"\nRequesting URL: {full_url}\n")

    # 4. Perform the request
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(full_url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as exc:
            print(f"An error occurred while requesting {exc.request.url!r}.")
            print(f"Error: {exc}")
            return None
        except httpx.HTTPStatusError as exc:
            print(f"Error response {exc.response.status_code} while requesting {exc.request.url!r}.")
            print(f"Response content: {exc.response.text}")
            return None
        except json.JSONDecodeError:
            print("Failed to decode JSON from response.")
            print(f"Status: {response.status_code}, Content: {response.text}")
            return None


async def main():
    """ Main function to run the script. """
    # You can change this to any video ID you want to test
    aweme_id_to_fetch = "7372484719365098803"
    
    video_data = await fetch_one_video(aweme_id_to_fetch)

    if video_data:
        print("\n" + "="*50)
        print("Successfully fetched video data!")
        print("="*50 + "\n")
        print(json.dumps(video_data, indent=2, ensure_ascii=False))
    else:
        print("\n" + "="*50)
        print("Failed to fetch video data.")
        print("="*50 + "\n")


if __name__ == "__main__":
    # The script now relies on project files, so no need to check for other libs here.
    # The try/except block for imports at the top handles the dependency check.
    asyncio.run(main())
