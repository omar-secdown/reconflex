import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_urlscan_subdomains(domain):
    """
    Fetch subdomains from URLScan.io Search API.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('URLSCAN_API_KEY')
    url = "https://urlscan.io/api/v1/search/"

    headers = {
        'API-Key': api_key,
        'Accept': 'application/json'
    }

    params = {
        'q': f'domain:{domain}',
        'size': 10000
    }

    try:
        response = make_request(url, headers=headers, params=params, timeout=60,
                                max_retries=3, source_name="URLScan.io")

        if response is None:
            return []

        if response.status_code == 200:
            data = response.json()
            subdomains = set()

            for result in data.get('results', []):
                page = result.get('page', {})
                task = result.get('task', {})

                subdomain = page.get('domain', '') or task.get('domain', '')
                if subdomain and domain in subdomain:
                    subdomains.add(subdomain)

            return sorted(list(subdomains))

        elif response.status_code == 401:
            print(f"    [!] URLScan.io API key invalid or unauthorized")
            return []

        else:
            return []

    except Exception as e:
        print(f"    [!] URLScan.io unexpected error: {str(e)}")
        return []
