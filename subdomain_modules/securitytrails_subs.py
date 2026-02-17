import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_securitytrails_subdomains(domain):
    """
    Fetch subdomains from SecurityTrails API.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of full subdomains (subdomain.domain.com) or empty list on failure
    """
    api_key = config.API_KEYS.get('SECURITYTRAILS_API_KEY')
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"

    headers = {
        'APIKEY': api_key,
        'Accept': 'application/json'
    }

    try:
        response = make_request(url, headers=headers, timeout=30, max_retries=3,
                                source_name="SecurityTrails")

        if response is None:
            return []

        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('subdomains', [])

            full_subdomains = []
            for subdomain in subdomains:
                if subdomain:
                    full_subdomain = f"{subdomain}.{domain}"
                    full_subdomains.append(full_subdomain)

            return full_subdomains

        elif response.status_code == 401:
            print(f"    [!] SecurityTrails API key invalid")
            return []

        else:
            print(f"    [!] SecurityTrails API error: HTTP {response.status_code}")
            return []

    except Exception as e:
        print(f"    [!] SecurityTrails unexpected error: {str(e)}")
        return []
