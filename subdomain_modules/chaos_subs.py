import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_chaos_subdomains(domain):
    """
    Fetch subdomains from ProjectDiscovery Chaos.

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('CHAOS_API_KEY')
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"

    headers = {
        'Authorization': api_key,
        'Accept': 'application/json'
    }

    try:
        response = make_request(url, headers=headers, timeout=30, max_retries=3,
                                source_name="Chaos")

        if response is None:
            return []

        if response.status_code == 200:
            data = response.json()
            subdomains = data.get('subdomains', [])

            full_subdomains = []
            for subdomain in subdomains:
                if not subdomain or subdomain in ['', '*', '*.']:
                    continue
                if subdomain.startswith('*.'):
                    subdomain = subdomain[2:]
                if not subdomain:
                    continue
                full_subdomain = f"{subdomain}.{domain}"
                full_subdomains.append(full_subdomain)

            return full_subdomains

        elif response.status_code == 401:
            print(f"    [!] Chaos API key invalid or unauthorized")
            return []

        elif response.status_code == 404:
            return []

        else:
            print(f"    [!] Chaos API error: HTTP {response.status_code}")
            return []

    except Exception as e:
        print(f"    [!] Chaos unexpected error: {str(e)}")
        return []
