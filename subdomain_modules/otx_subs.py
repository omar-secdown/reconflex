import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_otx_subdomains(domain):
    """
    Fetch subdomains from AlienVault OTX (Open Threat Exchange).

    Args:
        domain: Target domain to enumerate

    Returns:
        List of unique subdomains or empty list on failure
    """
    api_key = config.API_KEYS.get('OTX_API_KEY')
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

    headers = {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json'
    }

    try:
        response = make_request(url, headers=headers, timeout=60, max_retries=3,
                                source_name="AlienVault OTX")

        if response is None:
            return []

        if response.status_code == 200:
            data = response.json()
            subdomains = set()

            passive_dns = data.get('passive_dns', [])

            for record in passive_dns:
                hostname = record.get('hostname', '')
                if hostname and domain in hostname and hostname != domain:
                    subdomains.add(hostname)

            return sorted(list(subdomains))

        elif response.status_code == 401:
            print(f"    [!] AlienVault OTX API key invalid or unauthorized")
            return []

        elif response.status_code == 404:
            return []

        else:
            print(f"    [!] AlienVault OTX API error: HTTP {response.status_code}")
            return []

    except Exception as e:
        print(f"    [!] AlienVault OTX unexpected error: {str(e)}")
        return []
