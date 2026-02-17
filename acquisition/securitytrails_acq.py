import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_securitytrails_associated(domain):
    """
    Fetch associated domains from SecurityTrails API.
    Returns domains that share infrastructure/registrant details with the target.

    Args:
        domain: Target domain to find associated domains for

    Returns:
        List of associated domain names or empty list on failure
    """
    api_key = config.API_KEYS.get('SECURITYTRAILS_API_KEY')
    url = f"https://api.securitytrails.com/v1/domain/{domain}/associated"

    headers = {
        'APIKEY': api_key,
        'Accept': 'application/json'
    }

    try:
        response = make_request(url, headers=headers, timeout=60, max_retries=3,
                                source_name="SecurityTrails Acquisition")

        if response is None:
            return []

        if response.status_code == 200:
            data = response.json()
            associated_domains = set()

            records = data.get('records', [])

            for record in records:
                hostname = record.get('hostname', '')
                if hostname and hostname != domain:
                    associated_domains.add(hostname)

            return sorted(list(associated_domains))

        elif response.status_code == 401:
            print(f"    [!] SecurityTrails API key invalid or unauthorized")
            return []

        elif response.status_code == 404:
            return []

        else:
            print(f"    [!] SecurityTrails API error: HTTP {response.status_code}")
            return []

    except Exception as e:
        print(f"    [!] SecurityTrails unexpected error: {str(e)}")
        return []
