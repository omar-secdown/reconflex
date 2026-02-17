import sys
import os

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_otx_associated(domain, email_filters=None):
    """
    Fetch related domains from AlienVault OTX WHOIS data.
    Filters results based on registrant email domain names.

    Args:
        domain: Target domain to find associated domains for
        email_filters: List of email domain names to filter by (without TLD)
                      e.g., ['abbvie', 'caterpillar']
                      If None, defaults to filtering by target domain only

    Returns:
        List of associated domain names or empty list on failure
    """
    api_key = config.API_KEYS.get('OTX_API_KEY')
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/whois"

    headers = {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json'
    }

    # If no email filters provided, use target domain name as default
    if email_filters is None:
        domain_parts = domain.lower().split('.')
        if len(domain_parts) >= 2:
            email_filters = [domain_parts[0]]
        else:
            email_filters = []

    email_filters = [f.lower().strip() for f in email_filters if f.strip()]

    if not email_filters:
        print(f"    [!] No valid email filters provided")
        return []

    try:
        response = make_request(url, headers=headers, timeout=60, max_retries=3,
                                source_name="AlienVault OTX Acquisition")

        if response is None:
            return []

        if response.status_code == 200:
            data = response.json()
            related_domains = set()

            related_records = data.get('related', [])

            for record in related_records:
                if record.get('related_type') == 'email':
                    related_domain_name = record.get('domain', '')
                    email = record.get('related', '').lower()

                    if email and '@' in email:
                        if any(filter_word in email for filter_word in email_filters):
                            if related_domain_name and related_domain_name.lower() != domain.lower():
                                related_domains.add(related_domain_name)

            return sorted(list(related_domains))

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
