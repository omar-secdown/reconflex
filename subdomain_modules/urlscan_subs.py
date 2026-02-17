import os
import sys

# Add parent directory to path for config import
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import config
from utils import make_request


def get_urlscan_subdomains(domain):
    """
    Fetch subdomains from URLScan.io Search API.
    Also saves all URLs to a separate file for further analysis.

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
            urls = set()

            results = data.get('results', [])

            for result in results:
                page = result.get('page', {})
                subdomain = page.get('domain', '')
                page_url = page.get('url', '')

                task = result.get('task', {})
                if not subdomain:
                    subdomain = task.get('domain', '')
                if not page_url:
                    page_url = task.get('url', '')

                if subdomain and domain in subdomain:
                    subdomains.add(subdomain)

                if page_url and domain in page_url:
                    urls.add(page_url)

            # Save URLs to file
            if urls:
                urlscan_dir = os.path.join(os.getcwd(), 'output', 'urlscan_results', domain)
                if not os.path.exists(urlscan_dir):
                    os.makedirs(urlscan_dir)

                urls_file = os.path.join(urlscan_dir, 'urls.txt')
                with open(urls_file, 'w') as f:
                    for url_item in sorted(urls):
                        f.write(f"{url_item}\n")

                print(f"    [*] URLScan.io URLs saved to: {urls_file}")

            total_scans = data.get('total', 0)
            print(f"    [*] URLScan.io: Found {total_scans} scan results")
            print(f"    [*] URLScan.io: Extracted {len(urls)} unique URLs")

            return sorted(list(subdomains))

        elif response.status_code == 401:
            print(f"    [!] URLScan.io API key invalid or unauthorized")
            return []

        else:
            print(f"    [!] URLScan.io API error: HTTP {response.status_code}")
            return []

    except Exception as e:
        print(f"    [!] URLScan.io unexpected error: {str(e)}")
        return []
