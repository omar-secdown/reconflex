#!/usr/bin/env python3
"""
Reconflex Output Manager
Handles file output, directory creation, and result aggregation
"""

import os
from datetime import datetime


def ensure_dir(directory):
    """Create directory if it doesn't exist."""
    if not os.path.exists(directory):
        os.makedirs(directory)
    return directory


def get_quick_results_dir():
    """Get the quick_results output directory."""
    return ensure_dir(os.path.join(os.getcwd(), 'output', 'quick_results'))


def get_scan_dir(first_domain, suffix=''):
    """
    Create and return a date-stamped scan directory.

    Args:
        first_domain: First domain in the scan (used for naming)
        suffix: Optional suffix for the directory name

    Returns:
        str: Path to the scan directory
    """
    date_prefix = datetime.now().strftime('%Y-%m-%d')
    scan_name = f"{date_prefix}_{first_domain}"
    if suffix:
        scan_name += f"_{suffix}"
    return ensure_dir(os.path.join(os.getcwd(), 'output', 'scans', scan_name))


def get_acquisition_dir():
    """Get the acquisition output directory."""
    return ensure_dir(os.path.join(os.getcwd(), 'output', 'acquisition'))


def get_ips_dir():
    """Get the IPs output directory."""
    return ensure_dir(os.path.join(os.getcwd(), 'output', 'ips'))


def save_results(filepath, items):
    """
    Save a set or list of items to a file, sorted and deduplicated.

    Args:
        filepath: Output file path
        items: Set or list of strings to save

    Returns:
        int: Number of items saved
    """
    unique_items = sorted(set(items))
    with open(filepath, 'w') as f:
        for item in unique_items:
            if item.strip():
                f.write(f"{item}\n")
    return len(unique_items)


def count_lines(filepath):
    """Count non-empty lines in a file."""
    if not os.path.exists(filepath):
        return 0
    with open(filepath, 'r') as f:
        return sum(1 for line in f if line.strip())


def read_domains_from_file(filepath):
    """
    Read domains from a file (one per line).

    Args:
        filepath: Path to file containing domains

    Returns:
        List of domain strings
    """
    if not os.path.exists(filepath):
        print(f"[-] Error: File '{filepath}' not found!")
        return []

    with open(filepath, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    if not domains:
        print("[-] No domains found in file!")

    return domains
