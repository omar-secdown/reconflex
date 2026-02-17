#!/usr/bin/env python3
"""
Subdomain Expansion Module
Uses alterx (permutation) and shuffledns (bruteforce) to expand subdomain lists
"""

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
import config


def run_alterx(input_file, output_file):
    """
    Run alterx for subdomain permutation
    
    Args:
        input_file: File containing discovered subdomains
        output_file: File to append results to
    
    Returns:
        int: Number of new subdomains generated
    """
    try:
        print(f"    [*] Running alterx permutation engine...")
        
        # Command: cat input_file | alterx | anew output_file
        # Using shell=True to handle pipe
        command = f"cat {input_file} | alterx | anew {output_file}"
        
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 minutes timeout
        )
        
        if result.returncode != 0:
            print(f"    [!] alterx error: {result.stderr.strip()}")
            return 0
        
        # Count lines added by anew (stdout shows new entries)
        new_count = len([line for line in result.stdout.strip().split('\n') if line.strip()])
        
        print(f"    [✓] alterx: Generated {new_count} new permutations")
        return new_count
        
    except subprocess.TimeoutExpired:
        print(f"    [!] alterx timeout")
        return 0
    except Exception as e:
        print(f"    [!] alterx error: {str(e)}")
        return 0


def run_shuffledns(domain, output_file):
    """
    Run shuffledns for single domain bruteforce
    
    Args:
        domain: Single domain to bruteforce
        output_file: File to append results to
    
    Returns:
        int: Number of new subdomains found
    """
    try:
        # Create temporary output file for shuffledns
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_output = temp_file.name
        
        # shuffledns command
        command = [
            'shuffledns',
            '-d', domain,
            '-w', config.WORDLIST_FILE,
            '-r', config.RESOLVERS_FILE,
            '-mode', 'bruteforce',
            '-o', temp_output,
            '-silent'
        ]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600  # 10 minutes timeout per domain
        )
        
        if result.returncode != 0:
            # Check for common errors
            stderr_lower = result.stderr.lower()
            if 'no such file' in stderr_lower:
                print(f"    [!] Missing wordlist or resolvers file")
            elif 'permission denied' in stderr_lower:
                print(f"    [!] Permission error")
            else:
                print(f"    [!] shuffledns error: {result.stderr.strip()}")
            
            # Clean up temp file
            if os.path.exists(temp_output):
                os.remove(temp_output)
            return 0
        
        # Use anew to append unique results to output file
        if os.path.exists(temp_output) and os.path.getsize(temp_output) > 0:
            anew_command = f"cat {temp_output} | anew {output_file}"
            anew_result = subprocess.run(
                anew_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Count new entries
            new_count = len([line for line in anew_result.stdout.strip().split('\n') if line.strip()])
            
            # Clean up temp file
            os.remove(temp_output)
            
            return new_count
        else:
            # Clean up temp file
            if os.path.exists(temp_output):
                os.remove(temp_output)
            return 0
        
    except subprocess.TimeoutExpired:
        print(f"    [!] shuffledns timeout for {domain}")
        return 0
    except Exception as e:
        print(f"    [!] shuffledns error for {domain}: {str(e)}")
        return 0


def expand_subdomains(input_file, output_file, domains_list=None):
    """
    Expand subdomains using alterx and shuffledns in parallel
    
    Args:
        input_file: File containing discovered subdomains (all_subdomains.txt)
        output_file: Output file for expansion results (all_in_one.txt)
        domains_list: List of root domains for shuffledns (extracted from input_file)
    
    Returns:
        int: Total number of new subdomains discovered
    """
    print(f"\n{'='*60}")
    print(f"[+] Starting Subdomain Expansion")
    print(f"{'='*60}\n")
    
    # Validate files exist
    if not os.path.exists(input_file):
        print(f"[-] Input file not found: {input_file}")
        return 0
    
    if not os.path.exists(config.WORDLIST_FILE):
        print(f"[-] Wordlist not found: {config.WORDLIST_FILE}")
        print(f"[!] Run config.py to download required files")
        return 0
    
    if not os.path.exists(config.RESOLVERS_FILE):
        print(f"[-] Resolvers file not found: {config.RESOLVERS_FILE}")
        print(f"[!] Run config.py to download required files")
        return 0
    
    # Copy input file to output file first (seed data)
    subprocess.run(f"cp {input_file} {output_file}", shell=True)
    
    total_new = 0
    
    # ========================================
    # Step 1: Run alterx
    # ========================================
    print(f"[1/2] Running alterx permutation...")
    alterx_count = run_alterx(input_file, output_file)
    total_new += alterx_count
    
    # ========================================
    # Step 2: Run shuffledns for each domain
    # ========================================
    if domains_list and len(domains_list) > 0:
        print(f"\n[2/2] Running shuffledns bruteforce on {len(domains_list)} domains...")
        print(f"[*] This may take a while depending on wordlist size...\n")
        
        completed = 0
        shuffledns_total = 0
        
        # Process domains in parallel (2 at a time to avoid overwhelming)
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_domain = {
                executor.submit(run_shuffledns, domain, output_file): domain 
                for domain in domains_list
            }
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                completed += 1
                
                try:
                    new_count = future.result()
                    shuffledns_total += new_count
                    print(f"    [{completed}/{len(domains_list)}] ✓ {domain}: +{new_count} subdomains")
                except Exception as e:
                    print(f"    [{completed}/{len(domains_list)}] ✗ {domain}: Error - {str(e)}")
        
        total_new += shuffledns_total
        print(f"\n[✓] shuffledns: Found {shuffledns_total} new subdomains across all domains")
    else:
        print(f"\n[2/2] Skipping shuffledns (no root domains provided)")
    
    # ========================================
    # Summary
    # ========================================
    print(f"\n{'='*60}")
    print(f"[✓] Expansion Complete!")
    print(f"    - alterx permutations: +{alterx_count}")
    if domains_list:
        print(f"    - shuffledns bruteforce: +{shuffledns_total}")
    print(f"    - Total new subdomains: {total_new}")
    
    # Count total lines in output file
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            total_count = sum(1 for line in f if line.strip())
        print(f"    - Total subdomains in output: {total_count}")
    
    print(f"[✓] Results saved to: {output_file}")
    print(f"{'='*60}\n")
    
    return total_new


def extract_root_domains(subdomains_file):
    """
    Extract unique root domains from subdomains list
    
    Args:
        subdomains_file: File containing subdomains
    
    Returns:
        list: Unique root domains (e.g., ['example.com', 'test.com'])
    """
    root_domains = set()
    
    try:
        with open(subdomains_file, 'r') as f:
            for line in f:
                subdomain = line.strip()
                if not subdomain:
                    continue
                
                # Extract root domain (last two parts)
                # e.g., "api.dev.example.com" -> "example.com"
                parts = subdomain.split('.')
                if len(parts) >= 2:
                    root_domain = '.'.join(parts[-2:])
                    root_domains.add(root_domain)
        
        return sorted(list(root_domains))
    
    except Exception as e:
        print(f"[!] Error extracting root domains: {str(e)}")
        return []


# ============================================================================
# FOR STANDALONE TESTING
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 expand.py <subdomains_file>")
        print("Example: python3 expand.py all_subdomains.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = "all_in_one.txt"
    
    # Extract root domains
    domains = extract_root_domains(input_file)
    print(f"[*] Found {len(domains)} unique root domains: {', '.join(domains)}")
    
    # Run expansion
    expand_subdomains(input_file, output_file, domains)
