"""
Authentication Checker Module
Parses SPF, DKIM, DMARC results from email headers
and performs live DNS lookups against the sender's domain.
"""

import re
import dns.resolver


def parse_authentication_results(auth_results_list):
    """Parse Authentication-Results headers into spf/dkim/dmarc verdicts."""
    parsed = []
    for header in auth_results_list:
        authserv_id = header.split(';')[0].strip()

        result = {'authserv_id': authserv_id}
        for mechanism in ('spf', 'dkim', 'dmarc'):
            match = re.search(rf'{mechanism}=(\w+)', header, re.IGNORECASE)
            result[mechanism] = match.group(1).lower() if match else 'none'

        parsed.append(result)
    return parsed


def check_spf_dns(domain):
    """Look up the domain's SPF record via DNS. Returns the record string or None."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = ''.join(
                part.decode() if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            if txt.startswith('v=spf1'):
                return txt
    except Exception:
        pass
    return None


def check_dmarc_dns(domain):
    """Look up the domain's DMARC record. Returns dict with record and policy or None."""
    try:
        answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for rdata in answers:
            txt = ''.join(
                part.decode() if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            if txt.startswith('v=DMARC1'):
                policy_match = re.search(r'p=(\w+)', txt)
                policy = policy_match.group(1).lower() if policy_match else 'none'
                return {'record': txt, 'policy': policy}
    except Exception:
        pass
    return None


def get_dkim_domain(msg):
    """Extract the d= domain from the DKIM-Signature header."""
    dkim_header = msg.get('DKIM-Signature', '')
    if not dkim_header:
        return None
    match = re.search(r'd=([^;\s]+)', dkim_header)
    return match.group(1).lower() if match else None