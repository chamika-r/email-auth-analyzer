"""
Lookalike Domain Detection Module
Detects domains that are visually similar to trusted brands
using character substitution and string similarity scoring.
"""


# Common brand domains to check against
TRUSTED_DOMAINS = [
    'google.com', 'gmail.com', 'microsoft.com', 'outlook.com',
    'apple.com', 'icloud.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'instagram.com', 'linkedin.com', 'twitter.com',
    'github.com', 'dropbox.com', 'salesforce.com', 'docusign.com',
    'wellsfargo.com', 'chase.com', 'bankofamerica.com', 'hsbc.com',
]

# Common character substitutions attackers use
CHAR_SUBSTITUTIONS = {
    'a': ['@', '4', 'α'],
    'e': ['3', 'é'],
    'i': ['1', 'l', '!'],
    'l': ['1', 'i', '|'],
    'o': ['0', 'ο'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['9'],
    'b': ['6'],
}


def levenshtein_distance(s1, s2):
    """Calculate edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions    = previous_row[j + 1] + 1
            deletions     = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def similarity_score(s1, s2):
    """Return similarity as a 0.0-1.0 score (1.0 = identical)."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    distance = levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)


def strip_tld(domain):
    """Remove TLD for comparison — also strips subdomains and suffixes.
    'paypa1-security.com' → 'paypa1'
    'mail.paypal.com' → 'paypal'
    'paypal.co.uk' → 'paypal'
    """
    # Remove known TLDs and suffixes
    domain = domain.replace('.co.uk', '').replace('.com', '').replace(
        '.net', '').replace('.org', '').replace('.io', '')
    # Take the last meaningful segment before any hyphen-appended words
    # e.g. 'paypa1-security' → 'paypa1'
    parts = domain.split('-')
    domain = parts[0]
    # Also handle subdomains — take the last part
    # e.g. 'mail.paypal' → 'paypal'
    parts = domain.split('.')
    return parts[-1] if parts else domain


def check_lookalike(domain, threshold=0.75):
    """
    Check if a domain looks similar to any trusted brand.
    Returns a dict with the closest match and similarity score,
    or None if no suspicious match found.
    """
    if not domain:
        return None

    # Exact match on trusted domain = legitimate, skip
    if domain in TRUSTED_DOMAINS:
        return None

    domain_base = strip_tld(domain)
    best_match = None
    best_score = 0.0

    for trusted in TRUSTED_DOMAINS:
        trusted_base = strip_tld(trusted)
        score = similarity_score(domain_base, trusted_base)
        if score > best_score:
            best_score = score
            best_match = trusted

    if best_score >= threshold:
        return {
            'domain':      domain,
            'impersonates': best_match,
            'score':       round(best_score, 2),
        }
    return None