"""
Analyzer Module
Orchestrates parser, auth_checker, and lookalike modules
and produces a final risk score with findings.
"""

from src.parser import load_email, extract_headers, extract_domain, extract_address
from src.auth_checker import (
    parse_authentication_results,
    check_spf_dns,
    check_dmarc_dns,
    get_dkim_domain,
)
from src.lookalike import check_lookalike


# Risk score weights
WEIGHTS = {
    'spf_fail':        25,
    'dkim_fail':       25,
    'dmarc_fail':      20,
    'no_dmarc_record': 15,
    'reply_to_mismatch': 20,
    'lookalike_domain': 30,
    'no_spf_record':   10,
}


def analyze(filepath):
    """
    Run full analysis on a .eml file.
    Returns a results dict with risk score, findings, and all raw data.
    """
    msg      = load_email(filepath)
    headers  = extract_headers(msg)
    findings = []
    score    = 0

    from_domain    = extract_domain(headers['from'])
    from_address   = extract_address(headers['from'])
    reply_domain   = extract_domain(headers['reply_to'])
    return_domain  = extract_domain(headers['return_path'])

    # ── 1. Parse Authentication-Results headers ──────────────────────
    auth_results = parse_authentication_results(
        headers['authentication_results']
    )

    spf_result   = 'none'
    dkim_result  = 'none'
    dmarc_result = 'none'

    if auth_results:
        # Use the last result — closest to the recipient's mail server
        last = auth_results[-1]
        spf_result   = last.get('spf',   'none')
        dkim_result  = last.get('dkim',  'none')
        dmarc_result = last.get('dmarc', 'none')

    if spf_result == 'fail':
        score += WEIGHTS['spf_fail']
        findings.append({
            'severity': 'HIGH',
            'check':    'SPF',
            'detail':   'SPF check failed — sending server is not authorised for this domain.',
        })

    if dkim_result == 'fail':
        score += WEIGHTS['dkim_fail']
        findings.append({
            'severity': 'HIGH',
            'check':    'DKIM',
            'detail':   'DKIM signature failed — email may have been tampered with in transit.',
        })

    if dmarc_result == 'fail':
        score += WEIGHTS['dmarc_fail']
        findings.append({
            'severity': 'HIGH',
            'check':    'DMARC',
            'detail':   'DMARC check failed — email did not pass domain alignment checks.',
        })

    # ── 2. Live DNS checks ────────────────────────────────────────────
    spf_record   = check_spf_dns(from_domain)
    dmarc_record = check_dmarc_dns(from_domain)

    if not spf_record:
        score += WEIGHTS['no_spf_record']
        findings.append({
            'severity': 'MEDIUM',
            'check':    'SPF Record',
            'detail':   f'No SPF record found for {from_domain}.',
        })

    if not dmarc_record:
        score += WEIGHTS['no_dmarc_record']
        findings.append({
            'severity': 'MEDIUM',
            'check':    'DMARC Record',
            'detail':   f'No DMARC record found for {from_domain} — domain has no email authentication policy.',
        })

    # ── 3. Reply-To mismatch ──────────────────────────────────────────
    if reply_domain and reply_domain != from_domain:
        score += WEIGHTS['reply_to_mismatch']
        findings.append({
            'severity': 'HIGH',
            'check':    'Reply-To Mismatch',
            'detail':   f'From domain ({from_domain}) differs from Reply-To domain ({reply_domain}) — replies go to a different server.',
        })

    # ── 4. Lookalike domain ───────────────────────────────────────────
    lookalike = check_lookalike(from_domain)
    if lookalike:
        score += WEIGHTS['lookalike_domain']
        findings.append({
            'severity': 'CRITICAL',
            'check':    'Lookalike Domain',
            'detail':   f'{from_domain} closely resembles {lookalike["impersonates"]} (similarity: {lookalike["score"]}).',
        })

    # ── 5. Final risk rating ──────────────────────────────────────────
    score = min(score, 100)

    if score >= 70:
        risk = 'CRITICAL'
    elif score >= 45:
        risk = 'HIGH'
    elif score >= 20:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'

    return {
        'file':         filepath,
        'subject':      headers['subject'],
        'from':         headers['from'],
        'from_domain':  from_domain,
        'reply_to':     headers['reply_to'],
        'date':         headers['date'],
        'risk':         risk,
        'score':        score,
        'findings':     findings,
        'auth_results': auth_results,
        'spf_record':   spf_record,
        'dmarc_record': dmarc_record,
    }