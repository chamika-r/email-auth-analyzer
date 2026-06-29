"""
Email Parser Module
Loads a raw .eml file and extracts the headers needed for
authentication and BEC analysis.
"""

import email
from email import policy
from email.utils import parseaddr


def load_email(filepath):
    """Load and parse a raw .eml file."""
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    return msg


def extract_headers(msg):
    """Extract authentication-relevant headers from the parsed email."""
    return {
        'from':                   msg.get('From', ''),
        'reply_to':               msg.get('Reply-To', ''),
        'return_path':            msg.get('Return-Path', ''),
        'subject':                msg.get('Subject', ''),
        'date':                   msg.get('Date', ''),
        'authentication_results': msg.get_all('Authentication-Results', []),
        'received':               msg.get_all('Received', []),
        'dkim_signature':         msg.get('DKIM-Signature', ''),
    }


def extract_domain(address_header):
    """Extract the domain from an address header like 'Name <user@domain.com>'."""
    if not address_header:
        return ''
    _, addr = parseaddr(address_header)
    if '@' in addr:
        return addr.split('@')[-1].lower()
    return ''


def extract_address(address_header):
    """Extract just the email address from a header like 'Name <user@domain.com>'."""
    if not address_header:
        return ''
    _, addr = parseaddr(address_header)
    return addr.lower()