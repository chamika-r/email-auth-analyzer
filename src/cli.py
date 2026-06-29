"""
CLI Module
Command-line interface for the email authentication analyzer.
"""

import click
import json
from src.analyzer import analyze


def severity_color(severity):
    colors = {
        'CRITICAL': '\033[91m',  # red
        'HIGH':     '\033[93m',  # yellow
        'MEDIUM':   '\033[94m',  # blue
        'LOW':      '\033[92m',  # green
    }
    reset = '\033[0m'
    return f"{colors.get(severity, '')}{severity}{reset}"


def risk_color(risk):
    colors = {
        'CRITICAL': '\033[91m',
        'HIGH':     '\033[93m',
        'MEDIUM':   '\033[94m',
        'LOW':      '\033[92m',
    }
    reset = '\033[0m'
    return f"{colors.get(risk, '')}{risk}{reset}"


@click.command()
@click.argument('filepath')
@click.option('--json-output', is_flag=True, help='Output results as JSON')
def main(filepath, json_output):
    """Analyze an email .eml file for authentication issues and BEC indicators."""

    result = analyze(filepath)

    if json_output:
        click.echo(json.dumps(result, indent=2))
        return

    click.echo()
    click.echo('=' * 60)
    click.echo('  EMAIL AUTHENTICATION ANALYZER')
    click.echo('=' * 60)
    click.echo(f"  File:     {result['file']}")
    click.echo(f"  From:     {result['from']}")
    click.echo(f"  Subject:  {result['subject']}")
    click.echo(f"  Date:     {result['date']}")
    click.echo('=' * 60)
    click.echo(f"  Risk:     {risk_color(result['risk'])} ({result['score']}/100)")
    click.echo('=' * 60)

    if not result['findings']:
        click.echo('\n  ✅ No issues found — email passed all checks.\n')
    else:
        click.echo(f"\n  Findings ({len(result['findings'])}):\n")
        for f in result['findings']:
            click.echo(f"  [{severity_color(f['severity'])}] {f['check']}")
            click.echo(f"        {f['detail']}")
            click.echo()

    click.echo('  Authentication Results:')
    for auth in result['auth_results']:
        click.echo(f"    Server: {auth['authserv_id']}")
        click.echo(f"    SPF={auth['spf']}  DKIM={auth['dkim']}  DMARC={auth['dmarc']}")
        click.echo()

    click.echo(f"  SPF Record:   {result['spf_record'] or 'Not found'}")
    click.echo(f"  DMARC Policy: {result['dmarc_record']['policy'] if result['dmarc_record'] else 'Not found'}")
    click.echo()


if __name__ == '__main__':
    main()