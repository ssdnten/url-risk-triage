"""Explain suspicious URL features using offline parsing and an explicit trusted-host list."""
import argparse
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

def triage(url, trusted_hosts=()):
    reasons = []
    try:
        if any(ord(char)<32 or char.isspace() for char in url):
            raise ValueError('whitespace or control character')
        parts = urlsplit(url)
        host = parts.hostname
        if parts.scheme.lower() not in {'http','https'} or not host:
            raise ValueError('expected an absolute HTTP(S) URL')
        host = host.rstrip('.').encode('idna').decode('ascii').lower()
        port = parts.port
    except (ValueError, UnicodeError):
        return dict(url=url, host=None, score=5, reasons=['invalid_http_url'], verdict='review')
    if parts.scheme.lower() != 'https': reasons.append('unencrypted_http')
    if parts.username is not None or parts.password is not None: reasons.append('userinfo_in_url')
    try:
        ipaddress.ip_address(host)
        reasons.append('ip_literal_host')
    except ValueError:
        pass
    if any(label.startswith('xn--') for label in host.split('.')): reasons.append('internationalized_host')
    if len(host.split('.')) > 4: reasons.append('many_host_labels')
    if port is not None and port not in {80,443}: reasons.append('unusual_port')
    trusted = {name.rstrip('.').encode('idna').decode('ascii').lower() for name in trusted_hosts}
    if trusted and host not in trusted: reasons.append('outside_trusted_hosts')
    score = len(reasons)
    return dict(url=url,host=host,score=score,reasons=reasons,verdict='review' if reasons else 'no_flags')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='one URL per line')
    parser.add_argument('--trusted', action='append', default=[], help='exact hostname; repeat as needed')
    args = parser.parse_args()
    try:
        print(json.dumps([triage(line.strip(),args.trusted) for line in args.input.read_text(encoding='utf-8').splitlines() if line.strip()], indent=2))
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(2, f'error: {exc}\n')

if __name__ == '__main__': main()
