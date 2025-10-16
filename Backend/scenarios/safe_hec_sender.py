#!/usr/bin/env python3
"""
Safe HEC Sender wrapper with TLS fallback and endpoint overrides.
Use when direct hec_sender.py hits SSL/TLS errors or region issues.

Examples:
  python3 safe_hec_sender.py --product crowdstrike_falcon -n 50 \
    --endpoint usea1 --tls-low --insecure
"""
import argparse
import os
import sys
import importlib
import random


def build_session(insecure: bool, tls_low: bool):
    import requests
    from requests.adapters import HTTPAdapter
    try:
        from requests.packages.urllib3.util.ssl_ import create_urllib3_context
    except Exception:
        create_urllib3_context = None

    session = requests.Session()
    if tls_low and create_urllib3_context:
        class TLSAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                ctx = create_urllib3_context()
                # Lower OpenSSL security level for broader compatibility
                try:
                    ctx.set_ciphers('DEFAULT@SECLEVEL=1')
                except Exception:
                    pass
                # If we are running insecure mode, also disable hostname check
                if insecure:
                    try:
                        ctx.check_hostname = False
                    except Exception:
                        pass
                kwargs['ssl_context'] = ctx
                return super().init_poolmanager(*args, **kwargs)

        session.mount('https://', TLSAdapter())

    session.verify = not insecure
    return session


def configure_endpoints(endpoint: str | None):
    if not endpoint:
        return
    base_map = {
        'us1': 'https://ingest.us1.sentinelone.net',
        'usea1': 'https://ingest.usea1.sentinelone.net',
        'global': 'https://ingest.sentinelone.net',
    }
    if endpoint not in base_map:
        raise SystemExit(f"Unknown endpoint '{endpoint}'. Use one of: us1, usea1, global")
    base = base_map[endpoint]
    os.environ['S1_HEC_EVENT_URL_BASE'] = f"{base}/services/collector/event"
    os.environ['S1_HEC_RAW_URL_BASE'] = f"{base}/services/collector/raw"


def main():
    parser = argparse.ArgumentParser(description='HEC sender with TLS fallback and endpoint overrides')
    parser.add_argument('--product', required=True)
    parser.add_argument('-n', '--count', type=int, default=1)
    parser.add_argument('--min-delay', type=float, default=0.02)
    parser.add_argument('--max-delay', type=float, default=0.3)
    parser.add_argument('--marketplace-parser')
    parser.add_argument('--endpoint', choices=['us1', 'usea1', 'global'])
    parser.add_argument('--insecure', action='store_true', help='Disable TLS verification')
    parser.add_argument('--tls-low', action='store_true', help='Enable broader TLS cipher compatibility')
    parser.add_argument('--auth-scheme', choices=['Splunk', 'Bearer'], default=os.getenv('S1_HEC_AUTH_SCHEME', 'Splunk'))
    args = parser.parse_args()

    # Configure endpoints if requested
    configure_endpoints(args.endpoint)

    # Build session and monkeypatch requests in hec_sender
    session = build_session(args.insecure, args.tls_low)

    # Import hec_sender after environment is set
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'event_generators', 'shared'))
    import hec_sender  # type: ignore

    # Monkeypatch requests.post used inside hec_sender
    import types
    def _session_post(url, headers=None, data=None, json=None, timeout=10):
        return session.post(url, headers=headers, data=data, json=json, timeout=timeout)
    hec_sender.requests.post = _session_post  # type: ignore

    # Adjust Authorization header scheme if needed
    token = os.getenv('S1_HEC_TOKEN')
    if not token:
        raise SystemExit('S1_HEC_TOKEN not set. Export it or add to .env')
    if args.auth_scheme == 'Splunk':
        hec_sender.HEADERS['Authorization'] = f'Splunk {token}'  # type: ignore
    else:
        hec_sender.HEADERS['Authorization'] = f'Bearer {token}'  # type: ignore

    # Handle marketplace parser override
    product = args.product
    if args.marketplace_parser:
        mp = args.marketplace_parser
        if mp in hec_sender.MARKETPLACE_PARSER_MAP:
            product = hec_sender.MARKETPLACE_PARSER_MAP[mp]
            hec_sender.SOURCETYPE_MAP[product] = mp  # type: ignore
        else:
            print('Unknown marketplace parser. Available:')
            for k in sorted(hec_sender.MARKETPLACE_PARSER_MAP.keys()):
                print('  ', k)
            raise SystemExit(1)

    # Generate events using hec_sender mappings
    if product not in hec_sender.PROD_MAP:
        raise SystemExit(f"Unknown product '{product}'")
    mod_name, func_names = hec_sender.PROD_MAP[product]
    gen_mod = importlib.import_module(mod_name)
    attr_fields = getattr(gen_mod, 'ATTR_FIELDS')
    generators = [getattr(gen_mod, fn) for fn in func_names]
    events = [generators[i % len(generators)]() for i in range(args.count)]

    # Send
    if args.count == 1:
        print('HEC response:', hec_sender.send_one(events[0], product, attr_fields))
    else:
        print(f"Sending {args.count} events one-by-one (spacing {args.min_delay}s – {args.max_delay}s)…")
        print('Responses:', hec_sender.send_many_with_spacing(
            events, product, attr_fields, args.min_delay, args.max_delay
        ))


if __name__ == '__main__':
    main()
