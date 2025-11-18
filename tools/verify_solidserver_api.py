#!/usr/bin/env python3
"""
Simple helper to probe the EfficientIP SolidServer endpoints used by this project.
Usage:
  python tools\verify_solidserver_api.py [path/to/neutron.conf]
If a config file is provided it is passed to oslo.config so the SolidServer
address/credentials from that file are used.

Outputs a one-line summary per queried endpoint.
"""
import sys
from oslo_config import cfg

if len(sys.argv) > 1:
    cfg.CONF([f'--config-file={sys.argv[1]}'], project='neutron')

from networking_eip.request_builder import eip_rest

results = eip_rest.verify_api_endpoints()
for q, info in sorted(results.items()):
    status = info['status']
    ok = info['ok']
    reason = info['reason']
    tag = 'OK' if ok else 'FAIL'
    print(f"{tag:<5} {q:<35} status={status!s:<4} reason={reason}")
