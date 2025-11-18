#!/usr/bin/env python3
"""
Inspect and publish a test notification across different oslo.messaging versions.
Saves verbose diagnostics so we can adapt to the installed API.

Run:
  py -3 test_publisher_inspect.py
or
  python test_publisher_inspect.py

"""
import sys
import traceback
import inspect
from oslo_config import cfg

# adjust this if your neutron.conf is elsewhere
NEUTRON_CONF = '/etc/neutron/neutron.conf'

try:
    cfg.CONF([f'--config-file={NEUTRON_CONF}'], project='neutron')
except Exception as e:
    print('Warning: could not parse config file:', e)

import oslo_messaging
import pkg_resources

print('Python:', sys.executable)
try:
    print('oslo.messaging package version:', pkg_resources.get_distribution('oslo.messaging').version)
except Exception:
    print('oslo.messaging package version: (pkg_resources not available or package not found)')
print('oslo.messaging module __version__:', getattr(oslo_messaging, '__version__', None))

print('\nNotifier class and callables:')
try:
    print('Notifier:', oslo_messaging.Notifier)
    print('Notifier signature:', inspect.signature(oslo_messaging.Notifier))
    if hasattr(oslo_messaging.Notifier, 'prepare'):
        print('Notifier.prepare signature:', inspect.signature(oslo_messaging.Notifier.prepare))
    else:
        print('Notifier.prepare: <not present>')
except Exception:
    traceback.print_exc()

print('\nTrying to create transport and notifier...')
transport = None
try:
    transport = oslo_messaging.get_notification_transport(cfg.CONF)
    print('Transport created:', transport)
except Exception:
    print('Failed to create transport:')
    traceback.print_exc()

# Build a target object if available
Target = getattr(oslo_messaging, 'Target', None)
if Target:
    try:
        target = Target(topic='notifications')
        print('Built Target:', target)
    except Exception:
        print('Failed to build Target object:')
        traceback.print_exc()
else:
    target = None
    print('oslo_messaging.Target not found')

print('\nAttempting to construct Notifier with several common kwargs...')
notifier = None
constructor_attempts = [
    {'kwargs': {'transport': transport, 'driver': 'messaging', 'publisher_id': 'test.pub'}},
    {'kwargs': {'transport': transport, 'driver': 'messaging', 'publisher_id': 'test.pub', 'target': target}},
    {'kwargs': {'transport': transport, 'driver': 'messaging', 'publisher_id': 'test.pub', 'topic': 'notifications'}},
]
for idx, attempt in enumerate(constructor_attempts, 1):
    try:
        print(f'Attempt {idx} ctor kwargs: {attempt["kwargs"].keys()}')
        # many Notifier implementations accept (transport, driver=..., publisher_id=...)
        notifier = oslo_messaging.Notifier(attempt['kwargs']['transport'],
                                           driver=attempt['kwargs'].get('driver'),
                                           publisher_id=attempt['kwargs'].get('publisher_id'))
        print('Notifier created (simple ctor) ->', notifier)
        break
    except TypeError as e:
        print('TypeError creating Notifier with simple ctor:', e)
    except Exception:
        print('Exception creating Notifier:')
        traceback.print_exc()

if notifier is None:
    # As a last resort try the module-level constructor with all kwargs via **kwargs
    for idx, attempt in enumerate(constructor_attempts, 1):
        try:
            print(f'Fallback Attempt {idx} ctor with **kwargs: {attempt["kwargs"]}')
            notifier = oslo_messaging.Notifier(**attempt['kwargs'])
            print('Notifier created via fallback **kwargs ->', notifier)
            break
        except Exception as e:
            print('Fallback ctor attempt failed:')
            traceback.print_exc()

if notifier is None:
    print('Could not create a Notifier; aborting publish attempts. Paste the above output so I can adapt code for your oslo.messaging version.')
    sys.exit(1)

print('\nNotifier.prepare availability and signature:')
try:
    prep = getattr(notifier, 'prepare', None)
    print('prepare callable:', prep)
    if prep:
        try:
            print('prepare signature:', inspect.signature(prep))
        except Exception:
            print('Could not get prepare signature')
except Exception:
    traceback.print_exc()

# Build payload and event
payload = {'address_scope': {'name': 'testsite'}}
event_type = 'address_scope.create.end'
ctxt = {}

print('\nAttempting to send notification using several common info() signatures...')
send_attempts = [
    lambda n: n.info(ctxt, event_type, payload),
    lambda n: n.info(ctxt, 'test.pub', event_type, payload),
]
sent = False
for idx, fn in enumerate(send_attempts, 1):
    try:
        print(f'Call attempt {idx} -> {fn}')
        fn(notifier)
        print('Notification sent with attempt', idx)
        sent = True
        break
    except TypeError as e:
        print('TypeError calling info():', e)
        traceback.print_exc()
    except Exception:
        print('Exception calling info():')
        traceback.print_exc()

if not sent:
    # Try prepare-based publish if available
    try:
        if hasattr(notifier, 'prepare'):
            print('Trying prepare() with topic/target fallbacks...')
            try:
                prep_notifier = notifier.prepare(topic='notifications')
                prep_notifier.info(ctxt, event_type, payload)
                print('Notification sent via prepare(topic=...)')
                sent = True
            except Exception as e:
                print('prepare(topic=...) failed:', e)
                traceback.print_exc()
            try:
                prep_notifier = notifier.prepare(target=target)
                prep_notifier.info(ctxt, event_type, payload)
                print('Notification sent via prepare(target=...)')
                sent = True
            except Exception as e:
                print('prepare(target=...) failed:', e)
                traceback.print_exc()
    except Exception:
        traceback.print_exc()

if not sent:
    print('\nAll automated attempts failed. Please paste the full output here and I will adapt the publisher for your oslo.messaging version.')
else:
    print('\nDone. If the agent is running you should see the notification in its logs (enable --debug for more verbosity).')
