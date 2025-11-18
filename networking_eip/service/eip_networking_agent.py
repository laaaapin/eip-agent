#   Copyright [2017] [Yoann Terrade]
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import time
import sys
import asyncio
import threading
import concurrent.futures
from oslo_config import cfg
from oslo_service import service
from oslo_log import log as logging
import oslo_messaging
import networking_eip.request_builder.eip_rest as eip_rest

from networking_eip.neutron_connector import connector


LOG=logging.getLogger("eipAgent")

DOMAIN="neutronNotifs"

# Initialize oslo.config so oslo.messaging can pick up the notification
# configuration (we read Neutron's config by default per README instructions).
# This parses CLI args and loads /etc/neutron/neutron.conf so the
# [oslo_messaging_notifications] settings are available to get_notification_transport.
# Register a debug option so users can pass --debug to enable verbose logging
debug_opt = cfg.BoolOpt('debug', default=False, help='Enable debug logging for agent and EIP REST calls')
cfg.CONF.register_opt(debug_opt)

# Parse CLI and config files
cfg.CONF(sys.argv[1:], project='neutron', default_config_files=['/etc/neutron/neutron.conf'])

# optional: override log file if running under kolla/containerized setups
cfg.CONF.log_file = '/var/log/kolla/eipNotifs.log'
logging.register_options(cfg.CONF)
logging.setup(cfg.CONF, DOMAIN)

# If debug flag is set, enable debug logging for oslo.messaging and module loggers
if getattr(cfg.CONF, 'debug', False):
    # set root logger to DEBUG
    import logging as _std_logging
    _std_logging.getLogger().setLevel(_std_logging.DEBUG)
    # also ensure oslo.messaging is verbose
    _std_logging.getLogger('oslo.messaging').setLevel(_std_logging.DEBUG)


def create_addr_scope_handler(payload):
    sitename = payload['address_scope']['name']
    res = eip_rest.create_site(sitename)
    if res is None:
        LOG.error('Failed to create site %s on SolidServer', sitename)
    else:
        LOG.info('Site %s successfully created', sitename)

def delete_addr_scope_handler(payload):
    sitename = payload['address_scope']['name']
    res = eip_rest.delete_site(sitename)
    if res is None:
        LOG.error('Failed to delete site %s on SolidServer', sitename)
    else:
        LOG.info('Site %s successfully deleted', sitename)

def create_subnet_pool_handler(payload):
    start_addr,_,prefix = payload['subnetpool']['prefixes'][0].partition('/')
    resp = connector.NeutronConnector().list_resource('address_scopes', id=payload['subnetpool']['address_scope_id'])
    site_name = resp['address_scopes'][0]['name'] if resp and 'address_scopes' in resp and resp['address_scopes'] else None
    name = payload['subnetpool']['name']
    if payload['subnetpool']['ip_version'] == 4:
        ret = eip_rest.create_block_subnet_v4(start_addr,prefix,site_name,name)
    elif payload['subnetpool']['ip_version'] == 6:
        ret = eip_rest.create_block_subnet_v6(start_addr,prefix,site_name,name)

    if ret:
        LOG.info('Successfully created block %s', name)
    else:
        LOG.error('Failed to create block %s', name)

def delete_subnet_pool_handler(payload):
    resp = connector.NeutronConnector().list_resource('address_scopes', id=payload['subnetpool']['address_scope_id'])
    scope = resp['address_scopes'][0] if resp and 'address_scopes' in resp and resp['address_scopes'] else None
    name = payload['subnetpool']['name']
    sitename = scope['name']
    subnet_addr,_,prefix = payload['subnetpool']['prefixes'][0].partition('/')
    if scope['ip_version'] == 4:
        ret = eip_rest.delete_block_subnet_v4(sitename,subnet_addr,prefix)
    if scope['ip_version'] == 6:
        ret = eip_rest.delete_block_subnet_v6(sitename,subnet_addr,prefix)
    if ret:
        LOG.info('Successfully deleted block %s', name)
    else:
        LOG.error('Failed to delete block %s', name)



### code from oslo_messaging/notify/listener.py
class NotificationEndpoint(object):
    def __init__(self, loop):
        # loop: asyncio event loop where handlers will be scheduled
        self.loop = loop

    def _schedule_handler(self, func, *args, **kwargs):
        """Schedule a blocking handler to run in the loop's default executor.

        We use loop.call_soon_threadsafe to create an asyncio task that runs
        the blocking function in a thread via asyncio.to_thread. This keeps
        the notification listener responsive while handlers run concurrently
        in the threadpool.
        """
        try:
            self.loop.call_soon_threadsafe(
                lambda: asyncio.create_task(asyncio.to_thread(func, *args, **kwargs))
            )
        except Exception:
            LOG.exception('Failed to schedule handler %s', func)

    def warn(self,ctxt,publisher_id,event_type,payload,metadata):
        LOG.error('event %s ___ %s', event_type, payload)

    def info(self,ctxt,publisher_id,event_type,payload,metadata):
        et = str(event_type)
        if et == 'address_scope.create.end':
            self._schedule_handler(create_addr_scope_handler, payload)

        elif et == 'address_scope.delete.end':
            self._schedule_handler(delete_addr_scope_handler, payload)

        elif et == 'subnetpool.create.end':
            self._schedule_handler(create_subnet_pool_handler, payload)

        elif et == 'subnetpool.delete.end':
            self._schedule_handler(delete_subnet_pool_handler, payload)
        else:
            LOG.info('event %s %s', event_type, payload)

class EipNetworkingAgent(object):
    def __init__(self, loop):
        # loop: asyncio event loop where handlers will be scheduled
        try:
            self.transport = oslo_messaging.get_notification_transport(cfg.CONF)
            self.targets = [ oslo_messaging.Target(topic='notifications') ]
            self.endpoints = [ NotificationEndpoint(loop) ]
            # Use threading executor for the oslo listener; handlers are
            # scheduled onto the asyncio loop's executor (threadpool).
            self.server = oslo_messaging.get_notification_listener(
                self.transport, self.targets, self.endpoints, executor='threading'
            )
        except Exception:
            LOG.exception('Failed to initialize oslo.messaging notification listener')
            raise

    def start(self):
        self.server.start()
        self.server.wait()

    def stop(self):
        self.server.stop()

    def reset(self):
        self.server.reset()


class EipNetworkingAgentService(service.ServiceBase):

    def __init__(self):
        # Create a dedicated asyncio loop running in a background thread.
        self.loop = asyncio.new_event_loop()
        # Thread pool executor for blocking handlers (requests etc.)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)
        self.loop.set_default_executor(self.executor)

        self._loop_thread = threading.Thread(target=self.loop.run_forever, name='eip-async-loop', daemon=True)
        self._loop_thread.start()

        # Agent uses the asyncio loop to schedule handlers
        self.agent = EipNetworkingAgent(self.loop)

    def start(self):
        self.agent.start()

    def wait(self):
        # There's no eventlet pool to wait on; keep the service running until stopped
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    def reset(self):
        self.agent.reset()

    def stop(self):
        # Stop the notification server first
        self.agent.stop()
        # Stop asyncio loop and shut down executor
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self._loop_thread.join(timeout=5)
        finally:
            self.executor.shutdown(wait=True)




def main():
## doc says that we should use more than 1 worker
    launcher = service.launch(cfg.CONF,EipNetworkingAgentService(),workers=4)
    launcher.wait()


if __name__ == "__main__":
    main()
