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


import requests
from oslo_config import cfg
import netaddr
import json
from networking_eip.request_builder import request_builder
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


def _debug_enabled():
    try:
        # Use the agent-specific flag to avoid colliding with oslo.log's
        # global --debug option.
        return bool(getattr(cfg.CONF, 'eip_debug', False))
    except Exception:
        return False


def _req(method, url, headers=None, **kwargs):
    # Centralized request wrapper that logs request/response when debug is enabled
    if _debug_enabled():
        LOG.debug('EIP REST REQ %s %s headers=%s params=%s json=%s',
                  method, url, headers, kwargs.get('params'), kwargs.get('json'))
    # Ensure verify=False is set if not provided (existing code used verify=False everywhere)
    if 'verify' not in kwargs:
        kwargs['verify'] = False
    r = requests.request(method, url, headers=headers, **kwargs)
    if _debug_enabled():
        try:
            LOG.debug('EIP REST RESP status=%s text=%s', r.status_code, r.text)
        except Exception:
            LOG.debug('EIP REST RESP status=%s (failed to read body)', r.status_code)
    return r

def add_columns(ipv6Addr):
    ret_ipv6 = ipv6Addr[:4]+':'+ipv6Addr[4:8]+':'+ipv6Addr[8:12]+':'+ipv6Addr[12:16]+':'+\
            ipv6Addr[16:20]+':'+ipv6Addr[20:24]+':'+ipv6Addr[24:28]+':'+ipv6Addr[28:32]
    return ret_ipv6


def get_site_list(site_name):
    url, headers = request_builder.requestBuilder.buildRequest('ip_site_list')
    data = dict()
    data['WHERE'] = "site_name='"+site_name+"'"
    r = _req('GET', url, headers=headers, params=data)
    if r.status_code == 200:
        return 1
    else:
        LOG.error('get_site_list failed: %s %s', r.status_code, getattr(r, 'text', ''))
        return None

def create_site(site_name):
    url, headers = request_builder.requestBuilder.buildRequest('ip_site_add')
    data = dict()
    data['site_name'] = site_name
    r = requests.post(url,headers=headers,json=data,verify=False)
    if r.status_code == 201:
        return 1
    else:
        LOG.error('create_site failed: %s %s', r.status_code, getattr(r, 'text', ''))
        return None

def delete_site(site_name):
    url, headers = request_builder.requestBuilder.buildRequest('ip_site_delete')
    data = dict()
    data['site_name'] = site_name
    r = requests.delete(url,headers=headers,json=data,verify=False)
    if r.status_code == 201:
        return 1
    else:
        LOG.error('delete_site failed: %s %s', r.status_code, getattr(r, 'text', ''))
        return None



def get_subnet_list_v4(start_addr,sitename,subnetpool_name):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip_block_subnet_list')

    data['WHERE'] = "subnet_level='1' AND site_name='" + sitename +"' AND parent_subnet_name='"+subnetpool_name+"'"

    if start_addr:
        start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
        data['WHERE'] += "AND start_ip_addr='"+ start_addr_hexa+"'"


    r = requests.get(url,headers=headers,params=data,verify=False)
    LOG.debug('get_subnet_list_v4 URL: %s', r.url)
    try:
        if r.status_code == 200:
            return r.json()[0]
        else:
            LOG.error('get_subnet_list_v4 failed: %s %s', r.status_code, getattr(r, 'text', ''))
            return None
    except Exception:
        LOG.exception('Failed to parse get_subnet_list_v4 response: %s', getattr(r, 'text', None))
        return None


def get_subnet_list_v6(start_addr,sitename,subnetpool_name):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_block6_subnet6_list')

    data['WHERE'] = "subnet_level='1' AND site_name='" + sitename +"' AND parent_subnet6_name='"+subnetpool_name+"'"

    if start_addr:
        start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
        data['WHERE'] += "AND start_ip6_addr='"+start_addr_hexa+"'"

    r = _req('GET', url, headers=headers, params=data)
    if r.status_code == 200:
        return r.json()[0]
    else:
        return None



def get_block_subnet_list_v4(start_addr,sitename,name):
    data=dict()
    start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
    url,headers = request_builder.requestBuilder.buildRequest('ip_block_subnet_list')
    data['WHERE'] = "subnet_level='0' AND site_name='" + sitename +"' AND start_ip_addr='"+ \
            start_addr_hexa+"' AND subnet_name='"+name+"'"


    r = _req('GET', url, headers=headers, params=data)
    LOG.debug('get_block_subnet_list_v4 URL: %s', getattr(r, 'url', url))
    try:
        if r.status_code == 200:
            r_json = r.json()
            block_id = r_json[0]['subnet_id']
        elif r.status_code == 204:
            # No content, which means the block does not exist
            block_id = None
        else:
            LOG.error('get_block_subnet_list_v4 failed: %s %s', r.status_code, getattr(r, 'text', ''))
            block_id = None
    except Exception:
        LOG.exception('Failed to parse get_block_subnet_list_v4 response: %s', getattr(r, 'text', None))
        block_id = None

    return block_id




def get_block_subnet_list_v6(start_addr,sitename,name):
    data=dict()
    start_addr_hexa = hex(netaddr.IPAddress(start_addr))[2:]
    url,headers = request_builder.requestBuilder.buildRequest('ip6_block6_subnet6_list')
    data['WHERE'] = "subnet_level='0' AND site_name='" + sitename +"' AND start_ip6_addr='"+\
            start_addr_hexa+"' AND subnet6_name='"+name+"'"

    r = _req('GET', url, headers=headers, params=data)
    LOG.debug('get_block_subnet_list_v6 URL: %s', getattr(r, 'url', url))
    try:
        if r.status_code == 200:
            r_json = r.json()
            block_id = r_json[0]['subnet6_id']
        elif r.status_code == 204:
            # No content, which means the block does not exist
            block_id = None
        else:
            LOG.error('get_block_subnet_list_v6 failed: %s %s', r.status_code, getattr(r, 'text', ''))
            block_id = None
    except Exception:
        LOG.exception('Failed to parse get_block_subnet_list_v6 response: %s', getattr(r, 'text', None))
        block_id = None


    return block_id




def create_block_subnet_v4(start_addr,prefix,site_name,subnet_block_name):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip_subnet_add')
    data['subnet_addr'] = str(start_addr)
    data['subnet_prefix'] = prefix
    data['subnet_level'] = 0
    data['subnet_name'] = subnet_block_name
    data['site_name'] = site_name

    r = _req('POST', url, headers=headers, json=data)

    if r.status_code == 201:
        r_json = r.json()
        return r_json[0]['ret_oid']
    else:
        return None



def create_block_subnet_v6(start_addr,prefix,site_name,subnet_block_name):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_add')
    data['subnet6_addr'] = start_addr
    data['subnet6_prefix'] = prefix
    data['subnet_level'] = 0
    data['subnet6_name'] = subnet_block_name
    data['site_name'] = site_name

    r = _req('POST', url, headers=headers, json=data)

    if r.status_code == 201:
        r_json = r.json()
        return r_json[0]['ret_oid']
    else:
        return None




def get_free_subnet_v4(block_id,prefixlen):
    # block_id : id returned by get_block_subnet_list_v4 or create_block_subnet_v4
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip_find_free_subnet')
    data['WHERE'] = "block_id='"+block_id+"'"
    data['prefix'] = prefixlen
    r = _req('GET', url, headers=headers, params=data)
    LOG.debug('get_free_subnet_v4 URL: %s', getattr(r, 'url', url))
    LOG.debug('get_free_subnet_v4 status: %s', r.status_code)
    try:
        if r.status_code == 200:
            r_json = r.json()
            startAddr = netaddr.IPAddress('0x'+str(r_json[0]['start_ip_addr']))
            return netaddr.IPNetwork(str(startAddr)+'/'+str(prefixlen))
        else:
            LOG.error('get_free_subnet_v4 failed: %s %s', r.status_code, getattr(r, 'text', ''))
            return None
    except Exception:
        LOG.exception('Failed to parse get_free_subnet_v4 response: %s', getattr(r, 'text', None))
        return None


def get_free_subnet_v6(block_id,prefixlen):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_find_free_subnet6')
    data['WHERE'] = "block6_id='"+block_id+"'"
    data['prefix'] = prefixlen
    r = _req('GET', url, headers=headers, params=data)

    if r.status_code == 200:
        r_json = r.json()
        startAddr = netaddr.IPAddress(add_columns(str(r_json[0]['start_ip6_addr'])))
        return netaddr.IPNetwork(str(startAddr)+'/'+str(prefixlen))

    else:
        return None


def create_subnet_v4(block_id,subnet_name=None,start_addr=None,prefix=0):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip_subnet_add')
    data['subnet_level']=1
    data['subnet_addr'] = str(netaddr.IPAddress(start_addr))
    data['subnet_prefix'] = prefix
    if subnet_name is not None:
        data['subnet_name'] = subnet_name
    data['parent_subnet_id'] = block_id

    r = _req('POST', url, headers=headers, json=data)
    if r.status_code == 201:
        r_json = r.json()
        return r_json[0]['ret_oid']
    else:
        return None

def create_subnet_v6(block_id,subnet_name=None,start_addr=None,prefix=0):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_add')
    data['subnet_level']=1
    data['subnet6_addr'] = str(netaddr.IPAddress(start_addr))
    data['subnet6_prefix'] = prefix
    if subnet_name is not None:
        data['subnet6_name'] = subnet_name
    data['parent_subnet6_id'] = block_id
    r = _req('POST', url, headers=headers, json=data)
    LOG.error(r.url)
    LOG.error(str(data))
    if r.status_code == 201:
        r_json = r.json()
        return r_json[0]['ret_oid']
    else:
        return None


def delete_block_subnet_v4(sitename,subnet_addr,subnet_prefix):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip_subnet_delete')
    data['subnet_level']=0
    data['site_name'] = sitename
    data['subnet_addr'] = str(netaddr.IPAddress(subnet_addr))
    data['subnet_prefix'] = subnet_prefix

    r = requests.delete(url,headers=headers,json=data,verify=False)

    if r.status_code == 200:
        return 1
    else:
        return None

def delete_block_subnet_v6(sitename,subnet_addr,subnet_prefix):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_delete')
    data['subnet_level'] = 0
    data['site_name'] = sitename
    data['subnet6_addr'] = str(netaddr.IPAddress(subnet_addr))
    data['subnet6_prefix'] = subnet_prefix

    r = requests.delete(url,headers=headers,json=data,verify=False)

    if r.status_code == 200:
        return 1
    else:
        return None



def delete_subnet_v4(sitename,subnet_addr,subnet_prefix):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip_subnet_delete')
    data['subnet_level'] = 1
    data['site_name'] = sitename
    data['subnet_addr'] = str(netaddr.IPAddress(subnet_addr))
    data['subnet_prefix'] = subnet_prefix

    r = requests.delete(url,headers=headers,json=data,verify=False)

    if r.status_code == 200:
        return 1
    else:
        return None


def delete_subnet_v6(sitename,subnet_addr,subnet_prefix):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_delete')
    data['subnet_level'] = 1
    data['site_name'] = sitename
    data['subnet6_addr'] = str(netaddr.IPAddress(subnet_addr))
    data['subnet6_prefix'] = subnet_prefix

    r = requests.delete(url,headers=headers,json=data,verify=False)

    if r.status_code == 200:
        return 1
    else:
        return None


def rename_subnet_v4(subnet_id,subnet_new_name):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip_subnet_add')
    data['subnet_id'] = subnet_id
    data['subnet_name'] = subnet_new_name

    r = requests.put(url,headers=headers,json=data,verify=False)

def rename_subnet_v6(subnet_id,subnet_new_name):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_subnet6_add')
    data['subnet6_id'] = subnet_id
    data['subnet6_name'] = subnet_new_name

    r = requests.put(url,headers=headers,json=data,verify=False)

def create_allocation_pool_v4(subnet_id,start_addr,end_addr):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip_pool_add')
    data['subnet_id'] = subnet_id
    data['start_addr'] = str(netaddr.IPAddress(start_addr))
    data['end_addr'] = str(netaddr.IPAddress(end_addr))
    r = _req('POST', url, headers=headers, json=data)

    if r.status_code == 201:
        return 1
    else:
        LOG.error(str(r.__dict__))
        return None


def create_allocation_pool_v6(subnet_id,start_addr,end_addr):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip6_pool6_add')
    data['subnet6_id'] = subnet_id
    data['start_addr'] = str(netaddr.IPAddress(start_addr))
    data['end_addr'] = str(netaddr.IPAddress(end_addr))
    r = requests.post(url,headers=headers,json=data,verify=False)

    if r.status_code == 201:
        return 1
    else:
        return None


def delete_allocation_pool_v4(subnet_id,start_addr,end_addr):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip_pool_delete')
    data['subnet_id'] = str(subnet_id)
    data['start_addr'] = str(netaddr.IPAddress(start_addr))
    data['end_addr']   = str(netaddr.IPAddress(end_addr))
    r = _req('DELETE', url, headers=headers, json=data)

    if r.status_code == 200:
        return 1
    else:
        LOG.error(str(r.__dict__))
        return None



def delete_allocation_pool_v6(subnet_id,start_addr,end_addr):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip6_pool6_delete')
    data['subnet6_id'] = subnet_id
    data['start_addr'] = str(netaddr.IPAddress(start_addr))
    data['end_addr']   = str(netaddr.IPAddress(end_addr))
    r = requests.delete(url,headers=headers,json=data,verify=False)

    if r.status_code == 200:
        return 1
    else:
        return None


def get_allocation_pool_list_v4(subnet_id):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip_pool_list')
    data['WHERE'] = "subnet_id='"+subnet_id+"'"
    r = _req('GET', url, headers=headers, params=data)

    if r.status_code == 200:
        r_json = r.json()
    else:
        r_json = []
        ## NO pools associated

    return r_json


def get_allocation_pool_list_v6(subnet_id):
    data=dict()
    url, headers = request_builder.requestBuilder.buildRequest('ip6_pool6_list')
    data['WHERE'] = "subnet6_id='"+subnet_id+"'"
    r = _req('GET', url, headers=headers, params=data)

    if r.status_code == 200:
        r_json = r.json()
    else:
        r_json = []
        ## NO pools associated

    return r_json




def allocate_address_v4(sitename,address,name,mac):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip_add')
    data['hostaddr'] = str(netaddr.IPAddress(address))
    data['site_name'] = sitename
    if name != '':
        data['name'] = name
    if mac != '':
        data['mac_addr'] = mac

    r = _req('POST', url, headers=headers, json=data)

    if r.status_code == 201:
        return 1
    else:
        return None

def allocate_address_v6(sitename,address,name,mac):
    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_address6_add')
    data['hostaddr'] = str(netaddr.IPAddress(address))
    data['site_name'] = sitename
    if name != '':
        data['ip6_name'] = name
    if mac != '':
        data['ip6_mac_addr'] = mac

    r = requests.post(url,headers=headers,json=data,verify=False)

    if r.status_code == 201:
        return 1
    else:
        return None


def get_free_address_v4(subnetId):
    # subnetId : returned from a previous call to get_subnet_list_v4

    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip_find_free_address')
    data['subnet_id'] = subnetId

    r = requests.get(url,headers=headers,params=data,verify=False)
    try:
        return r.json()[0]['hostaddr']
    except Exception:
        LOG.exception('Failed to parse get_free_address_v4 response: %s', getattr(r, 'text', None))
        return None


def get_free_address_v6(subnetId):
    # subnetId : returned from a previous call to get_subnet_list_v6

    data=dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_find_free_address6')
    data['subnet6_id'] = subnetId

    r = requests.get(url,headers=headers,params=data,verify=False)
    try:
        return r.json()[0]['hostaddr6']
    except Exception:
        LOG.exception('Failed to parse get_free_address_v6 response: %s', getattr(r, 'text', None))
        return None


def deallocate_address_v4(sitename,address):
    data = dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip_delete')
    data['site_name'] = sitename
    data['hostaddr']  = str(address)

    r = _req('DELETE', url, headers=headers, json=data)
    if r.status_code == 200:
        return 1

    else:
        return None



def deallocate_address_v6(sitename,address):
    data = dict()
    url,headers = request_builder.requestBuilder.buildRequest('ip6_address6_delete')
    data['site_name'] = sitename
    data['hostaddr']  = str(address)

    r = _req('DELETE', url, headers=headers, json=data)
    if r.status_code == 200:
        return 1

    else:
        return None


# ---------------------------------------------------------------------------
# API probe helpers
# ---------------------------------------------------------------------------
ENDPOINT_PROBES = [
    'ip_site_list', 'ip_site_add', 'ip_site_delete',
    'ip_block_subnet_list', 'ip6_block6_subnet6_list',
    'ip_subnet_add', 'ip6_subnet6_add', 'ip_subnet_delete', 'ip6_subnet6_delete',
    'ip_find_free_subnet', 'ip6_find_free_subnet6',
    'ip_pool_add', 'ip6_pool6_add', 'ip_pool_delete', 'ip6_pool6_delete',
    'ip_pool_list', 'ip6_pool6_list',
    'ip_add', 'ip6_address6_add', 'ip_delete', 'ip6_address6_delete',
    'ip_find_free_address', 'ip6_find_free_address6'
]


def verify_api_endpoints(queries=None, timeout=5):
    """Probe the SolidServer endpoints used by this module.

    This helper attempts a simple GET request to each named endpoint and
    records the HTTP status or exception. It cannot determine precise
    parameter requirements for RPC endpoints, but it gives a quick view of
    which REST/RPC paths exist and respond on the configured SolidServer.

    Returns a dict: { query_name: { 'ok': bool, 'status': int|None, 'reason': str } }
    """
    if queries is None:
        queries = ENDPOINT_PROBES

    results = {}
    for q in queries:
        try:
            url, headers = request_builder.requestBuilder.buildRequest(q)
        except Exception as e:
            results[q] = {'ok': False, 'status': None, 'reason': f'buildRequest failed: {e}'}
            continue

        try:
            r = _req('GET', url, headers=headers, timeout=timeout)
            status = getattr(r, 'status_code', None)
            # Treat common positive responses (200,201,204) and "method not allowed"
            # or auth failures as evidence the endpoint exists (405/401/403).
            ok = status in (200, 201, 204, 401, 403, 405)
            results[q] = {'ok': ok, 'status': status, 'reason': None}
        except Exception as e:
            results[q] = {'ok': False, 'status': None, 'reason': str(e)}

    return results


def print_api_probe_report(results, out=LOG.info):
    """Pretty-print the probe results using provided output callable.

    `out` defaults to LOG.info but can be any callable like print.
    """
    for q, info in results.items():
        if info['ok']:
            out('OK   %-30s status=%s', q, info['status'])
        else:
            out('FAIL %-30s status=%s reason=%s', q, info['status'], info['reason'])

