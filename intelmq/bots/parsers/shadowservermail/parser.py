# -*- coding: utf-8 -*-

import sys
import re
import json
import collections
import csv

from io import StringIO
from datetime import datetime

from intelmq.lib import utils
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event
from intelmq.lib.harmonization import FQDN


# Generic
defmapping = {
                'ip': ('source.ip', None),
                'asn': ('source.asn', None),
                'geo': ('source.geolocation.country', None),
                'port': ('source.port', None),
                'hostname': ('source.reverse_dns', None),
             }

def map_event(logger, event, row, mapping=defmapping):
    """Maps fields of row to event object using mapping schema with
    validators."""
    for key, val in row.items():
        if key in mapping:
            if callable(mapping[key][1]) and not mapping[key][1](val):
                logger.info("field not valid: key -> %r, val -> %r", key, val)
            else:
                event.add(mapping[key][0], val, sanitize=True)

# Sinkhole HTTP drone
sinkhole_http_drone_map = dict(defmapping)
sinkhole_http_drone_map.update(
              {
                'type': ('classification.identifier', None),
                'src_port': ('source.port', None),
                'dst_port': ('destination.port', None),
                'http_host': ('destination.fqdn', FQDN.is_valid),
                'dst_ip': ('destination.ip', None),
                'dst_asn': ('destination.asn', None),
                'dst_geo': ('destination.geolocation.country', None),
              })
sinkhole_http_values = { 'classification.type': 'botnet drone' }

# Sandbox URL Report
sandbox_url_map = dict(defmapping)
sandbox_url_map['url'] = ('source.url', None)
sandbox_url_map['host'] = ('source.fqdn', None)
sandbox_url_values = { 'classification.type': 'malware' }
sandbox_url_extra_keys = ['user_agent', 'method', 'md5hash']

# Botnet drone
botnet_drone_map = dict(defmapping)
botnet_drone_map.update(
              {
                'infection': ('classification.identifier', None),
                'port': ('source.port', None),
                'cc_port': ('destination.port', None),
                'cc_dns': ('destination.reverse_dns', None),
                'cc_ip': ('destination.ip', None),
                'cc_asn': ('destination.asn', None),
                'cc_geo': ('destination.geolocation.country', None),
              })
botnet_drone_values = { 'classification.type': 'botnet drone' }

# C&C IP
cc_ip_map = dict(defmapping)
cc_ip_map.pop('hostname')
cc_ip_map.update({ 'domain': ('source.fqdn', FQDN.is_valid) })
cc_ip_values = { 'classification.identifier': 'c&c',
                 'classification.type': 'c&c' }

def cc_ip(event, row):
    event.add("time.source", row['first_seen'] + ' UTC',
              sanitize=True)
    return True


# DNS Openresolver
dns_openresolver_values = { 'classification.identifier': 'openresolver',
                            'classification.type': 'vulnerable service' }

# OpenSNMP
opensnmp_extra_keys = ['sysdesc', 'sysname']
opensnmp_values = { 'classification.identifier': 'opensnmp',
                     'classification.type': 'vulnerable service' }

# OpenIPMI
openipmi_extra_keys = ['none_auth', 'md2_auth', 'md5_auth', 'passkey_auth',
                        'permessage_auth', 'userlevel_auth', 'nulluser',
                        'anon_login', 'productname', 'manufacturername']
openipmi_values = { 'classification.identifier': 'openipmi',
                     'classification.type': 'vulnerable service' }

# OpenNTP
# https://www.rapid7.com/db/vulnerabilities/ntp-clock-variables-disclosure
openntp_values = { 'classification.identifier': 'ntp-readvar',
                            'classification.type': 'vulnerable service' }

# OpenNetBIOS
opennetbios_values = { 'classification.identifier': 'opennetbios',
                       'classification.type': 'vulnerable service' }
opennetbios_extra_keys = ['workgroup', 'machine_name', 'username', 'mac_address']

# OpenSSDP
openssdp_values = { 'classification.identifier': 'openssdp',
                    'classification.type': 'vulnerable service' }
openssdp_extra_keys = ['location', 'header']


# Poodle
ssl_poodle_values = { 'classification.identifier': 'ssl-poodle',
                      'classification.type': 'vulnerable service' }
ssl_poodle_extra_keys = ['handshake', 'cipher_suite', 'ssl_poodle',
                         'cert_length', 'subject_common_name',
                         'cert_expiration_date', 'issuer_common_name']

# Netis router
netis_router_values = { 'classification.identifier': 'netis-router',
                        'classification.type': 'vulnerable service' }
netis_router_extra_keys = ['handshake', 'cipher_suite', 'ssl_poodle',
                           'cert_length', 'subject_common_name',
                           'cert_expiration_date', 'issuer_common_name']

# OpenNATPMP
opennatpmp_values = { 'classification.identifier': 'opennatpmp',
                      'classification.type': 'vulnerable service' }
opennatpmp_extra_keys = ['version', 'opcode', 'uptime', 'external_ip']

# OpenRedis
openredis_values = { 'classification.identifier': 'openredis',
                     'classification.type': 'vulnerable service' }
openredis_extra_keys = ['version', 'mode', 'os', 'architecture', 'process_id',
                         'uptime']

# OpenMemcached
openmemcached_values = { 'classification.identifier': 'openmemcached',
                         'classification.type': 'vulnerable service' }
openmemcached_extra_keys = ['version', 'uptime', 'time', 'curr_connections']

# OpenMssql
openmssql_values = { 'classification.identifier': 'openmssql',
                         'classification.type': 'vulnerable service' }
openmssql_extra_keys = ['version', 'tcp_port', 'server_name', 'instance_name',
                        'amplification']

# OpenMongo
openmongo_values = { 'classification.identifier': 'openmongo',
                     'classification.type': 'vulnerable service' }
openmongo_extra_keys = ['version', 'sysinfo', 'opensslversion',
                        'javascriptengine', 'visible_databases']

# OpenElasticsearch
openes_values = { 'classification.identifier': 'openelasticsearch',
                  'classification.type': 'vulnerable service' }
openes_extra_keys = ['version', 'name', 'cluster_name', 'lucene_version']

# OpenPortmapper
openportmapper_values = { 'classification.identifier': 'openportmapper',
                  'classification.type': 'vulnerable service' }
openportmapper_extra_keys = ['programs', 'mountd_port', 'exports']

class ShadowServerParserBot(Bot):

    def process(self):
        report = self.receive_message()

        if not report or not report.contains("raw"):
            self.acknowledge_message()
            return

        # regex: (mapping, extra_keys, extra_vals, extra_fn)
        dispatch_types = {
                '.*sinkhole_http_drone.*': (sinkhole_http_drone_map, [],
                                            sinkhole_http_values, None),
                '.*microsoft_sinkhole.*': (sinkhole_http_drone_map, [],
                                            sinkhole_http_values, None),
                '.*botnet_drone.*': (botnet_drone_map, [],
                                     botnet_drone_values, None),
                '.*cc_ip.*': (cc_ip_map, [], cc_ip_values, cc_ip),
                '.*dns_openresolver.*': (defmapping, [],
                                         dns_openresolver_values, None),
                '.*scan_ntp.*': (defmapping, [], openntp_values, None),
                '.*scan_snmp.*': (defmapping, opensnmp_extra_keys,
                                  opensnmp_values, None),
                '.*scan_netbios.*': (defmapping, opennetbios_extra_keys,
                                     opennetbios_values, None),
                '.*scan_ssdp.*': (defmapping, openssdp_extra_keys,
                                  openssdp_values, None),
                '.*scan_ssl_poodle.*': (defmapping, ssl_poodle_extra_keys,
                                        ssl_poodle_values, None),
                '.*scan_ipmi.*': (defmapping, openipmi_extra_keys,
                                  openipmi_values, None),
                '.*netis_router.*': (defmapping, netis_router_extra_keys,
                                     netis_router_values, None),
                '.*scan_nat_pmp.*': (defmapping, opennatpmp_extra_keys,
                                     opennatpmp_values, None),
                '.*scan_redis.*': (defmapping, openredis_extra_keys,
                                   openredis_values, None),
                '.*scan_memcached.*': (defmapping, openmemcached_extra_keys,
                                   openmemcached_values, None),
                '.*scan_mssql.*': (defmapping, openmssql_extra_keys,
                                   openmssql_values, None),
                '.*scan_mongo.*': (defmapping, openmongo_extra_keys,
                                   openmongo_values, None),
                '.*scan_elasticsearch.*': (defmapping, openes_extra_keys,
                                   openes_values, None),
                '.*scan_portmapper.*': (defmapping, openportmapper_extra_keys,
                                   openportmapper_values, None),
                '.*cwsandbox_url.*': (sandbox_url_map, sandbox_url_extra_keys,
                                   sandbox_url_values, None),

        }

        raw_report = utils.base64_decode(report.value("raw"))

        handler = None
        for regex, (mapping, keys, vals, fn) in dispatch_types.items():
            if re.match(regex, report['attachment']):
                handler = (mapping, keys, vals, fn)

        if not handler:
            self.logger.error('Unknown handler for %s, consider adding one in '
                              'shadowservermail parser source',
                              report['attachment'])

        for row in csv.DictReader(StringIO(raw_report)):

            event = Event(report)
            send_msg = True

            #self.logger.debug("row -> %r, report['attachment'] -> %r", row, report['attachment'])

            if handler:
                (mapping, keys, vals, fn) = handler
                map_event(self.logger, event, row, mapping)
                event.add('extra', json.dumps({ k: row[k] for k in keys \
                                               if k in row }))
                for k, v in vals.items():
                    event.add(k, v)

                if callable(fn):
                    send_msg = fn(event, row)

            # Add and sanitize fields that are common
            if 'timestamp' in row:
                event.add("time.source", row['timestamp'] + ' UTC',
                          sanitize=True)

            event.add("raw", ",".join(row), sanitize=True)

            if send_msg:
                self.send_message(event)

            self.acknowledge_message()


if __name__ == "__main__":
    bot = ShadowServerParserBot(sys.argv[1])
    bot.start()
