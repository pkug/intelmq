# -*- coding: utf-8 -*-

import sys
import csv
from io import StringIO
from itertools import dropwhile
from collections import OrderedDict

from intelmq.lib import utils
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event


class TCConsoleParserBot(Bot):

    def parse_comments(self, event, comments):
        mapping = {
                'srcport': 'source.port',
                'mwtype': 'classification.identifier',
                'destaddr': 'destination.ip'
        }
        spl = comments.split()
        d = dict(zip(spl[0::2], spl[1::2]))
        for k, v in mapping.items():
            if k in d:
                event.add(v, d[k], sanitize=True)

    def process(self):
        report = self.receive_message()

        self.categories = {
            "beagle": "malware",
            "blaster": "malware",
            "bots": "botnet drone",
            "bruteforce": "brute-force",
            "dameware": "malware",
            "ddosreport": "ddos",
            "defacement": "defacement",
            "dipnet": "malware",
            "fastflux": "malware configuration",
            "malwareurl": "malware configuration",
            "mydoom": "malware",
            "nachi": "malware",
            "openresolvers": "vulnerable service",
            "phatbot": "botnet drone",
            "phishing": "phishing",
            "proxy": "vulnerable service",
            "routers": "compromised",
            "scanners": "scanner",
            "sinit": "malware",
            "slammer": "malware",
            "spam": "spam",
            "spreaders": "dropzone",
            "stormworm": "malware",
            "toxbot": "botnet drone",
        }


        self.columns = OrderedDict()
        self.columns['report'] = None
        self.columns['ip'] = 'source.ip'
        self.columns['asn'] = 'source.asn'
        self.columns['timestamp'] = None
        self.columns['comments'] = None
        self.columns['asn_name'] = None

        raw_report = utils.base64_decode(report.value("raw"))

        for row in csv.DictReader(
                filter(lambda row: row[0] != '#', StringIO(raw_report)),
                delimiter="|",
                fieldnames=self.columns.keys()):

            event = Event(report)

            # Iterate through mapped fields sanitizing them if needed
            for key, field in self.columns.items():

                if not field:
                    continue

                event.add(field, row[key], sanitize=True)


            self.parse_comments(event,row['comments'])
            ctype = self.categories[row['report']] if row['report'] in self.categories \
            else 'report'

            event.add('classification.type', ctype)
            event.add('extra', { 'extra': row['comments']}, sanitize=True)
            event.add('time.source', row['timestamp'] + ' UTC', sanitize=True)
            event.add("raw", ",".join(row), sanitize=True)

            self.logger.debug('event -> %r', event)

            self.send_message(event)

        self.acknowledge_message()


if __name__ == "__main__":
    bot = TCConsoleParserBot(sys.argv[1])
    bot.start()
