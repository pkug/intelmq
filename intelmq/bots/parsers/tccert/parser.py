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

    def bots(self, event, comments):
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
        return True

    def process(self):
        report = self.receive_message()

        self.columns = OrderedDict()
        self.columns['report'] = None
        self.columns['ip'] = 'source.ip'
        self.columns['asn'] = 'source.asn'
        self.columns['timestamp'] = None
        self.columns['comments'] = None
        self.columns['asn_name'] = None

        self.categories = {
            "bots": ("botnet drone", self.bots),
        }

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

            if row['report'] not in self.categories and not \
                    self.categories[row['report']][1](event, row['comments']):
                continue

            event.add('classification.type',
                      self.categories[row['report']][0])
            event.add('time.source', row['timestamp'] + ' UTC', sanitize=True)
            event.add("raw", ",".join(row), sanitize=True)

            self.logger.debug('event -> %r', event)

            self.send_message(event)

        self.acknowledge_message()


if __name__ == "__main__":
    bot = TCConsoleParserBot(sys.argv[1])
    bot.start()
