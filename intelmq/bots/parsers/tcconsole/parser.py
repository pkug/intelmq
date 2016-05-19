# -*- coding: utf-8 -*-

import sys
import csv
from io import StringIO
from itertools import dropwhile

from intelmq.lib import utils
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event


class TCConsoleParserBot(Bot):

    def process(self):
        report = self.receive_message()

        self.columns = {
            "# timestamp": None,
            "ip": "source.ip",
            "asn": "source.asn",
            "old_category": None,
            "malware": "classification.identifier",
            "geoip": None,
            "comment": None,
            "addtime": None,
            "category": None,
            "rir": None,
            "cc": "source.geolocation.country",
            "loadindex": None,
            "dstip": "destination.ip",
            "srcport": "source.port",
            "dstport": "destination.port",
        }

        self.categories = {
            "bots": "botnet drone",
            # TODO: more types ?
        }


        raw_report = utils.base64_decode(report.value("raw"))

        for row in csv.DictReader(StringIO(raw_report),
                                  delimiter="\t"):

            # Skip unknown categories
            if row['old_category'] not in self.categories:
                continue

            event = Event(report)

            # Iterate through mapped fields sanitizing them if needed
            for key, field in self.columns.items():

                if not field:
                    continue

                event.add(field, row[key], sanitize=True)

            event.add('classification.type',
                      self.categories[row['old_category']])
            event.add('time.source', row['# timestamp'] + ' UTC', sanitize=True)
            event.add("raw", ",".join(row), sanitize=True)

            self.logger.debug('event -> %r', event)

            self.send_message(event)

        self.acknowledge_message()


if __name__ == "__main__":
    bot = TCConsoleParserBot(sys.argv[1])
    bot.start()
