# -*- coding: utf-8 -*-
"""
Generic parser for mapping a line to selected field discarding comments (#).

Handy for parsing various blocklist sets.
"""

import sys

import dateutil

from ipaddress import ip_network

from intelmq.lib import utils
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event


class GenericIPlistParserBot(Bot):

    def init(self):
        #self.parameters.direction
        #self.parameters.clstype
        pass

    def process(self):
        report = self.receive_message()

        raw_report = utils.base64_decode(report.get("raw"))

        for row in raw_report.splitlines():

            row = row.strip()

            if row.startswith("#") or len(row) == 0:
                continue

            event = Event(report)

            ipn = ip_network(row)
            subkey = ".ip" if ipn.num_addresses == 1 else ".network"

            event.add(self.parameters.direction + subkey, row)
            event.add('classification.type', self.parameters.clstype)

            self.send_message(event)
        self.acknowledge_message()


if __name__ == "__main__":
    bot = GenericIPlistParserBot(sys.argv[1])
    bot.start()
