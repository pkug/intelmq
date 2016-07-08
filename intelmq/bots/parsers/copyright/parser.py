# -*- coding: utf-8 -*-

import sys
import re
import time
import json

from xml.etree import ElementTree as ET
from xml.etree.ElementTree import ParseError

from dateutil.parser import parse as parsetime

from intelmq.lib import utils
from intelmq.lib.bot import Bot
from intelmq.lib.message import Event
from intelmq.lib.harmonization import FQDN


class CopyrightParserBot(Bot):

    def process(self):
        report = self.receive_message()

        # E-mail contents ...
        raw = utils.base64_decode(report.value("raw"))

        xmlstr = re.search("\<\?xml .*\<\/Infringement\>", raw, re.DOTALL)

        # FIXME: do we need this?
        if xmlstr is None:
            self.logger.error("Failed to extract XML part")
            self.acknowledge_message()
            return

        # XXX: clean up the Infringement tag
        xmlsan = re.sub('<Infringement.*>', '<Infringement>', xmlstr.group(0))

        try:
            root = ET.fromstring(xmlsan)
        except ParseError as e:
            self.logger.error("Parser error")
            self.acknowledge_message()
            return

        # Find and fill required harmonization fields
        ip = root.find(".//Source/IP_Address").text
        port = root.find(".//Source/Port").text
        proto = root.find(".//Source/Type").text

        tm = parsetime(root.find(".//Source/TimeStamp").text)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", tm.utctimetuple())

        event = Event(report) 
        event.add('time.source', timestamp, sanitize=True)
        event.add('source.ip', ip, sanitize=True)
        event.add('source.port', port, sanitize=True)
        event.add('classification.identifier', proto, sanitize=True)
        event.add('classification.type', 'piracy')

        items = {}
        content = root.find(".//Content")

        for n, item in enumerate(content):
            items[n] = { e.tag: e.text for e in item }

        event.add('extra', items)

        self.send_message(event)
        self.acknowledge_message()


if __name__ == "__main__":
    bot = CopyrightParserBot(sys.argv[1])
    bot.start()
