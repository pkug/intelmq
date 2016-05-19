# -*- coding: utf-8 -*-

import sys
import re

from intelmq.lib.bot import Bot

# XXX: requires tldextract module
from tldextract import extract as tldextract


regexs = []
fqdns = set()

def load_file(filename):
    with open(filename) as f:
        for line in f:
            if line.startswith("/"):
                regexs.append(line[1:])
            else:
                fqdns.add(line)

class DomainMatchBot(Bot):

    def init(self):

        self.logger.info("Starting bot")

        load_file(self.parameters.configfile)

        if self.parameters.srcdest not in ("source", "destination", "both"):
            self.logger.error("parameter srcdest != source|destination|both")
            return


        self.logger.info("Domain file loaded")

        self.match = { "source": ["source"],
                       "destination": ["destination"],
                       "both": ["source", "destination"] }

    def process(self):
        event = self.receive_message()

        # Add FQDNs
        domains = { event.value(f + '.fqdn') for f in \
                   self.match[self.parameters.srcdest] if \
                   event.contains(f + '.fqdn') }

        # Add FQDNs from URLs
        for f in (event.value(f + '.url') for f in \
                  self.match[self.parameters.srcdest] if \
                  event.contains(f + '.url')):
            t = tldextract(f)
            if t.suffix:
                domains.add("{}.{}.{}".format(t.subdomain, t.domain,
                                              t.suffix).strip('.'))

        # Match 'em
        for d in domains:

            if d in fqdns:
                self.logger.debug("Domain %s matched", d)
                self.send_message(event)
                break

            for r in regexs:
                if re.match(r, d, re.IGNORECASE):
                    self.logger.debug("Regex matched")
                    self.send_message(event)
                    self.acknowledge_message()
                    return

        self.acknowledge_message()

if __name__ == "__main__":
    bot = DomainMatchBot(sys.argv[1])
    bot.start()
