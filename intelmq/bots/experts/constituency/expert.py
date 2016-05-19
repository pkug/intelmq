# -*- coding: utf-8 -*-

import sys

from ipaddress import ip_address, ip_network

from intelmq.lib.bot import Bot


class ConstituencyBot(Bot):

    def init(self):

        # Initialize parameters
        self.parameters.ipranges = [x.strip() for x in \
                                    str(self.parameters.ipranges).split(",") \
                                    if x]
        self.parameters.asns = [x.strip() for x in \
                                str(self.parameters.asns).split(",") if x]
        self.parameters.ipexcept = [x.strip() for x in \
                                    str(self.parameters.ipexcept).split(",") \
                                    if x]

        self.logger.info("Starting bot, ipranges -> %r, asns -> %r, ",
                         self.parameters.ipranges, self.parameters.asns)

        if not (self.parameters.srcdest == "source" or
                self.parameters.srcdest == "destination" or
                self.parameters.srcdest == "both"):
            self.logger.warn("No srcdest parameter found.")
            self.stop()

        # Fields to match
        self.ipfields = { 'source': ['source.ip'],
                          'destination': ['destination.ip'],
                          'both': ['source.ip', 'destination.ip'] }
        self.asnfields = { 'source': ['source.asn'],
                           'destination': ['destination.asn'],
                           'both': ['source.asn', 'destination.asn'] }

    def process(self):
        event = self.receive_message()

        ipfields = [field for field in self.ipfields[self.parameters.srcdest] \
                    if event.contains(field)]
        asnfields = [field for field in self.asnfields[self.parameters.srcdest] \
                     if event.contains(field)]

        # Skip blacklisted IPs or ranges
        for iprange in self.parameters.ipexcept:
            for ipf in (event.value(ipfield) for ipfield in ipfields):
                if ip_address(ipf) in ip_network(iprange):
                    self.logger.debug("Blacklisted IP %s, ignoring", ipf)
                    self.acknowledge_message()
                    return

        # ASNs
        for asn in self.parameters.asns:
            for asnf in (event.value(asnfield) for asnfield in asnfields):
                if str(asnf) == asn:
                    self.logger.debug("ASN %s matched", asnf)
                    self.send_message(event)
                    self.acknowledge_message()
                    return

        # IPs
        for iprange in self.parameters.ipranges:
            for ipf in (event.value(ipfield) for ipfield in ipfields):
                if ip_address(ipf) in ip_network(iprange):
                    self.logger.debug("IP %s matched", ipf)
                    self.send_message(event)
                    self.acknowledge_message()
                    return

        self.acknowledge_message()

if __name__ == "__main__":
    bot = ConstituencyBot(sys.argv[1])
    bot.start()
