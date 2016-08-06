# -*- coding: utf-8 -*-
"""
"""

import sys
import subprocess
import csv

import pytz

from dateutil.parser import parse as date_parse

from ipaddress import ip_address, ip_network

from intelmq.lib.bot import Bot
from intelmq.lib.harmonization import IPAddress

class CertBTContactExpertBot(Bot):

    def init(self):

        # self.parameters.whois_server
        # self.parameters.contacts_file
        with open(self.parameters.contacts_file) as f:
            reader = csv.reader(f, delimiter=';')
            self.contacts = { row[0]: row[1] for row in reader }


    def process(self):
        event = self.receive_message()

        contact = ''
        srcip = event.value("source.ip")
        whoiscmd = "whois -h " + self.parameters.whois_server + " " + \
                srcip + " | egrep 'e-mail:' | uniq | cut -d ':' -f 2 | xargs "

        for k in self.contacts.keys():
            if ip_address(srcip) in ip_network(k):
                contact = self.contacts[k]

        if not contact:
            emails = subprocess.Popen(whoiscmd, shell=True,
                                   stdout=subprocess.PIPE).communicate()[0]
            contact = emails.decode().partition(" ")[0].strip("\n")

        if not contact:
            self.logger.error("E-mail not found for for the address: %r (%r)",
                              srcip, self.parameters.whois_server)
        else:
            event.add("contact", contact)

        self.send_message(event)
        self.acknowledge_message()


if __name__ == "__main__":
    bot = CertBTContactExpertBot(sys.argv[1])
    bot.start()
