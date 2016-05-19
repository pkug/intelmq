# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import sys

from intelmq.lib.bot import Bot


class ReqfieldsBot(Bot):

    def init(self):
        self.parameters.reqfields = [x.strip() for x in \
                                    str(self.parameters.reqfields).split(",") if x]

    def process(self):
        event = self.receive_message()

        for field in self.parameters.reqfields:
            if not event.contains(field):
                self.acknowledge_message()
                return

        self.send_message(event)
        self.acknowledge_message()

if __name__ == "__main__":
    bot = ReqfieldsBot(sys.argv[1])
    bot.start()
