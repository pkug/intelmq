# -*- coding: utf-8 -*-
import sys
import os
import json
import gzip

import dateutil.parser

from intelmq.lib.bot import Bot
from intelmq.lib import utils

def dotdictcopy(srcd, dstd, key):
    "Copies nested dictionary keys using dot notation."
    subdict, *rem = key.split(".", 1)
    if rem:
        if subdict not in srcd:
            return
        if subdict not in dstd:
            dstd[subdict] = {}
        dotdictcopy(srcd[subdict], dstd[subdict], rem[0])
    elif key in srcd:
        dstd[key] = srcd[key]

def dictvals(d):
    "Iterate through nested dict values in order (sorted by keys)."
    for key, val in sorted(d.items()):
        if isinstance(val, dict):
            for subval in dictvals(val):
                yield subval
        else:
            yield val


class HistoryBot(Bot):

    TIMEFMT = "%Y%m%d%H%M"

    def init(self):
        if not os.path.isdir(self.parameters.dir):
            self.logger.error("Directory %s does not exist",
                              self.parameters.dir)
            self.stop()
        self.dirname = self.parameters.dir
        try:
            self.items = int(self.parameters.items)
        except ValueError:
            self.logger.error("items parameter must be an integer")
        self.fields = [x.strip() for x in \
                       str(self.parameters.fields).split(",") if x]
        #self.parameters.tsv

    def process(self):
        event = self.receive_message()

        ed = event.to_dict()

        dt = dateutil.parser.parse(ed['time']['observation'])
        feed = ed['feed']['name']

        feeddir = os.path.join(self.dirname, feed)
        if not os.path.exists(feeddir):
            os.mkdir(feeddir)
        event_dict = {}

        if self.fields:
            for key in self.fields:
                dotdictcopy(ed, event_dict, key)
        else:
            event_dict = ed

        if self.parameters.tsv:
            event_data = ",".join(val for val in dictvals(event_dict))
        else:
            event_data = utils.decode(json.dumps(event_dict, ensure_ascii=False))

        # TODO: better idiom
        if self.parameters.gzip:
            filename = os.path.join(feeddir,
                              "{}.txt.gz".format(dt.strftime(self.TIMEFMT)))
            with gzip.open(filename, 'a') as f:
                f.write(bytes(event_data + '\n', 'UTF-8'))

        else:
            filename = os.path.join(feeddir, "{}.txt".format(dt.strftime(self.TIMEFMT)))
            with open(filename, 'a') as f:
                f.write(event_data + '\n')


        # Rotate expired archives

        # XXX: plain sorting, careful with the dates (TIMEFMT)
        dirlist = sorted(os.listdir(feeddir))
        for expfn in dirlist[:max(len(dirlist)-self.items, 0)]:
            exppath = os.path.join(feeddir, expfn)
            os.remove(exppath)
            self.logger.info("Expired archive %s removed", exppath)

        self.acknowledge_message()


if __name__ == "__main__":
    bot = HistoryBot(sys.argv[1])
    bot.start()
