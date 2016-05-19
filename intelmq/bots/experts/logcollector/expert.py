# -*- coding: utf-8 -*-
"""
Finds a contact in a WHOIS database and collects logs using external command
according to the policy.

New event fields added: contact, logs
"""

import sys
import subprocess

import pytz

from dateutil.parser import parse as date_parse

from intelmq.lib.bot import Bot
from intelmq.lib.harmonization import IPAddress

class LogCollectorExpertBot(Bot):

    def init(self):
        # self.parameters.whois_server
        # self.parameters.log_collect_cmd
        # self.parameters.timezone
        pass

    def process(self):
        event = self.receive_message()

        srcip = event.value("source.ip")

        # query WHOIS database (FIXME: pythonize)
        whoiscmd = "whois -h " + self.parameters.whois_server + " " + \
                srcip + " | egrep 'e-mail:' | uniq | cut -d ':' -f 2 | xargs "

        # execute the pipeline and get stdout
        emails = subprocess.Popen(whoiscmd, shell=True,
                               stdout=subprocess.PIPE).communicate()[0]

        # get first contact
        requestor = emails.decode().partition(" ")[0].strip("\n")

        if not requestor:
            self.logger.error("E-mail not found for for the address: %r (%r)",
                              srcip, self.parameters.whois_server)
            self.acknowledge_message()
            return

        # add contact field
        event.add("contact", requestor)

        # skip according to log_policy:
        # -----------------------------
        # nologs: no logs are collected (DEFAULT)
        # required: logs are required to process the event further
        # normal: event is processed even if logs are not collected

        log_policy = event.get("log_policy", "nologs")

        if log_policy == "nologs":
            self.send_message(event)
            self.acknowledge_message()
            return

        # source/destination ip is missing
        if not (event.contains("destination.ip") and \
                event.contains("source.ip")):
            self.logger.error("Can't collect logs, "
                              "source.ip or destination.ip is missing for "
                              "event: %r", event)
            self.send_message(event)
            self.acknowledge_message()
            return

        # Date
        tm = date_parse(event.value("time.source"))

        # make sure we use default UTC timezone
        # if source/sanitizer didn't specify that, and that our date
        # is localized (contains tz info)
        if not tm.tzinfo:
            tm = pytz.timezone(pytz.utc).localize(tm)

        # convert to our timezone and get date period
        ttz = pytz.timezone(self.parameters.timezone)
        tm = tm.astimezone(ttz)

        # build filter
        args = event.value("source.ip")
        args += ":{}".format(event.value("source.port")) if event.contains("source.port") else ""
        args += " "
        args += event.value("destination.ip")
        args += ":{}".format(event.value("destination.port")) if event.contains("destination.port") else ""

        args += " " + tm.strftime("%Y-%m-%d %H:%M")

        logcmd = "{} {}".format(self.parameters.log_collect_cmd, args)

        self.logger.info("Collecting logs: %s", logcmd)

        # FIXME: handle process exit codes
        sp = subprocess.Popen(logcmd, shell=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        out, err = sp.communicate()

        if sp.returncode != 0:
            self.logger.info("Process exit status %r != 0, out: %s, err: %s",
                              sp.returncode, out, err)

        event.add("logs", out.decode())

        self.send_message(event)
        self.acknowledge_message()


if __name__ == "__main__":
    bot = LogCollectorExpertBot(sys.argv[1])
    bot.start()
