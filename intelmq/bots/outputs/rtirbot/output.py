# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from collections import OrderedDict

import sys
import subprocess
import itertools
import pytz

from datetime import timedelta
from dateutil.parser import parse as date_parse

from . import rt

from intelmq.lib.bot import Bot

# FIXME: maybe move this to a separate configuration file (mapping)
field_mapping = OrderedDict()
field_mapping["classification.identifier"] = "tipas"
field_mapping["time.source"] = "laikas"
field_mapping["source.ip"] = "src ip"
field_mapping["source.port"] = "src port"
field_mapping["destination.ip"] = "dst ip"
field_mapping["destination.port"] = "dst port"
field_mapping["destination.geolocation.country"] = "dst šalis"
field_mapping["destination.reverse_dns"] = "dst reverse DNS"
field_mapping["contact"] = "kontaktas"
field_mapping["extra"] = "papildoma info"


class RtirBot(Bot):

    def init(self):

        # self.parameters.rt_url
        # self.parameters.rt_user
        # self.parameters.rt_password
        # self.parameters.rt_template_dir
        # self.parameters.rt_use_templates
        # self.parameters.rt_inv_frequency

        # TODO: self.parameters.rt_requestor
        self.rt_requestor = ""

        # Create RT Client
        self.logger.info("Connecting to RT %s" % self.parameters.rt_url)
        self.rt_client = rt.RtClient(self.parameters.rt_url,
                                     self.parameters.rt_user,
                                     self.parameters.rt_password,
                                     self.logger)
        self.logger.info("Connected to RT")

        # Create RT Workflow automator
        self.rt_wf = rt.RtirWorkflow(self.rt_client,
                                     self.parameters.rt_template_dir)

    def process(self):
        event = self.receive_message()

        # Required fields in the event to proceed
        reqfields = ('rtir.classification', 'rtir.template',
                     'rtir.subject', 'source.ip', 'classification.identifier')

        if not all(event.contains(field) for field in reqfields):
            self.logger.error("Missing one of required fields (%r) for "
                              "event: %r", reqfields, event)
            self.acknowledge_message()
            return

        # Process RT ticket
        self.write_to_rt_ticket(event)

        self.acknowledge_message()

    def write_to_rt_ticket(self, event):

        templatefn = event.value("rtir.template")
        srcip = event.value("source.ip")

        # Ticket contents
        line = ""
        line_list = []

        logs_missing = False

        # Iterate through mapped keys and add them
        for key in field_mapping.keys():

            if key in event:
                line_list.append("{}: {} ".format(field_mapping[key],
                                                  event.value(key)))

        # Format and append logs
        logs = event.get("logs", "")

        # Log policy
        if not logs and event.get("log_policy", "") == "required":
            logs = "LOGS NOT FOUND"
            logs_missing = True

        for l in logs.split("\n"):
            line += "{} \n ".format(l)

        # Format ticket contents
        line += " \n "
        line += " \n ".join(line_list)

        # Create an empty ticket and populate with AH event data
        ticket = rt.RtIncidentReport()

        ticket.reported_ip = srcip
        ticket.status = "open"
        ticket.owner = "nobody"
        ticket.content = line
        ticket.cf_classification = event.value("rtir.classification")
        ticket.cf_inctype = event.get("rtir.inc_type", "")

        # XXX: use templatefn as description but not subject
        ticket.description = templatefn

        ticket.subject = event.value("rtir.subject") % \
            { 'type': event.value("classification.identifier"),
              'ip': srcip,
              'template': event.value("rtir.template") }

        # Get contact
        requestor = event.get('contact', '')

        # Required by RT then create the ticket.
        ticket_params = ticket.create_ticket_params()

        self.logger.info("Creating a ticket: %r", ticket_params)
        ticket.ticket_id = self.rt_client.create_ticket(ticket_params)

        # RTIR workflow automation.
        # If no parent ticket (incident) exists create a new
        # incident and link to it. If an open incident exists
        # link the new ticket.
        if not ticket.ticket_id:
            self.logger.info("Could not write events to RT")
            return

        self.logger.info("RT Events written to ticket (#%d)", ticket.ticket_id)
        parent_id, ticket_created, created_by_ah = \
            self.rt_wf.link_or_create_and_link_parent(ticket,
                                                      ticket.description)

        if parent_id:
            if ticket_created:
                self.logger.info("RT created parent ticket (#%d)",
                              parent_id)
            else:
                self.logger.info("RT linked parent ticket (#%d)",
                              parent_id)
        else:
            self.logger.info("RT Linking/creation of " +
                          "parent ticket failed")
            return

        if logs_missing:
            self.logger.info("Required logs not found for IR %r, only linking "
                             "to incident (#%d)", ticket.ticket_id, parent_id)
            return

        # Created my intelmq
        # FIXME: change this to "intelmq" someday...
        if created_by_ah:
            self.logger.info("Ticket generated by AH, updating incident (#%d)",
                             parent_id)
            self.rt_wf.create_and_link_investigation(
                requestor, self.parameters.rt_use_templates,
                parent_id, [ticket.ticket_id], templatefn,
                self.parameters.rt_inv_frequency)
        else:
            self.logger.info("Incident manually updated "
                             "(AbuseHelperCheck!='Yes'), only linking (#%d)",
                             parent_id)


if __name__ == "__main__":
    bot = RtirBot(sys.argv[1])
    bot.start()
