# -*- coding: utf-8 -*-
import os
import re
import codecs
import os.path as osp

from urllib import request as urllib2
from http.cookiejar import LWPCookieJar
from collections import defaultdict
from datetime import date, datetime, timedelta
from http.client import BadStatusLine
from urllib.parse import urlencode, quote

from dateutil.parser import parse as date_parse

# XXX: keeping this global for now :(
logger = None

def relative_path(*path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), *path)

class RtClient:
    def __init__(self, url, user, password, log):

        # XXX: dirty
        global logger
        logger = log

        # Base URL to RequestTracker REST API
        self.url = url
        self.headers = { "Content-type": "application/x-www-form-urlencoded",
                         "Accept": "text/plain"}

        cookie = LWPCookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
        urllib2.install_opener(opener)
        login = urllib2.Request(url, urlencode({'user': user,
                                                'pass': password}).encode())
        try:
            urllib2.urlopen(login)
        except urllib2.URLError:
            raise

    def _rt_request(self, url, params={}):

        #logger.debug("URL: %s, PARAMS: %r" % (url, params))

        req = urllib2.Request(url, urlencode(params).encode(),
                              self.headers)
        attempts = 0

        while attempts <= 3:

            try:
                attempts += 1
                response = urllib2.urlopen(req)
                response_value = response.read()

                if (self._get_response_status(response_value) == 200):
                    response_ok = True
                else:
                    response_ok = False
                    response_value = ""
                break

            except urllib2.URLError:
                response_ok = False
                response_value = ""
                break

            except BadStatusLine:
                continue # retry

        return [response_ok, response_value]


    def _get_response_status(self, response_value):
        # Status code is embedded into the content
        # returned by the REST API call, e.g.
        # RT/3.8.0 200 OK
        response_status = 0
        pattern = '^RT/(\d+\.\d+\.\d+)\s(\d{3})\s(\w+)$'
        prog = re.compile(pattern)

        for line in iter(response_value.splitlines()):
            m = prog.match(line.decode())
            if (m):
                response_status = int(m.group(2))

        return response_status


    def _find_in_response(self, pattern, content, group_name):
        l = []
        r = re.compile(pattern)

        for line in iter(content.splitlines()):
            m = r.match(line.decode())
            if (m):
                l.append(m.group(group_name))

        return l


    def _find_new_ticket_id(self, response_value):
        """
        Extract the newly created ticketID from the the REST response.
        """
        ticket_id = 0
        pattern = '^# Ticket (?P<id>\d+) created\.$'
        ticket_ids = self._find_in_response(pattern, response_value, 'id')

        # Should contain exactly one value
        if len(ticket_ids) == 1:
            ticket_id = ticket_ids[0]

        return ticket_id


    def find_open_tickets(self, query, queue=""):
        """
        Extract all ticket IDs from values returned by a query.
        """
        open_ticket_ids = []
        if queue:
            query = "Status='open' AND Queue='" + queue + "' AND " + query

        url = self.url + "search/ticket?query=" + quote(query)
        response_ok, response_value = self._rt_request(url)

        if response_ok:
            pattern = '^(?P<id>\d+): (.*)'
            open_ticket_ids = self._find_in_response(pattern, response_value,
                                                     'id')

        return open_ticket_ids


    def create_ticket(self, params):
        url = self.url + "ticket/new"
        response_ok, response_value = self._rt_request(url, params)

        if response_ok:
            ticket_id = self._find_new_ticket_id(response_value)
        else:
            ticket_id = 0

        return ticket_id


    def close_ticket(self, ticket_id):
        params = { "content": "Status: resolved" }
        url = self.url + "ticket/" + str(ticket_id) + "/edit"
        response_ok, response_value = self._rt_request(url, params)

        return response_ok


    def get_attachments(self, ticket_id):
        # RT stores the actual content in what it calls attachments
        # XXX: this is misleading since now function fetches only first
        # attachment (see regex below)
        attachment_ids = []
        content = ""

        logger.debug("Getting attachments (#%d)", ticket_id)

        url = self.url + 'ticket/' + str(ticket_id) + '/attachments'
        response_ok, response_value = self._rt_request(url)

        if response_ok:
            pattern = 'Attachments:\s+(?P<id>\d+): \([^)]+\)' + \
                ' \(text/\w+\s\/\s[0-9.]+\w*\),*'
            attachment_ids = self._find_in_response(pattern, response_value,
                                                    'id')

            for attachment_id in attachment_ids:
                content += self._get_attachment_contents(ticket_id,
                                                         attachment_id)

        return content


    def _get_attachment_contents(self, ticket_id, attachment_id):

        logger.debug("Getting attachment contents (#%d)", ticket_id)

        content = ""
        url = self.url + 'ticket/' + str(ticket_id) + '/attachments/' + \
            str(attachment_id) +'/content'
        response_ok, response_value = self._rt_request(url)

        # Strip off RT header (first line and following blank) from
        # content
        if response_ok:
            content = ("\n".join(response_value.decode().split("\n")[2:])).rstrip()
            content += "\n"

        return content


    def get_ticket_attributes(self, ticket_id, attribute_list):
        attribute_dict = {}
        pattern = '('

        url = self.url + 'ticket/' + str(ticket_id) + '/show'
        response_ok, response_value = self._rt_request(url)

        if response_ok:
            for key, attr in attribute_list.items():
                pattern += """%s:\s+(?P<%s>.*)|""" % (re.escape(attr), key)

            prog = re.compile(pattern[:-1] + ')')

            for line in iter(response_value.splitlines()):
                m = prog.match(line.decode())
                if (m):
                    attribute_dict.update((k,v) for k, v in m.groupdict().items() if v is not None)

        return attribute_dict


    def link_ticket(self, child, parent, rel="MemberOf"):
        url = self.url + 'ticket/link'
        params = { "id": child,
                   "rel": rel,
                   "to": parent }
        response_ok, response_value = self._rt_request(url, params)

        return response_ok


    def get_links(self, ticket_id):
        linked_to_ids = []
        id_list = []

        url = self.url + 'ticket/' + str(ticket_id) + '/links'
        response_ok, response_value = self._rt_request(url)

        if response_ok:
            pattern = '(Members:)*\s+fsck\.com-rt:' + \
                '\/\/[^/]+\/ticket\/(?P<id>\d+),*'
            linked_to_ids = self._find_in_response(pattern, response_value,
                                                   'id')

            for id in linked_to_ids:
                query = " id=" + str(id) + " AND Status='open'"
                id_list.extend(self.find_open_tickets(query))

        return id_list


    def add_ticket_comment(self, ticket_id, content, method):
        params = { "content": "Action: " + method + "\n" +
                   "Text: "  + content }
        url = self.url + 'ticket/' + ticket_id + '/comment'
        response_ok, response_value = self._rt_request(url, params)

        return response_ok


class RtTicket(object):
    ticket_id = 0
    reported_ip = ""
    url = ""
    queue = ""
    subject = ""
    owner="nobody"
    status="open"
    content = u""
    cf_ip_list = []
    cf_ah = "Yes"
    cf_constituency = ""
    custom_fields = ""

    def create_ticket_params(self):
        """
        Convert the attributes of a Ticket object into POST-parameters
        that can be parsed by RT. For complete description of fields,
        see the Best Practical wiki-entry on RT's REST API.

        Attributes vary by Ticket type. _generate_extra_parameters is
        used to add subclass specific attributes to the general
        attributes.
        """

        if isinstance(self, (RtIncident, RtInvestigation, RtIncidentReport)):
            extra_parameters = self._generate_extra_parameters()

        ticket_params = { "content": "id: ticket/new" + "\n" +
                          "Queue: " + self.queue + "\n" +
                          "Subject: " + self.subject + "\n" +
                          "Owner: " + self.owner + "\n" +
                          "Status: " + self.status + "\n" +
                          extra_parameters +
                          "Text: " + self.content + "\n" +
                          "CF.{AbuseHelperCheck}: " + self.cf_ah + "\n" +
                          "CF.{Constituency}: " + self.cf_constituency + "\n" +
                          self.custom_fields }

        return ticket_params


class RtIncident(RtTicket):
    """
    Incidents tie together IRs, Investigations and Blocks in RT-IR.
    """
    cur_date = date.isoformat(datetime.now())
    queue = "Incidents"
    priority = "50"
    initial_priority = "50"
    final_priority = "50"
    time_estimated = ""
    time_worked = ""
    time_left = ""
    starts = cur_date
    due = cur_date
    cf_function = "IncidentCoord"

    cf_classification = ""
    cf_inctype = ""
    description = ""

    def _generate_extra_parameters(self):
        extra_parameters = "Priority: " + self.priority + "\n"
        extra_parameters += "InitialPriority: " + self.initial_priority + "\n"
        extra_parameters += "FinalPriority: " + self.final_priority + "\n"
        extra_parameters += "TimeEstimated: " + self.time_estimated + "\n"
        extra_parameters += "TimeWorked: " + self.time_worked + "\n"
        extra_parameters += "TimeLeft: " + self.time_left + "\n"
        extra_parameters += "Starts: " + self.starts + "\n"
        extra_parameters += "Due: " + self.due + "\n"
        self.custom_fields = "CF.{Function}: " + self.cf_function + "\n"
        self.custom_fields += "CF.{Classification}: " + \
            self.cf_classification + "\n"
        self.custom_fields += "CF.{Incident Type}: " + \
            self.cf_inctype + "\n"
        self.custom_fields += "CF.{Description}: " + \
            self.description + "\n"

        return extra_parameters


class RtIncidentReport(RtTicket):
    """
    Incident reports are used to create new tickets for possible
    further action.
    """
    queue = "Incident reports"
    cc = ""
    admin_cc = ""
    priority = "50"
    time_worked = ""
    # IRs don't use cf_classification and description. Used to fwd info to parent.
    cf_classification = ""
    cf_inctype = ""
    description = ""
    # Leave empty, unless you want to send mail for created IRs
    requestor = ""

    def _generate_extra_parameters(self):
        extra_parameters = "Requestor: " + self.requestor + "\n"
        extra_parameters += "Cc: " + self.cc + "\n"
        extra_parameters += "AdminCc: " + self.admin_cc + "\n"
        extra_parameters += "Priority: " + self.priority + "\n"
        extra_parameters += "TimeWorked: " + self.time_worked + "\n"

        return extra_parameters


class RtInvestigation(RtTicket):
    """
    Investigations are used to communicate with 3rd
    parties. Essentially this means sending out mail from RT to the
    party being investigated.
    """
    queue = "Investigations"
    requestor = ""
    cc = ""
    admin_cc = ""
    time_estimated = ""
    time_worked = ""
    time_left = ""
    starts = ""
    due = ""
    cf_constituency = ""
    if requestor:
        cf_customer = requestor.split('@')[1]
    else:
        cf_customer = ""


    def _generate_extra_parameters(self):
        extra_parameters = "Requestor: " + self.requestor + "\n"
        extra_parameters += "Cc: " + self.cc + "\n"
        extra_parameters += "AdminCc: " + self.admin_cc + "\n"
        extra_parameters += "TimeEstimated: " + self.time_estimated + "\n"
        extra_parameters += "TimeWorked: " + self.time_worked + "\n"
        extra_parameters += "TimeLeft: " + self.time_left + "\n"
        extra_parameters += "Starts: " + self.starts + "\n"
        extra_parameters += "Due: " + self.due + "\n"
        self.custom_fields = "CF.{Customer}: " + self.cf_customer + "\n"
        self.custom_fields += "CF.{Constituency}: " + \
            self.cf_constituency + "\n"

        return extra_parameters


class RtirWorkflow(object):
    """
    RtirWorkflow consists of a number of helper methods for automating
    the RT-IR workflow. This consists of looking up and linking IRs to
    existing incidents, or creating new ones, and finally sending out
    mail via the Investigations queue.
    """

    def __init__(self, rt_client, rt_template_dir):
        self.rt_client = rt_client
        self.rt_template_dir = rt_template_dir


    def _find_ip_addr_in_content(self, content):
        """
        Search for IP addresses in a tickets contents and return a
        list of all addresses.
        """

        pattern = '(\d+\.\d+\.\d+\.\d+)'
        prog = re.compile(pattern)
        ip_list = prog.findall(content)

        return ip_list


    def _find_best_match_incident(self, reported_ip, cf_ip_list, type_detail):
        """
        Find the Incident that has the highest number of IP addresses
        that match the contents of the new ticket. An Incident Report
        may have multiple IPs if both communicating parties are
        reported, eg. infected host and C&C.
        """
        open_tickets_dict = defaultdict(list)
        incident_id = 0

        for ip in cf_ip_list:
	    #XXX: Only 'open' state tickets
            query = "'CF.{IP}' LIKE '" + ip + "' AND 'CF.{Description}' LIKE '" + type_detail + "'"
            for ticket_id in self.rt_client.find_open_tickets(query,
                                                              "Incidents"):
                open_tickets_dict[ticket_id].append(ip)

        # Remove any open tickets that do not contain the original
        # reported to prevent IR being linked to an Incident that
        # happens to have multiple IP addresses that would otherwise
        # be a better match.
        tmp_tickets_dict = defaultdict(list, open_tickets_dict.items())
        for tmp_ticket in tmp_tickets_dict:
            if not reported_ip in open_tickets_dict[tmp_ticket]:
                del open_tickets_dict[tmp_ticket]
        del tmp_tickets_dict

        # find the ticket_id with the longest list of IPs
        if len(open_tickets_dict) > 0:
            sorted_by_nr_of_ips = sorted(open_tickets_dict,
                                         key=lambda x :
                                         len(open_tickets_dict[x]))
            incident_id = sorted_by_nr_of_ips[-1]

        return incident_id


    def _is_created_by_ah(self, ticket_id):
        """
        Check if a ticket has been created by AH and not modified
        interactively.
        """
        query = " CF.{AbuseHelperCheck}='Yes' AND id=" + str(ticket_id)
        created_by_ah = self.rt_client.find_open_tickets(query, "Incidents")

        if created_by_ah:
            return True
        else:
            return False


    def link_or_create_and_link_parent(self, ticket, type_detail):
        """
        Link and IR to an open Incident or create a new Incident if
        none exists.
        """
        # Find related open incidents
        cf_ip_list = self._find_ip_addr_in_content(ticket.content)
        parent_id = self._find_best_match_incident(ticket.reported_ip,
                                                   cf_ip_list, type_detail)
        new_ticket_created = 0
        created_by_ah = True

        cur_date = date.isoformat(datetime.now())

        # If no candidate parent exists, create a new ticket and link
        # to it.  If an open ticket exists, check if has been manually
        # created or update (AbuseHelperCheck) status has been
        # updated. If it has been manually modified then do nothing
        # except link to the incident.
        if (parent_id == 0): # no match found
            parent_ticket = RtIncident()
            parent_ticket.content = ticket.content
            parent_ticket.owner = "nobody"
            parent_ticket.status = "open"
            parent_ticket.priority = "50"
            parent_ticket.initial_priority = "50"
            parent_ticket.final_priority = "50"
            parent_ticket.created = cur_date
            parent_ticket.starts = cur_date
            parent_ticket.due = cur_date
            parent_ticket.time_estimated = "60"
            parent_ticket.time_worked = "0"
            parent_ticket.subject = ticket.subject
            parent_ticket.cf_classification = ticket.cf_classification
            parent_ticket.cf_inctype = ticket.cf_inctype
            parent_ticket.description = ticket.description
            parent_ticket.cf_ah = "Yes"
            parent_ticket.custom_fields = ""

            parent_ticket_params = parent_ticket.create_ticket_params()
            parent_id = self.rt_client.create_ticket(parent_ticket_params)
            new_ticket_created = parent_id

            self.rt_client.link_ticket(ticket.ticket_id,
                                                         parent_id,
                                                         "MemberOf")
        else:
            created_by_ah = self._is_created_by_ah(parent_id)
            self.rt_client.link_ticket(ticket.ticket_id,
                                                         parent_id,
                                                         "MemberOf")

        return [parent_id, new_ticket_created, created_by_ah]


    def _create_investigation_contents(self, ir_ids, inc_id, rt_use_ah_template,
                                       cf_classification, cf_inctype, templatefn, ip):
        """
        Create the investigation content from new IRs and add it to a
        template based on the cf_classification of the event.
        """

        contents = ""

        # XXX: only contents of three IRs
        for ir_id in ir_ids[0:3]:
            contents += self.rt_client.get_attachments(ir_id) + "\n"

        # Use an AH defined template if rt_use_ah_template is
        # set. Otherwise just send raw content to the investigation
        # ticket and let RT do the template population magic.
        if rt_use_ah_template:
            template = RtTicketTemplate(cf_classification, cf_inctype, inc_id,
                                        templatefn, self.rt_template_dir)
            if not template.template: # skip if no template is found
                return
            u_contents = template.populate_template(contents, ip)
        else:
            u_contents = u"\n" + contents

        return u_contents

    def create_and_link_investigation(self, rt_requestor, rt_use_ah_template,
                                      incident_id, ir_ids, templatefn, writefreq):
        link_successful = False
        linked_ticket_ids = self.rt_client.get_links(incident_id)

        # The difference of all linked tickets and incident reports
        # should be list of all (one unless someone has manually
        # genearted an investigation) linked investigations.
        open_investigation_ids = list(set(linked_ticket_ids).difference(
                set(ir_ids)))

        attribute_list = {'cf_classification': 'CF.{Classification}',
                          'cf_inctype': 'CF.{Incident Type}',
                          'subject': 'Subject'}
        attribute_dict = self.rt_client.get_ticket_attributes(incident_id,
                                                              attribute_list)
        subject = str(attribute_dict['subject'])
        cf_classification = str(attribute_dict.get('cf_classification') or "unknown")
        cf_inctype = str(attribute_dict.get('cf_inctype') or "")

        # Extract IP from subject
        # FIXME: ipv6 anyone ? :\
        rex = re.compile("^.*\s(\d+\.\d+\.\d+\.\d+)\s.*$")
        m = rex.match(subject)
        if m:
            ip = m.group(1)
        else:
            ip = ""

        if open_investigation_ids:
            if len(open_investigation_ids) == 1:

                inv_attributes = self.rt_client.get_ticket_attributes(
                    open_investigation_ids[0], {'LastUpdated': 'LastUpdated'})
                modified = date_parse(inv_attributes['LastUpdated'])

                timeago = datetime.now() - modified

                if timedelta(days=float(writefreq)) < timeago:

                    contents = self._create_investigation_contents(
                        ir_ids,
                        incident_id,
                        rt_use_ah_template,
                        cf_classification,
                        cf_inctype,
                        templatefn,
                        ip)

                    if not contents:
                        return

                    link_successful = self.rt_client.add_ticket_comment(
                        open_investigation_ids[0],
                        contents,
                        'correspond')
                    logger.info("Investigation %r updated (#%d)",
                                open_investigation_ids[0], incident_id)

                else:

                    # Resolve IR
                    logger.info("Investigation modified %r ago, only linking "
                                "and resolving IR (#%d)", timeago, incident_id)
                    link_successful = True
            else:
                # This should not happen unless someone has manually
                # launched more investigations. Assuming manually
                # updated and thus stop processing.
                link_successful = False
                logger.info("Auto update of investigation is not "
                            "possible. Manually updated or perhaps other IRs "
                            "being open? (#%d)", incident_id)
        else:
            rt_investigation = RtInvestigation()
            contents = self._create_investigation_contents(
                ir_ids,
                incident_id,
                rt_use_ah_template,
                cf_classification,
                cf_inctype,
                templatefn,
                ip)

            if not contents:
                return

            rt_investigation.content = contents
            rt_investigation.subject = subject
            rt_investigation.status = "open"
            rt_investigation.requestor = rt_requestor

            rt_investigation_parameters = \
                rt_investigation.create_ticket_params()
            rt_investigation.id = \
                self.rt_client.create_ticket(rt_investigation_parameters)

            if rt_investigation:
                link_successful = self.rt_client.link_ticket(
                    rt_investigation.id,
                    incident_id,
                    "MemberOf")

            if link_successful:
                logger.info("Investigation %r with requestor '%r' created and "
                            "linked (#%d)",
                             rt_investigation.id,
                             rt_requestor,
                             incident_id)

        # Close IRs that were successfully processed
        if link_successful:
            logger.info("Resolving IRs: %r (#%d)", ir_ids, incident_id)
            for ir_id in ir_ids:
                self.rt_client.close_ticket(ir_id)

        return link_successful


class RtTicketTemplate(object):
    """
    A class to format ticket contents according to RT requirements and
    to select and load templates depending on the classification of
    the event.
    """

    template = u""

    def __init__(self, classification, inctype, inc_id, templatefn, directory):
        self._load_template(classification, inctype, inc_id, templatefn, directory)

    def _load_template(self, name, inctype, inc_id, templatefn, directory):
        template = u""

        if not name:
            return

        name = name.replace(" ", "")

        if inctype:
            name += "_" + inctype.replace(" ", "")

        name += '_' + templatefn.lower()

        try:
            logger.info("Opening templates from %s (#%d)",
                        osp.abspath(directory), inc_id)
            template_file = codecs.open(osp.join(osp.abspath(directory), name),
                                        "r", "utf-8", "ignore")
        except IOError:
            logger.error("Failed opening template '%s' (#%d)", name,
                         inc_id)
            return

        else:
            template = template_file.read()
            template_file.close()

        self.template = template


    def _prepend_spaces(self, content):
        """
        RT requires ticket contents to be prepended with 9 spaces.
        """
        prepended_content = u""
        spaces = u"         "

        for line in content.split("\n"):
            if line != "\n":
                prepended_content += spaces + (line.lstrip()).rstrip() + "\n"

        return prepended_content


    def populate_template(self, content, ip):
        """
        Replace template placeholders with actual ticket contents.
        """
        rex = u'IR_DATA_PLACEHOLDER'
        content = re.sub(rex, content, self.template)

        # Some templates have IP placeholders for URLs that
        # don't allow automated lookups, but provide value
        # to the recipient of the reports, e.g. CBL.
        rex = u'IP_DATA_PLACEHOLDER'
        content = re.sub(rex, ip, content)

        # Prepend spaces to content for RT "compliance"
        content = self._prepend_spaces(content)

        return content
