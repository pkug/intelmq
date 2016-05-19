# -*- coding: utf-8 -*-

import re
import sys
import zipfile

try:
    import imbox
except ImportError:
    imbox = None

from intelmq.lib.bot import Bot
from intelmq.lib.harmonization import DateTime
from intelmq.lib.message import Report


class MailBodyCollectorBot(Bot):

    def init(self):
        if imbox is None:
            self.logger.error('Could not import imbox. Please install it.')
            self.stop()


    def process(self):
        mailbox = imbox.Imbox(self.parameters.mail_host,
                              self.parameters.mail_user,
                              self.parameters.mail_password,
                              self.parameters.mail_ssl)
        emails = mailbox.messages(folder=self.parameters.mail_folder,
                                  unread=True)

        reflags = re.IGNORECASE if getattr(self.parameters,
                                           "mail_subject_ignorecase",
                                           False) else 0

        if emails:
            for uid, message in emails:

                if (self.parameters.mail_subject_regex and
                        not re.search(self.parameters.mail_subject_regex,
                                      message.subject, flags=reflags)):
                    self.logger.info("Subject regex not matched: '%s' in '%s'",
                            self.parameters.mail_subject_regex,
                            message.subject)
                    continue

                self.logger.info("Reading email report")

                report = Report()
                report.add("raw", message.body['plain'][0], sanitize=True)
                report.add("feed.name", self.parameters.feed,
                           sanitize=True)
                time_observation = DateTime().generate_datetime_now()
                report.add('time.observation', time_observation,
                           sanitize=True)

                self.send_message(report)


                mailbox.mark_seen(uid)
                self.logger.info("Email report read")


if __name__ == "__main__":
    bot = MailBodyCollectorBot(sys.argv[1])
    bot.start()
