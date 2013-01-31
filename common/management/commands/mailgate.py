from django.core.management.base import BaseCommand, CommandError
from common.models import User

import email
import email.mime.text
import pyme.constants.sigsum
import pyme.core
import sys

from _mailgate import MailGate

class Command(BaseCommand):
    help = 'mailgate - mail gateway command processor'

    def handle(self, *args, **options):
        try:
            mailgate = MailGate()
            message = email.message_from_file(sys.stdin)
            (fingerprint, commands) = self.verify_message(message)
            user = self.verify_fingerprint(fingerprint)
            result = mailgate.process_commands(user, commands)
            self.generate_reply(message, result)
        except Exception as err:
            raise CommandError(err)

    def verify_message(self, message):
        if not (message.get('Reply-To') or message.get('From')):
            raise Exception('malformed message: missing headers')
        ctx = pyme.core.Context()
        if message.get_content_type() == 'text/plain':
            try: # normal signature (clearsign or sign & armor)
                plaintext = pyme.core.Data() # output
                signature = pyme.core.Data(message.get_payload())
                ctx.op_verify(signature, None, plaintext)
                plaintext.seek(0,0)
            except Exception as err:
                raise Exception('malformed text/plain message')
            commands = plaintext.read().splitlines()
        elif message.get_content_type() == 'multipart/signed':
            try: # detached signature
                signedtxt = pyme.core.Data(message.get_payload(0).as_string())
                signature = pyme.core.Data(message.get_payload(1).as_string())
                ctx.op_verify(signature, signedtxt, None)
            except:
                raise Exception('malformed multipart/signed message')
            commands = message.get_payload(0).get_payload(decode=True).splitlines()
        else:
            raise Exception('malformed message: unsupported content-type')
        result = ctx.op_verify_result()
        if len(result.signatures) == 0:
            raise Exception('malformed message: too few signatures')
        if len(result.signatures) >= 2:
            raise Exception('malformed message: too many signatures')
        if result.signatures[0].status != 0:
            raise Exception('invalid signature')
        return (result.signatures[0].fpr, commands)

    def verify_fingerprint(self, fingerprint):
        result = User.objects.filter(keyFingerPrint=fingerprint)
        if len(result) == 0:
            raise Exception('too few user objects found')
        if len(result) >= 2:
            raise Exception('too many user objects found')
        return result[0]

    def generate_reply(self, message, result):
        msg = email.mime.text.MIMEText('\n'.join(result))
        msg['From'] = 'changes@db.debian.org'
        msg['To'] = reply_to = message.get('Reply-To') or message.get('From')
        msg['Subject'] = 'ud-mailgate processing results'
        print msg.as_string()

# vim: set ts=4 sw=4 et ai si sta:
