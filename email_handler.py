from flask_mail import Message
from threading import Thread
from extensions import mail

class EmailHandler:
    """Send emails asynchronously using Flask-Mail."""

    def __init__(self, app):
        self.app = app  # Pass the real Flask app instance

    def _send_async(self, msg):
        with self.app.app_context():  # Use the actual app context
            mail.send(msg)

    def send_email(self, subject, recipients, body):
        msg = Message(subject, recipients=recipients)
        msg.body = body
        Thread(target=self._send_async, args=(msg,)).start()

    def send_html_email(self, subject, recipients, html_body, plain_body=""):
        msg = Message(subject, recipients=recipients)
        msg.body = plain_body
        msg.html = html_body
        Thread(target=self._send_async, args=(msg,)).start()
