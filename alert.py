import smtplib
import json
import os
from email.message import EmailMessage
def load_config(path: str = "credentials.json") -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    full_path = os.path.join(base_dir, path)
    with open(full_path) as f:
        return json.load(f)

config = load_config()

def email_alert(subject, body, to):
    msg = EmailMessage()
    msg.set_content(body)
    msg['subject'] = subject
    msg['to'] =  to
    user = config["email"]["username"]
    msg['from'] = user
    password = config["email"]["password"]
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(user,password)
    server.send_message(msg)
    server.quit()