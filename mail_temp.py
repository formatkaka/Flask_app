from flask import Flask, current_app

from flask_mail import Mail, Message

import threading
#mail = Mail()
app = Flask(__name__)

#DEBUG = True


app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT']= 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL']= False
app.config['MAIL_USERNAME'] = 'EMAIL_ID'
app.config['MAIL_PASSWORD'] = 'PASSWORD'

mail = Mail(app)

@app.route('/')
def send_mail():
    send_email('EMAIL_TO')
    return "Sent"


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)
        print "sent"

def send_email(to):
    app = current_app._get_current_object()
    msg = Message(subject='hello',
                  sender='SENDER', recipients=[to])
    thr = threading.Thread(target=send_async_email, args=[app, msg])
    thr.start()
    return thr

#def send_email()

if __name__ == "__main__":
    app.run()