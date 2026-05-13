import os
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager
from flask_mail import Mail
from dotenv import load_dotenv
from extensions import mail
from email_handler import EmailHandler

from extensions import db, login_manager


logging.basicConfig(level=logging.DEBUG)

load_dotenv()

def create_app():
    app = Flask(__name__)

    app.secret_key = os.environ.get("SESSION_SECRET", "your_default_secret")
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///fraudguard.db")
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # Mail configuration (use safe defaults to avoid runtime errors when env vars are missing)
    app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "")
    # Provide a default port so int() never fails if MAIL_PORT isn't set
    app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", "25"))
    app.config['MAIL_USE_SSL'] = os.getenv("MAIL_USE_SSL", "False").lower() == 'true'
    # Also allow TLS flag
    app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "False").lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
    app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv("MAIL_DEFAULT_SENDER")


    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'


    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))

    with app.app_context():
        import models
        db.create_all()

        from routes import register_routes
        register_routes(app)
    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
