from flask import Flask
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'secret key'
app.config['WTF_CSRF_SECRET_KEY'] = 'random key for form'
app.config['LDAP_PROVIDER_URL'] = 'ldap://ldap.projet.com:389/'
app.config['LDAP_PROTOCOL_VERSION'] = 3
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/chat.db'

db = SQLAlchemy(app)


# configure login
login = LoginManager(app)
login.init_app(app)
login.login_view = 'login'

db.create_all()
