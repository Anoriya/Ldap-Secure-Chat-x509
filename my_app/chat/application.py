from flask_socketio import emit, join_room, SocketIO
import ldap
from flask import request, render_template, flash, redirect, \
    url_for
from flask_login import current_user, login_user, \
    logout_user

from my_app import app, db, login
from my_app.chat.ca import signRequestCSR
from my_app.chat.models import User
from my_app.chat.wtform_fields import RegistrationForm, LoginForm
from my_app.server.server import Server

# initialze flask socketIo
clients = []

# Chat room socket
socketio = SocketIO(app)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/')
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST' and form.validate():
        username = request.form.get('username')
        password = request.form.get('password')

        # sign certification
        with open("/home/sartharion/Bureau/v2/my_app/client/clients_csr/csr" + username + ".pem", "wb") as f:
            f.write(bytes(form.request.data, 'utf-8'))
        certification = signRequestCSR(username)

        # add user to ldap
        try:
            result = User.try_register(username, password, certification)
        except ValueError:
            flash(
                'User already exist.',
                'danger')
            return render_template('index.html', form=form)

        if result:
            # add user to db
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
            flash('register wish success, please login', 'success')
            return redirect(url_for('login', form=form, certification=certification))

        else:
            flash('Error adding to ldap, try again', 'danger')
            return render_template('index.html', form=form)

    if form.errors:
        flash(form.errors, 'danger')

    return render_template("index.html", form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    login_form = LoginForm()

    if request.method == 'POST' and login_form.validate():
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            User.try_login(username, password)
        except ldap.INVALID_CREDENTIALS:
            flash(
                'Invalid username or password. Please try again.',
                'danger')
            return render_template('login.html', form=login_form)
        try:
            Server.verify_ldap_cert(username)
        except ValueError:
            flash('Certificate denied', 'danger')
            return render_template('login.html', form=login_form)

        # Allow login if validation success
        user_object = User.query.filter_by(username=username).first()
        login_user(user_object)
        flash('You have successfully logged in.', 'success')
        return redirect(url_for('chat'))

    if login_form.errors:
        flash(login_form.errors, 'danger')

    return render_template("login.html", form=login_form)


@app.route("/chat", methods=['GET', 'POST'])
def chat():
    if not current_user.is_authenticated:
        flash(' please login', 'danger')
        return redirect(url_for('login'))
    # get certificate
    myCertif = open(
        "/home/sartharion/Bureau/v2/my_app/client/clients_crt/crt" + current_user.username + ".pem",
        'rb').read().decode("utf-8")
    return render_template("chat.html", username=current_user.username, clients=clients, myCertif=myCertif)




@app.route("/logout", methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('You have logged out successfully', 'success')
    return redirect(url_for('login'))


@socketio.on('connect-user')
def connect(data):
    username = data["username"]
    room = data["room"]
    certification = data["certification"]
    join_room(room)
    index = 0
    for i in range(len(clients)):
        if clients[i]['username'] == username:
            pass
            break
        index = index + 1
    if index == len(clients):
        clients.append({'username': username, 'certification': certification})
    # Broadcast that new user has joined
    emit('new-user', {'username': username, 'room': room, 'clients': clients}, broadcast=True)


@socketio.on('leave-my_app')
def connect(data):
    username = data["username"]
    room = data["room"]
    for i in range(len(clients)):
        if clients[i]['username'] == username:
            del clients[i]
            break
    # Broadcast that new user has left
    emit('leave-user', {'username': username, 'room': room, 'clients': clients}, broadcast=True)


@socketio.on('message')
def message(data):
    destination = ''
    if 'destination' in data:
        destination = data['destination']
    msg = {"msg": data['msg'], "username": data['username']}
    userRoom = destination + '_' + destination
    emit('notification',
         {"from": data['username'], "msg": data['msg'], 'clients': clients},
         room=userRoom)
