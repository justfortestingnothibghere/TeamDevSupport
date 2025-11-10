# === PATCH EVENTLET FIRST! ===
import eventlet
eventlet.monkey_patch(all=True)

# === IMPORTS ===
import os
import bcrypt
import markdown
import bleach
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory, Response, flash, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, helpers as admin_helpers
from flask_admin.contrib.sqla import ModelView
from queue import Queue
from threading import Lock

app = Flask(__name__)

# === CONFIG WITH SAFETY ===
database_url = os.getenv('DATABASE_URL')
if not database_url:
    raise RuntimeError("FATAL: DATABASE_URL not set in Render!")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-now')
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs('uploads', exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

queues = {}
queues_lock = Lock()

# === MODELS ===
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    banned = db.Column(db.Boolean, default=False)
    muted = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    tagline = db.Column(db.String(200))
    verified = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.String(120))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text)
    type = db.Column(db.String(20), default='text')
    created_at = db.Column(db.DateTime, server_default=db.func.now())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# === ADMIN PANEL (FIXED!) ===
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class HomeAdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

admin = Admin(app, name='Built-in-Group Admin', index_view=HomeAdminView())
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Group, db.session))
admin.add_view(SecureModelView(Message, db.session))

# === DEFAULT DATA ===
def create_defaults():
    with app.app_context():
        db.create_all()
        if not Group.query.filter_by(name='TeamDev').first():
            teamdev = Group(name='TeamDev', description='Official verified developer group of Built-in-Group',
                            tagline='We Build The Future Together 💻✨', verified=True, created_by='system')
            db.session.add(teamdev)
            db.session.commit()

        if not User.query.filter_by(email='armanhacker900@gmail.com').first():
            hashed = bcrypt.hashpw('@team#dev'.encode(), bcrypt.gensalt())
            admin_user = User(name='ArmanHacker', email='armanhacker900@gmail.com', password=hashed.decode(),
                              verified=True, is_admin=True)
            db.session.add(admin_user)
            db.session.commit()

# === ROUTES ===
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect('/chat/1')
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        pwd = request.form['password']
        if User.query.filter_by(name=name).first() or User.query.filter_by(email=email).first():
            flash('Taken!')
            return redirect('/register')
        user = User(name=name, email=email, password=bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode())
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect('/chat/1')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.checkpw(request.form['password'].encode(), user.password.encode()):
            login_user(user)
            return redirect('/chat/1')
        flash('Wrong!')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/chat/<int:group_id>')
@login_required
def chat(group_id):
    group = Group.query.get_or_404(group_id)
    messages = Message.query.filter_by(group_id=group_id).order_by(Message.created_at).all()
    groups = Group.query.all()
    return render_template('chat.html', group=group, messages=messages, groups=groups)

@app.route('/uploads/<filename>')
def uploads(filename):
    return send_from_directory('uploads', filename)

@app.route('/send/<int:group_id>', methods=['POST'])
@login_required
def send(group_id):
    if current_user.banned or current_user.muted: return jsonify(success=False)
    content = bleach.clean(request.form.get('content', ''), tags=['b','i','code','p','br'])
    file = request.files.get('file')
    msg_type = 'text'
    file_url = None
    if file and file.filename:
        filename = os.path.join('uploads', file.filename)
        file.save(filename)
        file_url = url_for('uploads', filename=file.filename)
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext in ['png','jpg','jpeg','gif','webp','mp4','webm']: msg_type = 'media'
        elif ext in ['pdf','doc','zip']: msg_type = 'file'
        elif ext in ['mp3','wav','ogg']: msg_type = 'audio'
    msg = Message(group_id=group_id, sender_id=current_user.id, content=content or file_url, type=msg_type)
    db.session.add(msg)
    db.session.commit()
    broadcast(group_id, render_message(msg))
    return jsonify(success=True)

@app.route('/stream/<int:group_id>')
def stream(group_id):
    def gen():
        q = Queue()
        with queues_lock:
            queues.setdefault(group_id, []).append(q)
        try:
            while True: yield f"data: {q.get()}\n\n"
        except GeneratorExit:
            with queues_lock:
                queues[group_id].remove(q)
    return Response(gen(), mimetype='text/event-stream')

def broadcast(gid, html):
    with queues_lock:
        for q in queues.get(gid, []):
            q.put(html)

def render_message(msg):
    user = User.query.get(msg.sender_id)
    group = Group.query.get(msg.group_id)
    verified = '<img src="/static/icons/verified.svg" class="verified">' if (user.verified or group.verified) else ''
    admin_tag = '<span class="official">Official</span>' if user.is_admin else ''
    if msg.type == 'text':
        content = markdown.markdown(msg.content)
    elif msg.type == 'audio':
        content = f'<audio controls><source src="{msg.content}"></audio>'
    elif msg.type == 'media':
        if msg.content.lower().endswith(('.png','.jpg','.jpeg','.gif','.webp')):
            content = f'<img src="{msg.content}" loading="lazy" style="max-width:100%;border-radius:12px;">'
        else:
            content = f'<video controls style="max-width:100%;"><source src="{msg.content}"></video>'
    else:
        content = f'<a href="{msg.content}" target="_blank">📎 {msg.type.upper()} File</a>'
    own = 'own' if msg.sender_id == current_user.id else ''
    return f'<div class="message {own}"><span class="name">{user.name}{verified} {admin_tag}</span><div class="bubble">{content}</div></div>'

if __name__ == '__main__':
    create_defaults()
    app.run(debug=False)
