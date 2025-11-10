import os
import bcrypt
import markdown
import bleach
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory, Response, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from queue import Queue
from threading import Lock
import eventlet
eventlet.monkey_patch()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL').replace("postgres://", "postgresql://")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs('uploads', exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

queues = {}
queues_lock = Lock()

# ===================== MODELS =====================
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

# ===================== ADMIN PANEL =====================
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class HomeAdminView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

admin = Admin(app, name='Built-in-Group Admin', template_mode='bootstrap4', index_view=HomeAdminView())
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Group, db.session))
admin.add_view(SecureModelView(Message, db.session))

# ===================== INIT DB & DEFAULT DATA =====================
@app.before_first_request
def init_db():
    db.create_all()
    # Create TeamDev
    if not Group.query.filter_by(name='TeamDev').first():
        teamdev = Group(
            name='TeamDev',
            description='Official verified developer group of Built-in-Group',
            tagline='We Build The Future Together 💻✨',
            verified=True,
            created_by='system'
        )
        db.session.add(teamdev)
        db.session.commit()

    # Create Admin
    if not User.query.filter_by(email='armanhacker900@gmail.com').first():
        hashed = bcrypt.hashpw('@team#dev'.encode(), bcrypt.gensalt())
        admin_user = User(
            name='ArmanHacker',
            email='armanhacker900@gmail.com',
            password=hashed.decode(),
            verified=True,
            is_admin=True
        )
        db.session.add(admin_user)
        db.session.commit()

# ===================== ROUTES =====================
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat', group_id=1))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = bcrypt.hashpw(request.form['password'].encode(), bcrypt.gensalt()).decode()
        if User.query.filter_by(name=name).first() or User.query.filter_by(email=email).first():
            flash('Name or email already taken!')
            return redirect(url_for('register'))
        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('chat', group_id=1))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.checkpw(request.form['password'].encode(), user.password.encode()):
            login_user(user)
            return redirect(url_for('chat', group_id=1))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

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
    if current_user.banned or current_user.muted:
        return jsonify(success=False, error="You are banned or muted")

    content = bleach.clean(request.form.get('content', ''), tags=['b','i','code','p','br'])
    file = request.files.get('file')
    msg_type = 'text'
    file_url = None

    if file and file.filename:
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        file_url = url_for('uploads', filename=file.filename)
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext in ['png','jpg','jpeg','gif','webp','svg']: msg_type = 'media'
        elif ext in ['mp4','webm','ogg']: msg_type = 'media'
        elif ext in ['pdf','doc','docx','zip','rar']: msg_type = 'file'
        elif ext in ['mp3','wav','ogg']: msg_type = 'audio'

    message = Message(
        group_id=group_id,
        sender_id=current_user.id,
        content=content or file_url or '',
        type=msg_type if file else 'text'
    )
    db.session.add(message)
    db.session.commit()

    html = render_message(message)
    broadcast(group_id, html)
    return jsonify(success=True)

@app.route('/stream/<int:group_id>')
def stream(group_id):
    def gen():
        q = Queue()
        with queues_lock:
            if group_id not in queues:
                queues[group_id] = []
            queues[group_id].append(q)
        try:
            while True:
                msg = q.get()
                yield f"data: {msg}\n\n"
        except GeneratorExit:
            with queues_lock:
                queues[group_id].remove(q)
    return Response(gen(), mimetype='text/event-stream')

def broadcast(group_id, html):
    with queues_lock:
        for q in queues.get(group_id, []):
            q.put(html)

def render_message(msg):
    user = User.query.get(msg.sender_id)
    group = Group.query.get(msg.group_id)
    verified = '<img src="/static/icons/verified.svg" class="verified" alt="✓">' if (user.verified or group.verified) else ''
    admin_tag = '<span class="official">Official Account</span>' if user.is_admin else ''
    name = user.name

    if msg.type == 'text':
        content = markdown.markdown(msg.content)
    elif msg.type in ['media', 'audio']:
        if 'audio' in msg.type:
            content = f'<audio controls><source src="{msg.content}"></audio>'
        else:
            content = f'<img src="{msg.content}" loading="lazy" style="max-width:100%;border-radius:12px;">' if 'image' in msg.content else f'<video controls style="max-width:100%;"><source src="{msg.content}"></video>'
    else:
        content = f'<a href="{msg.content}" target="_blank" class="file-link">📎 {msg.type.upper()} File</a>'

    own = 'own' if msg.sender_id == current_user.id else ''
    return f'<div class="message {own}"><span class="name">{name}{verified} {admin_tag}</span><div class="bubble">{content}</div></div>'

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=False)
