from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from supabase import create_client, Client
import os
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

supabase_url = os.environ.get('SUPABASE_URL')
supabase_service_key = os.environ.get('SUPABASE_SERVICE_KEY')
anon_key = os.environ.get('SUPABASE_ANON_KEY') or supabase_service_key  # Use service key if anon not set, but not recommended for prod

supabase: Client = create_client(supabase_url, supabase_service_key)

admin_email = 'armanhacker900@gmail.com'
admin_password = '@team#dev'

def is_logged_in():
    return 'user_id' in session

def get_current_user():
    if not is_logged_in():
        return None
    user = supabase.table('users').select('*').eq('id', session['user_id']).single().execute().data
    return user

def is_admin(user):
    return user and user['verified'] and user['email'] == admin_email

def log_action(action, details, by_user_id):
    supabase.table('logs').insert({
        'action': action,
        'details': details,
        'by_user_id': by_user_id,
        'created_at': datetime.utcnow().isoformat()
    }).execute()

@app.before_request
def initialize():
    # Create admin if not exists
    try:
        response = supabase.auth.sign_in_with_password({'email': admin_email, 'password': admin_password})
    except Exception as e:
        response = supabase.auth.sign_up({'email': admin_email, 'password': admin_password})
        user = response.user
        supabase.table('users').insert({
            'id': user.id,
            'name': 'Admin',
            'email': admin_email,
            'verified': True,
            'banned': False,
            'muted': False
        }).execute()
    # Create TeamDev group if not exists
    groups = supabase.table('groups').select('id').eq('name', 'TeamDev').execute()
    if not groups.data:
        group_response = supabase.table('groups').insert({
            'name': 'TeamDev',
            'description': 'Official verified developer group of Built-in-Group',
            'tagline': '“We Build The Future Together 💻✨”',
            'verified': True,
            'created_by': admin_email,
            'allow_text': True,
            'allow_media': True,
            'allow_file': True,
            'allow_audio': True
        }).execute()
        group_id = group_response.data[0]['id']
        # Add admin to TeamDev
        admin_user = supabase.table('users').select('id').eq('email', admin_email).execute()
        admin_id = admin_user.data[0]['id']
        supabase.table('user_groups').insert({'user_id': admin_id, 'group_id': group_id}).execute()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            response = supabase.auth.sign_in_with_password({'email': email, 'password': password})
            session['access_token'] = response.session.access_token
            session['user_id'] = response.user.id
            return redirect('/chat/TeamDev')
        except Exception as e:
            return 'Invalid credentials', 400
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        # Check unique name
        existing = supabase.table('users').select('id').eq('name', name).execute()
        if existing.data:
            return 'Name taken', 400
        try:
            response = supabase.auth.sign_up({'email': email, 'password': password})
            user = response.user
            supabase.table('users').insert({
                'id': user.id,
                'name': name,
                'email': email,
                'verified': False,
                'banned': False,
                'muted': False
            }).execute()
            # Auto join TeamDev
            group = supabase.table('groups').select('id').eq('name', 'TeamDev').execute()
            group_id = group.data[0]['id']
            supabase.table('user_groups').insert({'user_id': user.id, 'group_id': group_id}).execute()
            # Auto login
            login_response = supabase.auth.sign_in_with_password({'email': email, 'password': password})
            session['access_token'] = login_response.session.access_token
            session['user_id'] = login_response.user.id
            return redirect('/chat/TeamDev')
        except Exception as e:
            return str(e), 400
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/api/groups')
def api_groups():
    if not is_logged_in():
        return jsonify([])
    user_groups = supabase.table('user_groups').select('group_id').eq('user_id', session['user_id']).execute()
    group_ids = [g['group_id'] for g in user_groups.data]
    groups = supabase.table('groups').select('*').in_('id', group_ids).execute()
    return jsonify(groups.data)

@app.route('/api/messages')
def api_messages():
    if not is_logged_in():
        return jsonify([])
    group_id = request.args.get('group_id')
    if not group_id:
        return jsonify([])
    # Check membership
    check = supabase.table('user_groups').select('user_id').eq('user_id', session['user_id']).eq('group_id', group_id).execute()
    if not check.data:
        return jsonify([])
    messages = supabase.table('messages').select('*').eq('group_id', group_id).order('created_at', asc=True).execute()
    for m in messages.data:
        sender = supabase.table('users').select('name, verified').eq('id', m['sender_id']).single().execute().data
        m['sender_name'] = sender['name']
        m['sender_verified'] = sender['verified']
    return jsonify(messages.data)

@app.route('/chat/<group_name>')
def chat(group_name):
    if not is_logged_in():
        return redirect('/login')
    group = supabase.table('groups').select('*').eq('name', group_name).single().execute()
    if not group.data:
        return 'Group not found', 404
    check = supabase.table('user_groups').select('*').eq('user_id', session['user_id']).eq('group_id', group.data['id']).execute()
    if not check.data:
        return 'Not a member of this group', 403
    access_token = session['access_token']
    current_user = get_current_user()
    return render_template('chat.html', group=group.data, supabase_url=supabase_url, anon_key=anon_key, access_token=access_token, current_user=current_user)

@app.route('/admin')
def admin_panel():
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    groups = supabase.table('groups').select('*').execute().data
    users = supabase.table('users').select('*').execute().data
    logs = supabase.table('logs').select('*').order('created_at', desc=True).execute().data
    for log in logs:
        by_user = supabase.table('users').select('name').eq('id', log['by_user_id']).single().execute().data
        log['by_name'] = by_user['name']
    return render_template('admin.html', groups=groups, users=users, logs=logs)

@app.route('/admin/create_group', methods=['POST'])
def admin_create_group():
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    name = request.form['name']
    description = request.form.get('description', '')
    tagline = request.form.get('tagline', '')
    verified = 'verified' in request.form
    allow_text = 'allow_text' in request.form
    allow_media = 'allow_media' in request.form
    allow_file = 'allow_file' in request.form
    allow_audio = 'allow_audio' in request.form
    group = supabase.table('groups').insert({
        'name': name,
        'description': description,
        'tagline': tagline,
        'verified': verified,
        'created_by': user['email'],
        'allow_text': allow_text,
        'allow_media': allow_media,
        'allow_file': allow_file,
        'allow_audio': allow_audio
    }).execute()
    supabase.table('user_groups').insert({'user_id': user['id'], 'group_id': group.data[0]['id']}).execute()
    log_action('create_group', f'Created group {name}', user['id'])
    return redirect('/admin')

@app.route('/admin/delete_group/<group_id>')
def admin_delete_group(group_id):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    group = supabase.table('groups').select('name').eq('id', group_id).single().execute().data
    supabase.table('groups').delete().eq('id', group_id).execute()
    log_action('delete_group', f'Deleted group {group["name"]}', user['id'])
    return redirect('/admin')

@app.route('/admin/add_all_to_group/<group_id>')
def admin_add_all_to_group(group_id):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    all_users = supabase.table('users').select('id').execute().data
    for u in all_users:
        supabase.table('user_groups').upsert({'user_id': u['id'], 'group_id': group_id}).execute()
    group_name = supabase.table('groups').select('name').eq('id', group_id).single().execute().data['name']
    log_action('add_all_to_group', f'Added all users to group {group_name}', user['id'])
    return redirect('/admin')

@app.route('/admin/ban/<user_id>')
def admin_ban(user_id):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    supabase.table('users').update({'banned': True}).eq('id', user_id).execute()
    banned_user = supabase.table('users').select('name').eq('id', user_id).single().execute().data
    log_action('ban_user', f'Banned user {banned_user["name"]}', user['id'])
    return redirect('/admin')

@app.route('/admin/unban/<user_id>')
def admin_unban(user_id):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    supabase.table('users').update({'banned': False}).eq('id', user_id).execute()
    banned_user = supabase.table('users').select('name').eq('id', user_id).single().execute().data
    log_action('unban_user', f'Unbanned user {banned_user["name"]}', user['id'])
    return redirect('/admin')

@app.route('/admin/mute/<user_id>')
def admin_mute(user_id):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    supabase.table('users').update({'muted': True}).eq('id', user_id).execute()
    muted_user = supabase.table('users').select('name').eq('id', user_id).single().execute().data
    log_action('mute_user', f'Muted user {muted_user["name"]}', user['id'])
    return redirect('/admin')

@app.route('/admin/unmute/<user_id>')
def admin_unmute(user_id):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    supabase.table('users').update({'muted': False}).eq('id', user_id).execute()
    muted_user = supabase.table('users').select('name').eq('id', user_id).single().execute().data
    log_action('unmute_user', f'Unmuted user {muted_user["name"]}', user['id'])
    return redirect('/admin')

@app.route('/admin/delete_user/<user_id>')
def admin_delete_user(user_id):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    deleted_user = supabase.table('users').select('name').eq('id', user_id).single().execute().data
    supabase.auth.admin.delete_user(user_id)
    supabase.table('users').delete().eq('id', user_id).execute()
    log_action('delete_user', f'Deleted user {deleted_user["name"]}', user['id'])
    return redirect('/admin')

@app.route('/admin/add_user', methods=['POST'])
def admin_add_user():
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    existing = supabase.table('users').select('id').eq('name', name).execute()
    if existing.data:
        return 'Name taken', 400
    response = supabase.auth.sign_up({'email': email, 'password': password})
    new_user = response.user
    supabase.table('users').insert({
        'id': new_user.id,
        'name': name,
        'email': email,
        'verified': False,
        'banned': False,
        'muted': False
    }).execute()
    log_action('add_user', f'Added user {name}', user['id'])
    return redirect('/admin')

@app.route('/admin/toggle_permission/<group_id>/<permission>')
def admin_toggle_permission(group_id, permission):
    user = get_current_user()
    if not is_admin(user):
        return 'Not authorized', 403
    current = supabase.table('groups').select(permission).eq('id', group_id).single().execute().data[permission]
    supabase.table('groups').update({permission: not current}).eq('id', group_id).execute()
    group_name = supabase.table('groups').select('name').eq('id', group_id).single().execute().data['name']
    log_action('toggle_permission', f'Toggled {permission} for group {group_name}', user['id'])
    return redirect('/admin')

if __name__ == '__main__':
    app.run(debug=True)

from a2wsgi import WSGIMiddleware
app = WSGIMiddleware(app)
