# app.py

import os
import uuid
import sqlite3
import mimetypes
import secrets
import re
from datetime import datetime, timedelta
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, g, abort, send_file, jsonify, Response
)
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
# Note: For production, consider adding Flask-WTF for CSRF protection
# from flask_wtf.csrf import CSRFProtect

from PIL import Image
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Note: CSRF protection would be initialized here if Flask-WTF is available
# csrf = CSRFProtect(app)


app.config['SECRET_KEY'] = os.getenv('SSP_SECRET_KEY')
app.config['ADMIN_PASSWORD_HASH'] = os.getenv('SSP_ADMIN_PASSWORD_HASH')
app.config['ADMIN_URL'] = os.getenv('SSP_ADMIN_URL')

enc_key = os.getenv('SSP_ENCRYPTION_KEY')
if not enc_key:
    raise ValueError("FATAL: SSP_ENCRYPTION_KEY is not set in the environment.")
app.config['ENCRYPTION_KEY'] = enc_key.encode('utf-8')

app.config['UPLOAD_FOLDER'] = os.getenv('SSP_UPLOAD_FOLDER', 'uploads')
app.config['DATABASE_PATH'] = os.getenv('SSP_DATABASE_PATH', 'database.db')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

# Ensure debug mode is never enabled in production
debug_env = os.getenv('SSP_FLASK_DEBUG', 'False').lower()
app.config['FLASK_DEBUG'] = debug_env in ('true', '1', 't') and os.getenv('FLASK_ENV') != 'production'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'tiff'}
ALLOWED_MIME_TYPES = {
    'image/png', 'image/jpeg', 'image/gif', 'image/webp', 
    'image/bmp', 'image/x-icon', 'image/tiff'
}

# Maximum filename length and allowed characters
MAX_FILENAME_LENGTH = 255
SAFE_FILENAME_REGEX = re.compile(r'^[a-zA-Z0-9._-]+$')

# --- Rate Limiting (I2P-aware) ---
def i2p_key_func():
    # Prioritize the I2P destination header for rate limiting
    b32 = request.headers.get('X-I2P-DestB32')
    if b32:
        return b32
    # Fallback to X-Forwarded-For if behind a standard proxy
    fwd = request.headers.get('X-Forwarded-For')
    if fwd:
        return fwd.split(',')[0].strip()
    # Final fallback to the direct remote address
    return get_remote_address()

limiter = Limiter(
    app=app,
    key_func=i2p_key_func,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

fernet = Fernet(app.config['ENCRYPTION_KEY'])

# --- Expiry Map & Languages ---
EXPIRY_MAP = {
    "15m": timedelta(minutes=15), "1h": timedelta(hours=1), "2h": timedelta(hours=2),
    "4h": timedelta(hours=4), "8h": timedelta(hours=8), "12h": timedelta(hours=12),
    "24h": timedelta(hours=24), "48h": timedelta(hours=48)
}
POPULAR_LANGUAGES = [
    'text', 'bash', 'c', 'cpp', 'csharp', 'css', 'go', 'html', 'java', 'javascript', 'json',
    'kotlin', 'lua', 'markdown', 'php', 'python', 'ruby', 'rust', 'sql', 'swift',
    'typescript', 'xml', 'yaml'
]

# --- Database Helpers ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

app.teardown_appcontext(close_db)

def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS pastes (
              id TEXT PRIMARY KEY,
              content BLOB NOT NULL,
              language TEXT NOT NULL,
              expiry_date DATETIME NOT NULL,
              password_hash TEXT,
              view_count INTEGER DEFAULT 0,
              max_views INTEGER
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS images (
              id TEXT PRIMARY KEY,
              upload_date DATETIME NOT NULL,
              expiry_date DATETIME NOT NULL,
              password_hash TEXT,
              view_count INTEGER DEFAULT 0,
              max_views INTEGER
            )
        ''')
        c.execute('CREATE TABLE IF NOT EXISTS stats (stat_key TEXT PRIMARY KEY, stat_value INTEGER NOT NULL)')
        for stat in ['total_images', 'total_pastes', 'total_api_uploads']:
            c.execute("INSERT OR IGNORE INTO stats(stat_key,stat_value) VALUES(?,0)", (stat,))
        db.commit()

def update_stat(key, inc=1):
    db = get_db()
    db.execute("UPDATE stats SET stat_value = stat_value + ? WHERE stat_key = ?", (inc, key))
    db.commit()

# --- Cleanup Scheduler ---
scheduler = BackgroundScheduler(daemon=True)

def cleanup_expired_content():
    with app.app_context():
        now = datetime.now()
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        cur = conn.cursor()
        cur.execute("DELETE FROM pastes WHERE expiry_date < ?", (now,))
        cur.execute("SELECT id FROM images WHERE expiry_date < ?", (now,))
        for (img_id,) in cur.fetchall():
            path = os.path.join(app.config['UPLOAD_FOLDER'], img_id)
            try:
                os.remove(path)
            except OSError as e:
                app.logger.error(f"Error removing expired image file: {sanitize_error_message(e)}")
            cur.execute("DELETE FROM images WHERE id = ?", (img_id,))
        conn.commit()
        conn.close()

# --- Utility Functions ---
def sanitize_error_message(error_msg):
    """Sanitize error messages to prevent information disclosure"""
    # Remove file paths and sensitive information
    sanitized = re.sub(r'/[\w/.-]+', '[path]', str(error_msg))
    sanitized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[ip]', sanitized)
    return sanitized

def secure_session_key(prefix, identifier):
    """Generate cryptographically secure session keys"""
    random_token = secrets.token_hex(16)
    return f"{prefix}_{identifier}_{random_token}"

def validate_filename_security(filename):
    """Enhanced filename validation for security"""
    if not filename or len(filename) > MAX_FILENAME_LENGTH:
        return False
    
    # Check for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Check for null bytes and control characters
    if '\x00' in filename or any(ord(c) < 32 for c in filename if c != '\t'):
        return False
    
    # Ensure filename matches safe pattern
    if not SAFE_FILENAME_REGEX.match(filename):
        return False
    
    return True

def validate_file_content(file_stream, filename):
    """Validate file content matches expected image format"""
    try:
        # Reset stream position
        file_stream.seek(0)
        
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        if mime_type not in ALLOWED_MIME_TYPES:
            return False
        
        # Try to open as image to verify it's actually an image
        file_stream.seek(0)
        img = Image.open(file_stream)
        img.verify()  # Verify it's a valid image
        
        # Reset stream for later use
        file_stream.seek(0)
        return True
    except Exception:
        return False

def allowed_file(fn):
    """Enhanced file validation with security checks"""
    if not fn or not validate_filename_security(fn):
        return False
    
    return '.' in fn and fn.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_time_left(expiry_str):
    try:
        expiry = datetime.fromisoformat(expiry_str)
        rem = expiry - datetime.now()
        if rem.total_seconds() <= 0:
            return "Expired"
        days = rem.days
        hrs = rem.seconds // 3600
        mins = (rem.seconds % 3600) // 60
        if days > 0:
            return f"~{days} days {hrs} hours"
        if hrs > 0:
            return f"~{hrs} hours {mins} minutes"
        return f"~{mins} minutes"
    except (ValueError, TypeError):
        return "N/A"

def process_and_encrypt_image(stream, orig_fn, keep_exif=False):
    try:
        img = Image.open(stream)
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        buf = BytesIO()
        exif = img.info.get('exif') if keep_exif and 'exif' in img.info else None
        
        save_params = {'quality': 80}
        if exif:
            save_params['exif'] = exif
        
        img.save(buf, 'WEBP', **save_params)
        buf.seek(0)
        encrypted = fernet.encrypt(buf.read())
        
        new_fn = f"{uuid.uuid4().hex}.webp"
        path = os.path.join(app.config['UPLOAD_FOLDER'], new_fn)
        with open(path, 'wb') as f:
            f.write(encrypted)
        return new_fn
    except Exception as e:
        app.logger.error(f"Image processing failed: {sanitize_error_message(e)}")
        return None

@app.context_processor
def inject_announcement():
    try:
        with open('announcement.txt', 'r') as f:
            msg = f.read().strip()
        if msg:
            return dict(announcement_enabled=True, announcement_message=msg)
    except FileNotFoundError:
        pass
    return dict(announcement_enabled=False, announcement_message='')

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(e):
    flash('Content not found or has expired.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(410)
def gone(e):
    flash('Content has expired due to exceeding its view limit.', 'error')
    return redirect(url_for('index'))
    
@app.errorhandler(413)
def too_large(e):
    if request.path.startswith('/api/'):
        return jsonify(error="File is too large (max 10MB)."), 413
    flash('File is too large (max 10MB).', 'error')
    return redirect(url_for('index'))

@app.errorhandler(429)
def rate_limited(e):
    if request.path.startswith('/api/'):
        return jsonify(error=f"Rate limit exceeded: {e.description}"), 429
    flash('Too many requests. Please wait a while.', 'error')
    return redirect(url_for('index'))

# --- Health Check ---
@app.route('/healthz')
def healthz():
    try:
        conn = sqlite3.connect(app.config['DATABASE_PATH'])
        conn.execute("SELECT 1").fetchone()
        conn.close()
        db_status = "ok"
    except Exception as e:
        app.logger.error(f"Health check DB error: {sanitize_error_message(e)}")
        db_status = "error"
    sched_status = "running" if scheduler.running and scheduler.state == 1 else "stopped"
    return jsonify(database=db_status, scheduler=sched_status)

# --- Web UI Routes ---
@app.route('/')
def index():
    db = get_db()
    rows = db.execute("SELECT stat_key, stat_value FROM stats").fetchall()
    stats = {r['stat_key']: r['stat_value'] for r in rows}
    # We want 'text' to be at the top of the list in the index page dropdown
    index_languages = [lang for lang in POPULAR_LANGUAGES if lang != 'text']
    return render_template(
        'index.html',
        languages=index_languages,
        stats=stats,
        allowed_extensions=list(ALLOWED_EXTENSIONS)
    )

@app.route('/donate')
def donate_page():
    return render_template('donate.html')

if not app.config.get('ADMIN_URL'):
    raise ValueError("Configuration Error: SSP_ADMIN_URL is not set.")

@app.route(app.config['ADMIN_URL'], methods=['GET', 'POST'])
def admin_dashboard():
    if request.method == 'POST':
        pw = request.form.get('password', '')
        if app.config['ADMIN_PASSWORD_HASH'] and check_password_hash(app.config['ADMIN_PASSWORD_HASH'], pw):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash('Incorrect password.', 'error')

    if not session.get('admin_logged_in'):
        return render_template('admin.html', auth_success=False)

    db = get_db()
    now = datetime.now()
    imgs = db.execute("SELECT id, expiry_date, view_count, max_views FROM images ORDER BY expiry_date ASC").fetchall()
    past = db.execute("SELECT id, language, expiry_date, view_count, max_views FROM pastes ORDER BY expiry_date ASC").fetchall()

    images = [(i['id'], i['expiry_date'], get_time_left(i['expiry_date']), i['view_count'], i['max_views']) for i in imgs]
    pastes = [(p['id'], p['language'], p['expiry_date'], get_time_left(p['expiry_date']), p['view_count'], p['max_views']) for p in past]
    
    return render_template('admin.html', auth_success=True, images=images, pastes=pastes)

@app.route('/upload/image', methods=['POST'])
@limiter.limit("10 per hour")
def upload_image():
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('index', _anchor='image'))
        
    file = request.files['file']
    if file and allowed_file(file.filename) and validate_file_content(file.stream, file.filename):
        keep_exif = bool(request.form.get('keep_exif'))
        new_fn = process_and_encrypt_image(file.stream, file.filename, keep_exif)
        if not new_fn:
            flash('Error processing image.', 'error')
            return redirect(url_for('index', _anchor='image'))
            
        now = datetime.now()
        expiry = now + EXPIRY_MAP.get(request.form.get('expiry', '1h'), timedelta(hours=1))
        pw = request.form.get('password') or None
        pw_hash = generate_password_hash(pw, method='pbkdf2:sha256') if pw else None
        mv = request.form.get('max_views')
        mv = int(mv) if mv and mv.isdigit() else None

        db = get_db()
        db.execute(
            'INSERT INTO images (id, upload_date, expiry_date, password_hash, max_views, view_count) VALUES (?, ?, ?, ?, ?, ?)',
            (new_fn, now, expiry, pw_hash, mv, -1)
        )
        db.commit()
        update_stat('total_images')
        
        flash('Image uploaded successfully! This is your shareable link.', 'success')
        return redirect(url_for('view_image', filename=new_fn))

    flash('Invalid file type.', 'error')
    return redirect(url_for('index', _anchor='image'))


@app.route('/upload/paste', methods=['POST'])
@limiter.limit("20 per hour")
def upload_paste():
    content = request.form.get('content', '').strip()
    if not content:
        flash('Paste content cannot be empty.', 'error')
        return redirect(url_for('index', _anchor='paste'))
    
    # Input validation and size limits
    if len(content) > 1024 * 1024:  # 1MB limit for pastes
        flash('Paste content is too large (max 1MB).', 'error')
        return redirect(url_for('index', _anchor='paste'))
        
    now = datetime.now()
    expiry = now + EXPIRY_MAP.get(request.form.get('expiry', '1h'), timedelta(hours=1))
    pw = request.form.get('password') or None
    pw_hash = generate_password_hash(pw, method='pbkdf2:sha256') if pw else None
    mv = request.form.get('max_views')
    mv = int(mv) if mv and mv.isdigit() else None

    paste_id = uuid.uuid4().hex
    encrypted = fernet.encrypt(content.encode('utf-8'))
    db = get_db()
    db.execute(
        'INSERT INTO pastes (id, content, language, expiry_date, password_hash, max_views, view_count) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (paste_id, encrypted, request.form.get('language', 'text'), expiry, pw_hash, mv, -1)
    )
    db.commit()
    update_stat('total_pastes')
    
    flash('Paste created successfully! This is your shareable link.', 'success')
    return redirect(url_for('view_paste', paste_id=paste_id))


@app.route('/image/<filename>', methods=['GET', 'POST'])
def view_image(filename):
    db = get_db()
    row = db.execute("SELECT * FROM images WHERE id = ?", (filename,)).fetchone()

    if not row or datetime.now() > datetime.fromisoformat(row['expiry_date']):
        if row: # If row exists but is expired, delete it.
            db.execute("DELETE FROM images WHERE id = ?", (filename,))
            db.commit()
        abort(404)

    pw_hash = row['password_hash']
    session_key = f'unlocked_image_{filename}'
    if pw_hash and not session.get(session_key):
        if request.method == 'POST':
            if check_password_hash(pw_hash, request.form.get('password', '')):
                session[session_key] = secrets.token_hex(16)
                return redirect(url_for('view_image', filename=filename))
            flash('Incorrect password.', 'error')
        return render_template('view_image.html', password_required=True, filename=filename)

    return render_template('view_image.html',
                           password_required=False,
                           filename=filename,
                           time_left=get_time_left(row['expiry_date'])
                           )


@app.route('/paste/<paste_id>', methods=['GET', 'POST'])
def view_paste(paste_id):
    db = get_db()
    row = db.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()

    if not row or datetime.now() > datetime.fromisoformat(row['expiry_date']):
        if row:
            db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
            db.commit()
        abort(404)

    pw_hash = row['password_hash']
    session_key = f'unlocked_paste_{paste_id}'
    if pw_hash and not session.get(session_key):
        if request.method == 'POST':
            if check_password_hash(pw_hash, request.form.get('password', '')):
                session[session_key] = secrets.token_hex(16)
                return redirect(url_for('view_paste', paste_id=paste_id))
            flash('Incorrect password.', 'error')
        return render_template('view_paste.html', password_required=True, paste_id=paste_id)

    if row['max_views'] is not None and row['view_count'] >= row['max_views']:
        db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
        db.commit()
        abort(410)

    # Only increment view count on the initial, non-overridden view
    if 'lang' not in request.args:
        db.execute("UPDATE pastes SET view_count = view_count + 1 WHERE id = ?", (paste_id,))
        db.commit()

    content = fernet.decrypt(row['content']).decode('utf-8')
    
    # Get the language, allowing for a user override via URL parameter
    default_language = row['language']
    selected_language = request.args.get('lang', default_language)

    try:
        lexer = get_lexer_by_name(selected_language)
    except:
        lexer = get_lexer_by_name('text')
        
    fmt = HtmlFormatter(style='monokai', cssclass='syntax', linenos='table')
    highlighted = highlight(content, lexer, fmt)

    return render_template('view_paste.html',
                           password_required=False,
                           paste_id=paste_id,
                           highlighted_content=highlighted,
                           time_left=get_time_left(row['expiry_date']),
                           languages=POPULAR_LANGUAGES,
                           selected_language=selected_language
                           )


@app.route('/paste/<paste_id>/raw')
def paste_raw(paste_id):
    db = get_db()
    row = db.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()

    if not row or datetime.now() > datetime.fromisoformat(row['expiry_date']):
        abort(404)

    if row['password_hash'] and not session.get(f'unlocked_paste_{paste_id}'):
        abort(403) 

    if row['max_views'] is not None and row['view_count'] >= row['max_views']:
        db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
        db.commit()
        abort(410)

    db.execute("UPDATE pastes SET view_count = view_count + 1 WHERE id = ?", (paste_id,))
    db.commit()

    text = fernet.decrypt(row['content']).decode('utf-8')
    return Response(text, mimetype='text/plain')


@app.route('/uploads/<filename>')
def get_upload(filename):
    # Enhanced security validation
    if not validate_filename_security(filename):
        abort(404)
    
    safe_fn = secure_filename(filename)
    
    # Additional path traversal protection
    if safe_fn != filename or not safe_fn:
        abort(404)
    
    # Ensure the file path is within the upload directory
    upload_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
    file_path = os.path.abspath(os.path.join(upload_dir, safe_fn))
    
    if not file_path.startswith(upload_dir + os.sep):
        abort(404)
    
    path = file_path
    db = get_db()
    
    row = db.execute("SELECT * FROM images WHERE id = ?", (safe_fn,)).fetchone()

    if not row or not os.path.exists(path) or datetime.now() > datetime.fromisoformat(row['expiry_date']):
        if row: 
            db.execute("DELETE FROM images WHERE id = ?", (safe_fn,))
            db.commit()
            if os.path.exists(path): os.remove(path)
        abort(404)

    if row['password_hash'] and not session.get(f'unlocked_image_{safe_fn}'):
        abort(403) 

    if row['max_views'] is not None and row['view_count'] >= row['max_views']:
        db.execute("DELETE FROM images WHERE id = ?", (safe_fn,))
        db.commit()
        os.remove(path)
        abort(410)

    db.execute("UPDATE images SET view_count = view_count + 1 WHERE id = ?", (safe_fn,))
    db.commit()

    try:
        with open(path, 'rb') as f:
            encrypted = f.read()
        data = fernet.decrypt(encrypted)
        return send_file(BytesIO(data), mimetype='image/webp')
    except Exception as e:
        app.logger.error(f"Error serving image: {sanitize_error_message(e)}")
        abort(500)

@app.route('/admin/delete/image/<filename>', methods=['POST'])
def delete_image(filename):
    if not session.get('admin_logged_in'): abort(401)
    safe = secure_filename(filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], safe)
    try:
        if os.path.exists(path): os.remove(path)
        db = get_db()
        db.execute("DELETE FROM images WHERE id = ?", (safe,))
        db.commit()
        flash(f'Image "{safe}" has been deleted.', 'success')
    except Exception as e:
        flash('Error deleting image file.', 'error')
        app.logger.error(f'Error deleting image file: {sanitize_error_message(e)}')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/paste/<paste_id>', methods=['POST'])
def delete_paste(paste_id):
    if not session.get('admin_logged_in'): abort(401)
    try:
        db = get_db()
        db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
        db.commit()
        flash(f'Paste "{paste_id}" has been deleted.', 'success')
    except Exception as e:
        flash('Error deleting paste.', 'error')
        app.logger.error(f'Error deleting paste: {sanitize_error_message(e)}')
    return redirect(url_for('admin_dashboard'))

# --- API Routes ---
@app.route('/api/upload/image', methods=['POST'])
@limiter.limit("50 per hour")
def api_upload_image():
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify(error="No file selected"), 400
        
    file = request.files['file']
    if file and allowed_file(file.filename) and validate_file_content(file.stream, file.filename):
        new_fn = process_and_encrypt_image(file.stream, file.filename, bool(request.form.get('keep_exif')))
        if not new_fn: return jsonify(error="Failed to process image"), 500
        
        now = datetime.now()
        expiry = now + EXPIRY_MAP.get(request.form.get('expiry', '1h'), timedelta(hours=1))
        pw = request.form.get('password')
        pw_hash = generate_password_hash(pw, method='pbkdf2:sha256') if pw else None
        mv = request.form.get('max_views')
        mv = int(mv) if mv and mv.isdigit() else None

        db = get_db()
        db.execute(
            'INSERT INTO images (id, upload_date, expiry_date, password_hash, max_views, view_count) VALUES (?, ?, ?, ?, ?, ?)',
            (new_fn, now, expiry, pw_hash, mv, -1)
        )
        db.commit()
        update_stat('total_api_uploads')
        return jsonify(success=True, url=url_for('get_upload', filename=new_fn, _external=True)), 200

    return jsonify(error="Invalid file type"), 400


@app.route('/api/upload/paste', methods=['POST'])
@limiter.limit("100 per hour")
def api_upload_paste():
    if not request.is_json: return jsonify(error="Request must be JSON"), 400
        
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify(error="Invalid JSON data"), 400
    
    content = data.get('content', '').strip()
    if not content: return jsonify(error="Paste content is missing"), 400
    
    # Input validation and size limits
    if len(content) > 1024 * 1024:  # 1MB limit for pastes
        return jsonify(error="Paste content is too large (max 1MB)"), 400
        
    now = datetime.now()
    expiry = now + EXPIRY_MAP.get(data.get('expiry', '1h'), timedelta(hours=1))
    pw = data.get('password')
    pw_hash = generate_password_hash(pw, method='pbkdf2:sha256') if pw else None
    mv = data.get('max_views')
    mv = int(mv) if mv and str(mv).isdigit() else None

    paste_id = uuid.uuid4().hex
    encrypted = fernet.encrypt(content.encode('utf-8'))
    db = get_db()
    db.execute(
        'INSERT INTO pastes (id, content, language, expiry_date, password_hash, max_views, view_count) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (paste_id, encrypted, data.get('language', 'text'), expiry, pw_hash, mv, -1)
    )
    db.commit()
    update_stat('total_api_uploads')
    return jsonify(success=True, url=url_for('view_paste', paste_id=paste_id, _external=True)), 200


if __name__ == '__main__':
    required_vars = ['SSP_SECRET_KEY', 'SSP_ADMIN_PASSWORD_HASH', 'SSP_ADMIN_URL', 'SSP_ENCRYPTION_KEY']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        print(f"FATAL ERROR: Required environment variables are not set: {', '.join(missing_vars)}")
        exit(1)

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        init_db()
    scheduler.add_job(cleanup_expired_content, 'interval', minutes=15)
    scheduler.start()
    
    print(f"Starting Flask app with debug mode: {app.config['FLASK_DEBUG']}")
    
    # Run the app. Debug mode is controlled by the SSP_FLASK_DEBUG environment variable.
    # For production, it's recommended to use a proper WSGI server like Gunicorn or uWSGI.
    app.run(debug=app.config['FLASK_DEBUG'], use_reloader=False)