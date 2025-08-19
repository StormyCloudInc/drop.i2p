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
from flask_wtf.csrf import CSRFProtect

from PIL import Image
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
import time
import logging
import json
from dotenv import load_dotenv

# Load environment variables from a .env file
load_dotenv()

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Note: CSRF protection would be initialized here if Flask-WTF is available
csrf = CSRFProtect(app)


app.config['SECRET_KEY'] = os.getenv('SSP_SECRET_KEY')
app.config['ADMIN_PASSWORD_HASH'] = os.getenv('SSP_ADMIN_PASSWORD_HASH')
app.config['ADMIN_URL'] = os.getenv('SSP_ADMIN_URL')

# Clearnet configuration
app.config['CLEARNET_DOMAIN'] = os.getenv('SSP_CLEARNET_DOMAIN', 'drop.stormycloud.org')
app.config['I2P_DOMAIN'] = os.getenv('SSP_I2P_DOMAIN', 'drop.i2p')

# Mobile app API key for clearnet authentication
app.config['MOBILE_API_KEY'] = os.getenv('SSP_MOBILE_API_KEY')

# SSL certificate paths for monitoring
app.config['SSL_CERT_PATH'] = os.getenv('SSP_SSL_CERT_PATH', '/etc/letsencrypt/live/drop.stormycloud.org/fullchain.pem')
app.config['SSL_KEY_PATH'] = os.getenv('SSP_SSL_KEY_PATH', '/etc/letsencrypt/live/drop.stormycloud.org/privkey.pem')

enc_key = os.getenv('SSP_ENCRYPTION_KEY')
if not enc_key:
    raise ValueError("FATAL: SSP_ENCRYPTION_KEY is not set in the environment.")
app.config['ENCRYPTION_KEY'] = enc_key.encode('utf-8')

app.config['UPLOAD_FOLDER'] = os.getenv('SSP_UPLOAD_FOLDER', 'uploads')
app.config['DATABASE_PATH'] = os.getenv('SSP_DATABASE_PATH', 'database.db')
def _to_int(default_val, env_val):
    try:
        return int(env_val)
    except Exception:
        return default_val

# Max upload size (in MB) via env, default 25MB
max_mb_env = os.getenv('MAX_UPLOAD_MB', '25')
app.config['MAX_CONTENT_LENGTH'] = _to_int(25, max_mb_env) * 1024 * 1024

# API key and domain from env
app.config['API_KEY'] = os.getenv('API_KEY')
app.config['DOMAIN'] = os.getenv('DOMAIN', app.config.get('CLEARNET_DOMAIN', 'drop.stormycloud.org'))

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

# --- Host Detection and Validation ---
def is_clearnet_request():
    """Detect if request is coming from clearnet domain"""
    host = request.headers.get('Host', '').lower()
    clearnet_host = app.config.get('CLEARNET_DOMAIN') or app.config.get('DOMAIN') or ''
    return clearnet_host.lower() in host

def is_i2p_request():
    """Detect if request is coming from I2P domain"""
    host = request.headers.get('Host', '').lower()
    b32_header = request.headers.get('X-I2P-DestB32')
    return app.config['I2P_DOMAIN'].lower() in host or bool(b32_header)

def validate_host():
    """Validate that the request is from an allowed host"""
    host = request.headers.get('Host', '').lower()
    allowed_hosts = [app.config['CLEARNET_DOMAIN'].lower(), app.config['I2P_DOMAIN'].lower()]
    return any(allowed_host in host for allowed_host in allowed_hosts)

def validate_mobile_api_key():
    """Validate mobile app API key for clearnet requests"""
    if not app.config.get('MOBILE_API_KEY'):
        return True  # If no API key is configured, allow all requests
    
    api_key = request.headers.get('X-API-Key')
    return api_key == app.config['MOBILE_API_KEY']

def block_clearnet_web_access():
    """Block clearnet users from accessing web interface - API only"""
    if is_clearnet_request():
        return jsonify(error="Web interface not available via clearnet. Use API endpoints only."), 403
    return None

def get_appropriate_base_url():
    """Get the appropriate base URL based on request source"""
    if is_clearnet_request():
        return f"https://{app.config.get('CLEARNET_DOMAIN') or app.config.get('DOMAIN')}"
    else:
        return f"http://{app.config['I2P_DOMAIN']}"

# --- Rate Limiting (I2P-aware + Clearnet-aware) ---
def smart_key_func():
    """Smart rate limiting key function for both I2P and clearnet"""
    # For I2P: Prioritize the I2P destination header for rate limiting
    b32 = request.headers.get('X-I2P-DestB32')
    if b32:
        return f"i2p:{b32}"
    
    # For clearnet: Use IP-based limiting
    if is_clearnet_request():
        fwd = request.headers.get('X-Forwarded-For')
        if fwd:
            return f"clearnet:{fwd.split(',')[0].strip()}"
        return f"clearnet:{get_remote_address()}"
    
    # Fallback for any other case
    return f"unknown:{get_remote_address()}"

limiter = Limiter(
    app=app,
    key_func=smart_key_func,
    # Keep conservative global defaults; API-specific limiter below enforces 10 rps
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Clearnet-specific rate limits (more restrictive)
def clearnet_rate_limit(limit_string):
    """Apply stricter rate limiting for clearnet requests"""
    def decorator(f):
        if is_clearnet_request():
            return limiter.limit(limit_string)(f)
        return f
    return decorator

fernet = Fernet(app.config['ENCRYPTION_KEY'])

# --- Security headers ---
@app.after_request
def add_security_headers(resp):
    resp.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Permissions-Policy'] = "camera=(), microphone=(), geolocation=()"
    resp.headers['Content-Security-Policy'] = "default-src 'none'"
    return resp

# --- Logging filter to scrub sensitive headers ---
class RedactAuthFilter(logging.Filter):
    def filter(self, record):
        try:
            msg = str(record.getMessage())
            if 'Authorization' in msg:
                msg = msg.replace(request.headers.get('Authorization', ''), 'REDACTED')
            if 'X-API-Key' in msg:
                msg = msg.replace(request.headers.get('X-API-Key', ''), 'REDACTED')
            record.msg = msg
        except Exception:
            pass
        return True

app.logger.addFilter(RedactAuthFilter())

# --- API key authentication (clearnet /api/* only) ---
def _extract_bearer_token(auth_header):
    if not auth_header:
        return None
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == 'bearer':
        return parts[1]
    return None

def _get_client_ip():
    fwd = request.headers.get('X-Forwarded-For')
    if fwd:
        return fwd.split(',')[0].strip()
    return request.remote_addr or 'unknown'

# Simple token-bucket per-IP for API: 10 req/s with burst 20
_rate_lock = threading.Lock()
_buckets = {}
_RATE_PER_SEC = 10.0
_BURST = 20.0

def _rate_limit_check():
    if not request.path.startswith('/api/'):
        return True
    ip = _get_client_ip()
    now = time.time()
    with _rate_lock:
        bucket = _buckets.get(ip)
        if not bucket:
            bucket = {'tokens': _BURST, 'last': now}
            _buckets[ip] = bucket
        # Refill
        elapsed = max(0.0, now - bucket['last'])
        bucket['tokens'] = min(_BURST, bucket['tokens'] + elapsed * _RATE_PER_SEC)
        bucket['last'] = now
        if bucket['tokens'] >= 1.0:
            bucket['tokens'] -= 1.0
            return True
        return False

def _unauthorized_response():
    resp = jsonify({"detail": "Unauthorized"})
    resp.status_code = 401
    resp.headers['WWW-Authenticate'] = 'Bearer'
    return resp

def _forbidden_response():
    return jsonify({"detail": "Forbidden"}), 403

@app.before_request
def clearnet_api_enforcement():
    # Scrub sensitive inbound headers from being logged downstream
    try:
        if 'HTTP_AUTHORIZATION' in request.environ:
            request.environ['HTTP_AUTHORIZATION'] = 'REDACTED'
        if 'HTTP_X_API_KEY' in request.environ:
            request.environ['HTTP_X_API_KEY'] = 'REDACTED'
    except Exception:
        pass

    host = (request.headers.get('Host') or '').lower()
    clearnet_host = (app.config.get('CLEARNET_DOMAIN') or app.config.get('DOMAIN') or '').lower()
    i2p_host = (app.config.get('I2P_DOMAIN') or '').lower()

    # Deny unknown hosts entirely (except ssl-status) to avoid accidental exposure via IP/other hostnames
    if host and host not in {clearnet_host, i2p_host} and request.path != '/ssl-status':
        return _forbidden_response()

    if not is_clearnet_request():
        return None

    # Allow public SSL status
    if request.path == '/ssl-status':
        return None

    # Default deny for non-API on clearnet
    if not request.path.startswith('/api/'):
        # Always return JSON for clearnet non-API
        return _forbidden_response()

    # API paths: enforce API key and rate limit
    if not _rate_limit_check():
        return jsonify({"detail": "Too Many Requests"}), 429

    configured_key = app.config.get('API_KEY')
    # Backward compatibility: fall back to existing MOBILE_API_KEY if API_KEY not set
    if not configured_key:
        configured_key = app.config.get('MOBILE_API_KEY')

    if not configured_key:
        # If no key configured, require one as per spec: deny
        return _unauthorized_response()

    auth_header = request.headers.get('Authorization')
    token = _extract_bearer_token(auth_header)
    x_api = request.headers.get('X-API-Key')
    supplied = token or x_api

    if not supplied or supplied != configured_key:
        return _unauthorized_response()
    return None

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
        return jsonify(error=f"File is too large (max {int(app.config['MAX_CONTENT_LENGTH']/(1024*1024))}MB)."), 413
    flash(f"File is too large (max {int(app.config['MAX_CONTENT_LENGTH']/(1024*1024))}MB).", 'error')
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


# --- SSL Status Monitoring for UptimeRobot ---
@app.route('/ssl-status')
def ssl_status():
    # Public, non-auth endpoint for UptimeRobot SSL monitoring
    return Response("ok", mimetype='text/plain')

# Auth-required API health
@app.route('/api/health')
def api_health():
    return jsonify(status="ok"), 200

# --- Web UI Routes ---
@app.route('/')
def index():
    # Block clearnet users from web interface
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
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
    # Block clearnet users from web interface
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
    return render_template('donate.html')

if not app.config.get('ADMIN_URL'):
    raise ValueError("Configuration Error: SSP_ADMIN_URL is not set.")

@app.route(app.config['ADMIN_URL'], methods=['GET', 'POST'])
def admin_dashboard():
    # Block clearnet users from admin interface
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
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
    # Block clearnet users from web upload form
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
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
    # Block clearnet users from web upload form
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
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
    # Block clearnet users from viewing images via web interface
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
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
    # Block clearnet users from viewing pastes via web interface
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
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
    # Block clearnet users from raw paste access
    block_check = block_clearnet_web_access()
    if block_check:
        return block_check
        
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
@csrf.exempt
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
        base_url = get_appropriate_base_url()
        upload_url = f"{base_url}/uploads/{new_fn}"
        return jsonify(success=True, url=upload_url), 200

    return jsonify(error="Invalid file type"), 400


@app.route('/api/upload/paste', methods=['POST'])
@limiter.limit("100 per hour")
@csrf.exempt
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
    base_url = get_appropriate_base_url()
    paste_url = f"{base_url}/paste/{paste_id}"
    return jsonify(success=True, url=paste_url), 200


# --- Clearnet-Specific API Routes ---
@app.route('/api/clearnet/upload/image', methods=['POST'])
@limiter.limit("30 per hour")  # More restrictive for clearnet
@csrf.exempt
def api_clearnet_upload_image():
    """Clearnet-specific image upload endpoint with mobile app authentication"""
    # Validate that this is actually a clearnet request
    if not is_clearnet_request():
        return jsonify(error="This endpoint is only available via clearnet"), 403
    
    if not validate_host():
        return jsonify(error="Invalid host"), 400
    
    # Validate mobile API key
    if not validate_mobile_api_key():
        return jsonify(error="Invalid or missing API key"), 401
    
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
        
        # Always return clearnet URL for clearnet uploads
        clearnet_url = f"https://{app.config['CLEARNET_DOMAIN']}/uploads/{new_fn}"
        return jsonify(success=True, url=clearnet_url, source="clearnet"), 200

    return jsonify(error="Invalid file type"), 400


@app.route('/api/clearnet/upload/paste', methods=['POST'])
@limiter.limit("60 per hour")  # More restrictive for clearnet
@csrf.exempt
def api_clearnet_upload_paste():
    """Clearnet-specific paste upload endpoint with mobile app authentication"""
    # Validate that this is actually a clearnet request
    if not is_clearnet_request():
        return jsonify(error="This endpoint is only available via clearnet"), 403
    
    if not validate_host():
        return jsonify(error="Invalid host"), 400
    
    # Validate mobile API key
    if not validate_mobile_api_key():
        return jsonify(error="Invalid or missing API key"), 401
    
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
    
    # Always return clearnet URL for clearnet uploads
    clearnet_url = f"https://{app.config['CLEARNET_DOMAIN']}/paste/{paste_id}"
    return jsonify(success=True, url=clearnet_url, source="clearnet"), 200


# --- End-to-End Encryption API Endpoints ---
@app.route('/api/clearnet/upload/image/encrypted', methods=['POST'])
@limiter.limit("20 per hour")  # Even more restrictive for E2E
@csrf.exempt
def api_clearnet_upload_image_encrypted():
    """End-to-end encrypted image upload for mobile app"""
    # Validate clearnet request and API key
    if not is_clearnet_request():
        return jsonify(error="This endpoint is only available via clearnet"), 403
    
    if not validate_host():
        return jsonify(error="Invalid host"), 400
    
    if not validate_mobile_api_key():
        return jsonify(error="Invalid or missing API key"), 401
    
    # For E2E encrypted uploads, we expect base64 encoded encrypted data
    if not request.is_json:
        return jsonify(error="Request must be JSON for encrypted uploads"), 400
    
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify(error="Invalid JSON data"), 400
    
    # Validate required fields for encrypted upload
    encrypted_data = data.get('encrypted_data')
    client_iv = data.get('iv')  # Initialization vector used by client
    content_type = data.get('content_type', 'image/webp')
    
    if not encrypted_data or not client_iv:
        return jsonify(error="Missing encrypted_data or iv"), 400
    
    # Validate data size (base64 encoded, so account for encoding overhead)
    if len(encrypted_data) > 15 * 1024 * 1024:  # ~15MB to account for base64 encoding
        return jsonify(error="Encrypted data too large"), 400
    
    try:
        # Store the client-encrypted data directly (double encryption)
        now = datetime.now()
        expiry = now + EXPIRY_MAP.get(data.get('expiry', '1h'), timedelta(hours=1))
        pw = data.get('password')
        pw_hash = generate_password_hash(pw, method='pbkdf2:sha256') if pw else None
        mv = data.get('max_views')
        mv = int(mv) if mv and str(mv).isdigit() else None
        
        # Generate unique filename
        image_id = uuid.uuid4().hex
        
        # Store metadata about the encrypted upload
        upload_metadata = {
            'client_encrypted': True,
            'content_type': content_type,
            'iv': client_iv,
            'upload_source': 'mobile_app_e2e'
        }
        
        # Encrypt the client-encrypted data again for server-side storage
        metadata_json = json.dumps(upload_metadata)
        combined_data = f"{metadata_json}||{encrypted_data}"
        server_encrypted = fernet.encrypt(combined_data.encode('utf-8'))
        
        # Store in database as encrypted image
        db = get_db()
        db.execute(
            'INSERT INTO images (id, upload_date, expiry_date, password_hash, max_views, view_count) VALUES (?, ?, ?, ?, ?, ?)',
            (image_id, now, expiry, pw_hash, mv, -1)
        )
        
        # Store the encrypted data as a file
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], image_id)
        with open(upload_path, 'wb') as f:
            f.write(server_encrypted)
        
        db.commit()
        update_stat('total_api_uploads')
        
        # Return the viewing URL and decryption info
        clearnet_url = f"https://{app.config['CLEARNET_DOMAIN']}/image/encrypted/{image_id}"
        return jsonify({
            'success': True,
            'url': clearnet_url,
            'image_id': image_id,
            'source': 'clearnet_e2e',
            'requires_client_decryption': True
        }), 200
        
    except Exception as e:
        app.logger.error(f"E2E image upload failed: {sanitize_error_message(e)}")
        return jsonify(error="Failed to process encrypted upload"), 500


@app.route('/api/clearnet/upload/paste/encrypted', methods=['POST'])
@limiter.limit("40 per hour")  # More restrictive for E2E
@csrf.exempt
def api_clearnet_upload_paste_encrypted():
    """End-to-end encrypted paste upload for mobile app"""
    # Validate clearnet request and API key
    if not is_clearnet_request():
        return jsonify(error="This endpoint is only available via clearnet"), 403
    
    if not validate_host():
        return jsonify(error="Invalid host"), 400
    
    if not validate_mobile_api_key():
        return jsonify(error="Invalid or missing API key"), 401
    
    if not request.is_json:
        return jsonify(error="Request must be JSON for encrypted uploads"), 400
    
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify(error="Invalid JSON data"), 400
    
    # Validate required fields
    encrypted_content = data.get('encrypted_content')
    client_iv = data.get('iv')
    language = data.get('language', 'text')
    
    if not encrypted_content or not client_iv:
        return jsonify(error="Missing encrypted_content or iv"), 400
    
    # Size validation
    if len(encrypted_content) > 2 * 1024 * 1024:  # 2MB for encrypted pastes
        return jsonify(error="Encrypted content too large"), 400
    
    try:
        now = datetime.now()
        expiry = now + EXPIRY_MAP.get(data.get('expiry', '1h'), timedelta(hours=1))
        pw = data.get('password')
        pw_hash = generate_password_hash(pw, method='pbkdf2:sha256') if pw else None
        mv = data.get('max_views')
        mv = int(mv) if mv and str(mv).isdigit() else None
        
        paste_id = uuid.uuid4().hex
        
        # Store metadata about the encrypted paste
        paste_metadata = {
            'client_encrypted': True,
            'language': language,
            'iv': client_iv,
            'upload_source': 'mobile_app_e2e'
        }
        
        # Combine metadata and encrypted content
        metadata_json = json.dumps(paste_metadata)
        combined_data = f"{metadata_json}||{encrypted_content}"
        
        # Server-side encryption of the client-encrypted data
        server_encrypted = fernet.encrypt(combined_data.encode('utf-8'))
        
        db = get_db()
        db.execute(
            'INSERT INTO pastes (id, content, language, expiry_date, password_hash, max_views, view_count) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (paste_id, server_encrypted, 'encrypted', expiry, pw_hash, mv, -1)
        )
        db.commit()
        update_stat('total_api_uploads')
        
        # Return viewing URL
        clearnet_url = f"https://{app.config['CLEARNET_DOMAIN']}/paste/encrypted/{paste_id}"
        return jsonify({
            'success': True,
            'url': clearnet_url,
            'paste_id': paste_id,
            'source': 'clearnet_e2e',
            'requires_client_decryption': True
        }), 200
        
    except Exception as e:
        app.logger.error(f"E2E paste upload failed: {sanitize_error_message(e)}")
        return jsonify(error="Failed to process encrypted upload"), 500


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
    
    # SSL Configuration for production
    ssl_context = None
    cert_path = app.config.get('SSL_CERT_PATH')
    key_path = app.config.get('SSL_KEY_PATH')
    
    # Check if SSL certificates are available
    if cert_path and key_path and os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            ssl_context = (cert_path, key_path)
            print(f"SSL enabled: Using certificates from {cert_path}")
        except Exception as e:
            print(f"SSL setup failed: {e}")
            print("Running without SSL")
    else:
        print("SSL certificates not found or not configured. Running HTTP only.")
        print("For production with clearnet access, configure SSL certificates.")
    
    # Determine port and host
    port = int(os.getenv('SSP_PORT', 5001))
    host = os.getenv('SSP_HOST', '0.0.0.0')
    
    print(f"Server starting on {host}:{port}")
    if ssl_context:
        print(f"HTTPS enabled for clearnet domain: {app.config['CLEARNET_DOMAIN']}")
    print(f"I2P domain: {app.config['I2P_DOMAIN']}")
    
    # Run the app. Debug mode is controlled by the SSP_FLASK_DEBUG environment variable.
    # For production, it's recommended to use a proper WSGI server like Gunicorn or uWSGI.
    app.run(
        host=host,
        port=port,
        debug=app.config['FLASK_DEBUG'],
        ssl_context=ssl_context,
        use_reloader=False
    )
=======
# app.py

import os
import uuid
import sqlite3
from datetime import datetime, timedelta
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, g, abort, send_file, jsonify, Response
)
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

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

app.config['FLASK_DEBUG'] = os.getenv('SSP_FLASK_DEBUG', 'False').lower() in ('true', '1', 't')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'tiff'}

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
                app.logger.error(f"Error removing expired image file {path}: {e}")
            cur.execute("DELETE FROM images WHERE id = ?", (img_id,))
        conn.commit()
        conn.close()

# --- Utility Functions ---
def allowed_file(fn):
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
        app.logger.error(f"Image processing failed ({orig_fn}): {e}")
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
        app.logger.error(f"Health check DB error: {e}")
        db_status = "error"
    sched_status = "running" if scheduler.running and scheduler.state == 1 else "stopped"
    return jsonify(database=db_status, scheduler=sched_status)

# --- Web UI Routes ---
@app.route('/')
def index():
    # Block clearnet users from web interface
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
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
    # Block clearnet users from web interface
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
    return render_template('donate.html')

if not app.config.get('ADMIN_URL'):
    raise ValueError("Configuration Error: SSP_ADMIN_URL is not set.")

@app.route(app.config['ADMIN_URL'], methods=['GET', 'POST'])
def admin_dashboard():
    # Block clearnet users from admin interface
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
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
    # Block clearnet users from web upload form
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('index', _anchor='image'))
        
    file = request.files['file']
    if file and allowed_file(file.filename):
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
    # Block clearnet users from web upload form
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
    content = request.form.get('content', '').strip()
    if not content:
        flash('Paste content cannot be empty.', 'error')
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
    # Block clearnet users from viewing images
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
    db = get_db()
    row = db.execute("SELECT * FROM images WHERE id = ?", (filename,)).fetchone()

    if not row or datetime.now() > datetime.fromisoformat(row['expiry_date']):
        if row: # If row exists but is expired, delete it.
            db.execute("DELETE FROM images WHERE id = ?", (filename,))
            db.commit()
        abort(404)

    pw_hash = row['password_hash']
    if pw_hash and not session.get(f'unlocked_image_{filename}'):
        if request.method == 'POST':
            if check_password_hash(pw_hash, request.form.get('password', '')):
                session[f'unlocked_image_{filename}'] = True
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
    # Block clearnet users from viewing pastes
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
    db = get_db()
    row = db.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()

    if not row or datetime.now() > datetime.fromisoformat(row['expiry_date']):
        if row:
            db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
            db.commit()
        abort(404)

    pw_hash = row['password_hash']
    if pw_hash and not session.get(f'unlocked_paste_{paste_id}'):
        if request.method == 'POST':
            if check_password_hash(pw_hash, request.form.get('password', '')):
                session[f'unlocked_paste_{paste_id}'] = True
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
    # Block clearnet users from raw paste access
    if request.headers.get('Host', '').lower() == 'drop.stormycloud.org':
        abort(404)
        
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
    safe_fn = secure_filename(filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], safe_fn)
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
        app.logger.error(f"Error serving image {safe_fn}: {e}")
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
        flash(f'Error deleting image file: {e}', 'error')
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
        flash(f'Error deleting paste: {e}', 'error')
    return redirect(url_for('admin_dashboard'))

# --- API Routes ---
@app.route('/api/upload/image', methods=['POST'])
@limiter.limit("50 per hour")
def api_upload_image():
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify(error="No file selected"), 400
        
    file = request.files['file']
    if file and allowed_file(file.filename):
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
    content = data.get('content', '').strip()
    if not content: return jsonify(error="Paste content is missing"), 400
        
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

