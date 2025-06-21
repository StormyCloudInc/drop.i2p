import os
import uuid
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort, send_file, jsonify, session, g
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from io import BytesIO

# --- Library Imports ---
from PIL import Image
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv  # Import python-dotenv

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
app = Flask(__name__)
# This is the definitive fix for URL generation behind a proxy.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Load secrets from environment variables
app.config['SECRET_KEY'] = os.getenv('I2PCAKE_SECRET_KEY', 'default-dev-key-if-not-set')
app.config['ADMIN_PASSWORD'] = os.getenv('I2PCAKE_ADMIN_PASSWORD')
encryption_key = os.getenv('I2PCAKE_ENCRYPTION_KEY')
app.config['ENCRYPTION_KEY'] = encryption_key.encode('utf-8') if encryption_key else None

app.config['SERVER_NAME'] = 'drop.i2p'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'database.db'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
app.config['ADMIN_URL'] = '/s3cr3t-4dm1n-p4n3l-d3adbeef'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'tiff'}

# --- I2P-Aware Rate Limiting ---
def i2p_key_func():
    i2p_b32_address = request.headers.get('X-I2P-DestB32')
    if i2p_b32_address:
        return i2p_b32_address
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return get_remote_address()

limiter = Limiter(
    app=app,
    key_func=i2p_key_func,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# --- Cryptography Setup ---
fernet = Fernet(app.config['ENCRYPTION_KEY']) if app.config['ENCRYPTION_KEY'] else None

# --- Expiry Time Mapping ---
EXPIRY_MAP = {
    "15m": timedelta(minutes=15),
    "1h":  timedelta(hours=1),
    "2h":  timedelta(hours=2),
    "4h":  timedelta(hours=4),
    "8h":  timedelta(hours=8),
    "12h": timedelta(hours=12),
    "24h": timedelta(hours=24),
    "48h": timedelta(hours=48)
}

# --- Curated Language List ---
POPULAR_LANGUAGES = [
    'bash', 'c', 'cpp', 'csharp', 'css', 'go', 'html', 'java',
    'javascript', 'json', 'kotlin', 'lua', 'markdown', 'php',
    'python', 'ruby', 'rust', 'sql', 'swift', 'typescript',
    'xml', 'yaml'
]

# --- New Database Connection Management ---
def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        # Open connection
        db = sqlite3.connect(
            app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False
        )
        # Access columns by name
        db.row_factory = sqlite3.Row

        # Tune SQLite for higher throughput / lower tail latency
        db.execute("PRAGMA journal_mode = WAL;")
        db.execute("PRAGMA synchronous = NORMAL;")
        db.execute("PRAGMA busy_timeout = 5000;")  # wait up to 5s if database is locked

        g.db = db
    return g.db

def close_db(e=None):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Register the close_db function to be called when the app context is torn down
app.teardown_appcontext(close_db)

# --- Database Setup ---
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS pastes ('
            'id TEXT PRIMARY KEY, '
            'content BLOB NOT NULL, '
            'language TEXT NOT NULL, '
            'expiry_date DATETIME NOT NULL'
            ')'
        )
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS images ('
            'id TEXT PRIMARY KEY, '
            'upload_date DATETIME NOT NULL, '
            'expiry_date DATETIME NOT NULL'
            ')'
        )
        cursor.execute(
            'CREATE TABLE IF NOT EXISTS stats ('
            'stat_key TEXT PRIMARY KEY, '
            'stat_value INTEGER NOT NULL'
            ')'
        )
        stats_to_initialize = ['total_images', 'total_pastes', 'total_api_uploads']
        for stat in stats_to_initialize:
            cursor.execute(
                "INSERT OR IGNORE INTO stats (stat_key, stat_value) VALUES (?, 0)",
                (stat,)
            )
        db.commit()

# --- Statistics Helper ---
def update_stat(stat_key, increment=1):
    db = get_db()
    db.execute(
        "UPDATE stats SET stat_value = stat_value + ? WHERE stat_key = ?",
        (increment, stat_key)
    )
    db.commit()

# --- Deletion Scheduler Setup ---
scheduler = BackgroundScheduler(daemon=True)
def cleanup_expired_content():
    # This function runs in a background thread, so it needs its own app context
    with app.app_context():
        now = datetime.now()
        print(f"[{now}] Running cleanup job...")
        db = sqlite3.connect(app.config['DATABASE'])
        cursor = db.cursor()
        cursor.execute("DELETE FROM pastes WHERE expiry_date < ?", (now,))
        pastes_deleted = cursor.rowcount
        cursor.execute("SELECT id FROM images WHERE expiry_date < ?", (now,))
        expired_images = cursor.fetchall()
        images_deleted = 0
        for image_record in expired_images:
            filename = image_record[0]
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                os.remove(filepath)
                cursor.execute("DELETE FROM images WHERE id = ?", (filename,))
                images_deleted += 1
            except OSError:
                pass
        db.commit()
        db.close()
        if pastes_deleted > 0:
            print(f"Cleaned up {pastes_deleted} expired paste(s).")
        if images_deleted > 0:
            print(f"Cleaned up {images_deleted} expired image(s).")

# --- Helper Functions ---
def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

def process_and_encrypt_image(file_stream, original_filename):
    try:
        img = Image.open(file_stream)
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        output_buffer = BytesIO()
        img.save(output_buffer, 'webp', quality=80)
        output_buffer.seek(0)
        image_data = output_buffer.read()
        encrypted_data = fernet.encrypt(image_data)
        new_filename = f"{uuid.uuid4().hex}.webp"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
        return new_filename
    except Exception as e:
        print(f"Could not process image {original_filename}: {e}")
        return None

def get_time_left(expiry_date_str):
    if not expiry_date_str:
        return "N/A"
    try:
        expiry_date = datetime.fromisoformat(expiry_date_str)
        now = datetime.now()
        remaining = expiry_date - now
        if remaining.total_seconds() <= 0:
            return "Expired"
        days, seconds = remaining.days, remaining.seconds
        hours = days * 24 + seconds // 3600
        minutes = (seconds % 3600) // 60
        if hours > 0:
            return f"~{hours}h {minutes}m"
        else:
            return f"~{minutes}m"
    except Exception:
        return "Invalid date"

# Context processor to inject banner variables by reading from a file
@app.context_processor
def inject_announcement():
    try:
        with open('announcement.txt', 'r') as f:
            message = f.read().strip()
        if message:
            return dict(
                announcement_enabled=True,
                announcement_message=message
            )
    except FileNotFoundError:
        pass
    return dict(announcement_enabled=False, announcement_message='')

# --- Custom Error Handlers ---
@app.errorhandler(413)
def request_entity_too_large(error):
    if request.path.startswith('/api/'):
        return jsonify(error="File is too large (max 10MB)."), 413
    flash('File is too large (max 10MB). Please upload a smaller file.', 'error')
    return redirect(url_for('index'))

@app.errorhandler(429)
def ratelimit_handler(e):
    if request.path.startswith('/api/'):
        return jsonify(error=f"ratelimit exceeded: {e.description}"), 429
    flash('You have made too many requests. Please wait a while before trying again.', 'error')
    return redirect(url_for('index'))

# --- Web UI Routes ---
@app.route('/')
def index():
    db = get_db()
    stats_list = db.execute("SELECT stat_key, stat_value FROM stats").fetchall()
    stats = {row['stat_key']: row['stat_value'] for row in stats_list}
    return render_template(
        'index.html',
        languages=POPULAR_LANGUAGES,
        stats=stats,
        allowed_extensions=list(ALLOWED_EXTENSIONS)
    )

@app.route('/donate')
def donate_page():
    return render_template('donate.html')

@app.route(app.config['ADMIN_URL'], methods=['GET', 'POST'])
def admin_dashboard():
    if request.method == 'POST':
        password_attempt = request.form.get('password')
        if password_attempt == app.config['ADMIN_PASSWORD']:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Incorrect password.', 'error')

    if not session.get('admin_logged_in'):
        return render_template('admin.html', auth_success=False)

    db = get_db()
    now = datetime.now()
    images_raw = db.execute(
        "SELECT id, expiry_date FROM images WHERE expiry_date >= ? ORDER BY expiry_date ASC",
        (now,)
    ).fetchall()
    pastes_raw = db.execute(
        "SELECT id, language, expiry_date FROM pastes WHERE expiry_date >= ? ORDER BY expiry_date ASC",
        (now,)
    ).fetchall()

    images = [
        (i['id'], i['expiry_date'], get_time_left(i['expiry_date']))
        for i in images_raw
    ]
    pastes = [
        (p['id'], p['language'], p['expiry_date'], get_time_left(p['expiry_date']))
        for p in pastes_raw
    ]
    return render_template(
        'admin.html',
        images=images,
        pastes=pastes,
        auth_success=True
    )

@app.route('/upload/image', methods=['POST'])
@limiter.limit("10 per hour")
def upload_image():
    if 'file' not in request.files:
        flash('No file part in request.', 'error')
        return redirect(url_for('index', _anchor='image'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('index', _anchor='image'))
    if file and allowed_file(file.filename):
        new_filename = process_and_encrypt_image(file.stream, file.filename)
        if not new_filename:
            flash('There was an error processing the image.', 'error')
            return redirect(url_for('index', _anchor='image'))
        now = datetime.now()
        expiry_key = request.form.get('expiry', '1h')
        expiry_delta = EXPIRY_MAP.get(expiry_key, timedelta(hours=1))
        expiry_date = now + expiry_delta
        db = get_db()
        db.execute(
            "INSERT INTO images (id, upload_date, expiry_date) VALUES (?, ?, ?)",
            (new_filename, now, expiry_date)
        )
        db.commit()
        update_stat('total_images')
        return redirect(url_for('view_image', filename=new_filename))
    flash('Invalid file type. Please check the allowed formats.', 'error')
    return redirect(url_for('index', _anchor='image'))

@app.route('/upload/paste', methods=['POST'])
@limiter.limit("20 per hour")
def upload_paste():
    content = request.form.get('content')
    language = request.form.get('language', 'text')
    expiry_key = request.form.get('expiry', '1h')
    if not content or not content.strip():
        flash('Paste content cannot be empty.', 'error')
        return redirect(url_for('index', _anchor='paste'))
    paste_id = uuid.uuid4().hex
    expiry_delta = EXPIRY_MAP.get(expiry_key, timedelta(hours=1))
    expiry_date = datetime.now() + expiry_delta
    encrypted_content = fernet.encrypt(content.encode('utf-8'))
    db = get_db()
    db.execute(
        "INSERT INTO pastes (id, content, language, expiry_date) VALUES (?, ?, ?, ?)",
        (paste_id, encrypted_content, language, expiry_date)
    )
    db.commit()
    update_stat('total_pastes')
    return redirect(url_for('view_paste', paste_id=paste_id))

@app.route('/image/<filename>')
def view_image(filename):
    safe_filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    if not os.path.exists(filepath):
        flash('The image you requested has expired or does not exist.', 'error')
        return redirect(url_for('index'))
    return render_template('view_image.html', filename=safe_filename)

@app.route('/paste/<paste_id>')
def view_paste(paste_id):
    db = get_db()
    result = db.execute(
        "SELECT content, language FROM pastes WHERE id = ?",
        (paste_id,)
    ).fetchone()
    if result is None:
        flash('The paste you requested has expired or does not exist.', 'error')
        return redirect(url_for('index'))
    encrypted_content = result['content']
    language = result['language']
    decrypted_content = fernet.decrypt(encrypted_content).decode('utf-8')
    try:
        lexer = get_lexer_by_name(language)
    except:
        lexer = get_lexer_by_name('text')
    formatter = HtmlFormatter(
        style='monokai',
        cssclass="syntax",
        noclasses=False
    )
    highlighted_content = highlight(decrypted_content, lexer, formatter)
    css_styles = formatter.get_style_defs('.syntax')
    return render_template(
        'view_paste.html',
        paste_id=paste_id,
        highlighted_content=highlighted_content,
        css_styles=css_styles
    )

@app.route('/uploads/<filename>')
def get_upload(filename):
    safe_filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    try:
        with open(filepath, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        return send_file(BytesIO(decrypted_data), mimetype='image/webp')
    except (FileNotFoundError, IOError):
        abort(404)
    except Exception as e:
        print(f"Could not decrypt or serve file {filename}: {e}")
        abort(500)

@app.route('/admin/delete/image/<filename>', methods=['POST'])
def delete_image(filename):
    if not session.get('admin_logged_in'):
        abort(401)
    safe_filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    try:
        os.remove(filepath)
        db = get_db()
        db.execute("DELETE FROM images WHERE id = ?", (safe_filename,))
        db.commit()
        flash(f'Image "{safe_filename}" has been deleted.', 'success')
    except OSError as e:
        flash(f'Error deleting image file: {e}', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/paste/<paste_id>', methods=['POST'])
def delete_paste(paste_id):
    if not session.get('admin_logged_in'):
        abort(401)
    db = get_db()
    db.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
    db.commit()
    flash(f'Paste "{paste_id}" has been deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- API Routes ---
@app.route('/api/upload/image', methods=['POST'])
@limiter.limit("50 per hour")
def api_upload_image():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    if file and allowed_file(file.filename):
        new_filename = process_and_encrypt_image(file.stream, file.filename)
        if not new_filename:
            return jsonify({"error": "Failed to process image"}), 500
        now = datetime.now()
        expiry = request.form.get('expiry', '1h')
        expiry_delta = EXPIRY_MAP.get(expiry, timedelta(hours=1))
        expiry_date = now + expiry_delta
        db = get_db()
        db.execute(
            "INSERT INTO images (id, upload_date, expiry_date) VALUES (?, ?, ?)",
            (new_filename, now, expiry_date)
        )
        db.commit()
        update_stat('total_api_uploads')
        image_url = url_for('get_upload', filename=new_filename, _external=True)
        return jsonify({"success": True, "url": image_url, "expires_in": expiry}), 200
    return jsonify({"error": "Invalid file type. Please check the allowed formats."}), 400

@app.route('/api/upload/paste', methods=['POST'])
@limiter.limit("100 per hour")
def api_upload_paste():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    data = request.get_json()
    content = data.get('content')
    language = data.get('language', 'text')
    expiry = data.get('expiry', '1h')
    if not content:
        return jsonify({"error": "Paste content is missing"}), 400
    paste_id = uuid.uuid4().hex
    expiry_delta = EXPIRY_MAP.get(expiry, timedelta(hours=1))
    expiry_date = datetime.now() + expiry_delta
    encrypted_content = fernet.encrypt(content.encode('utf-8'))
    db = get_db()
    db.execute(
        "INSERT INTO pastes (id, content, language, expiry_date) VALUES (?, ?, ?, ?)",
        (paste_id, encrypted_content, language, expiry_date)
    )
    db.commit()
    update_stat('total_api_uploads')
    paste_url = url_for('view_paste', paste_id=paste_id, _external=True)
    return jsonify({"success": True, "url": paste_url, "expires_in": expiry}), 200

# --- Main Execution ---
if __name__ == '__main__':
    # Check if essential environment variables are set
    if not all([
        app.config['SECRET_KEY'],
        app.config['ADMIN_PASSWORD'],
        app.config['ENCRYPTION_KEY']
    ]):
        print("FATAL ERROR: One or more required environment variables are not set.")
        print("Please create a .env file or set them on your system.")
        exit(1)

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    init_db()
    scheduler.add_job(cleanup_expired_content, 'interval', minutes=30)
    scheduler.start()
    print("--- Deletion Scheduler and Cleanup Job are Running ---")
    app.run(debug=True, use_reloader=False)