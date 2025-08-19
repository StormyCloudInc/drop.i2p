#!/usr/bin/env python3

import os
import uuid
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from collections import defaultdict, deque
import logging

from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.base import BaseHTTPMiddleware
import uvicorn
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
from PIL import Image, ImageFile
from io import BytesIO

# Load environment variables from main .env file
load_dotenv()

# Configuration - Read from main .env file
API_KEY = os.getenv('SSP_MOBILE_API_KEY')
if not API_KEY:
    raise ValueError("FATAL: SSP_MOBILE_API_KEY is not set in the environment.")

DOMAIN = os.getenv('SSP_CLEARNET_DOMAIN', 'drop.stormycloud.org')
MAX_UPLOAD_MB = 10  # Mirror the 10MB limit from app.py
MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024  # Convert to bytes

# Mirror settings from app.py
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'ico', 'tiff'}
UPLOAD_FOLDER = os.getenv('SSP_UPLOAD_FOLDER', 'uploads')
DATABASE_PATH = os.getenv('SSP_DATABASE_PATH', 'database.db')

# Encryption key - must match app.py
enc_key = os.getenv('SSP_ENCRYPTION_KEY')
if not enc_key:
    raise ValueError("FATAL: SSP_ENCRYPTION_KEY is not set in the environment.")
fernet = Fernet(enc_key.encode('utf-8'))

# Expiry mapping - mirror from app.py
EXPIRY_MAP = {
    "15m": timedelta(minutes=15), "1h": timedelta(hours=1), "2h": timedelta(hours=2),
    "4h": timedelta(hours=4), "8h": timedelta(hours=8), "12h": timedelta(hours=12),
    "24h": timedelta(hours=24), "48h": timedelta(hours=48)
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Drop.i2p Clearnet API",
    description="Clearnet API service for drop.i2p file sharing",
    version="1.0.0",
    docs_url=None,  # Disable docs for security
    redoc_url=None  # Disable redoc for security
)

# Token bucket rate limiter
class TokenBucket:
    def __init__(self, capacity: int = 20, refill_rate: int = 10):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
    
    def consume(self, tokens: int = 1) -> bool:
        now = time.time()
        # Refill tokens based on time elapsed
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False

# In-memory rate limiter storage
rate_limiters: Dict[str, TokenBucket] = defaultdict(lambda: TokenBucket())

# Security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers to every response
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        
        return response

# Path restriction middleware - default deny except /mobile/* and /ssl-status
class PathRestrictionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Allow /ssl-status and /mobile/* paths
        if path == "/ssl-status" or path.startswith("/mobile/"):
            return await call_next(request)
        
        # Default deny - return 403 for all other paths
        return JSONResponse(
            status_code=403,
            content={"detail": "Forbidden"}
        )

# Rate limiting middleware
class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for /ssl-status
        if request.url.path == "/ssl-status":
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host
        if "X-Forwarded-For" in request.headers:
            client_ip = request.headers["X-Forwarded-For"].split(",")[0].strip()
        
        # Check rate limit
        bucket = rate_limiters[client_ip]
        if not bucket.consume():
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": "60"}
            )
        
        return await call_next(request)

# Body size middleware
class BodySizeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip for non-upload endpoints
        if not request.url.path.startswith("/mobile/upload"):
            return await call_next(request)
        
        # Check Content-Length header
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_CONTENT_LENGTH:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request entity too large"}
            )
        
        return await call_next(request)

# Add middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(PathRestrictionMiddleware)  
app.add_middleware(RateLimitMiddleware)
app.add_middleware(BodySizeMiddleware)

# Security: Prevent decompression bombs and truncated images
ImageFile.LOAD_TRUNCATED_IMAGES = False
Image.MAX_IMAGE_PIXELS = 25_000_000

# Authentication
security = HTTPBearer(auto_error=False)

def get_api_key(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> str:
    # Check Authorization header (Bearer token)
    if credentials and credentials.credentials == API_KEY:
        return credentials.credentials
    
    # Check X-API-Key header  
    api_key = request.headers.get("X-API-Key")
    if api_key == API_KEY:
        return api_key
    
    # Authentication failed
    raise HTTPException(
        status_code=401,
        detail="Unauthorized",
        headers={"WWW-Authenticate": "Bearer"}
    )

# Database helpers - mirror from app.py
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def update_stat(key: str, inc: int = 1):
    """Update statistics in database - mirror from app.py"""
    try:
        with get_db() as db:
            db.execute("UPDATE stats SET stat_value = stat_value + ? WHERE stat_key = ?", (inc, key))
            db.commit()
    except Exception as e:
        logger.error(f"Failed to update stat {key}: {e}")

def allowed_file(filename: str) -> bool:
    """Check if file extension is allowed - mirror from app.py"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_and_encrypt_image(stream, orig_fn: str, keep_exif: bool = False) -> Optional[str]:
    """Process and encrypt image - mirror logic from app.py"""
    try:
        # Read all content from stream
        raw = stream.read()
        bio = BytesIO(raw)

        # Verify integrity
        with Image.open(bio) as probe:
            probe.verify()

        # Reopen for processing
        bio2 = BytesIO(raw)
        img = Image.open(bio2)

        # Enforce format whitelist
        allowed_formats = {'PNG', 'JPEG', 'JPG', 'GIF', 'WEBP', 'BMP', 'ICO', 'TIFF'}
        fmt = (img.format or '').upper()
        if fmt == 'JPG':
            fmt = 'JPEG'
        if fmt not in allowed_formats:
            raise ValueError(f"Unsupported image format: {fmt}")

        # Enforce dimension and pixel limits
        max_side = 8000
        max_pixels = 50_000_000
        width, height = img.size
        if width > max_side or height > max_side or (width * height) > max_pixels:
            raise ValueError("Image dimensions too large")

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
        path = os.path.join(UPLOAD_FOLDER, new_fn)

        # Ensure upload directory exists
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        with open(path, 'wb') as f:
            f.write(encrypted)

        return new_fn
    except Exception as e:
        logger.error(f"Image processing failed ({orig_fn}): {e}")
        return None

# Routes

@app.get("/ssl-status")
async def ssl_status():
    """Public SSL status endpoint - no auth required"""
    return Response(content="ok", media_type="text/plain")

@app.get("/mobile/health")
async def health_check(api_key: str = Depends(get_api_key)):
    """Health check endpoint - auth required"""
    try:
        # Test database connection
        with get_db() as db:
            db.execute("SELECT 1").fetchone()
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail="Service unavailable")

@app.post("/mobile/upload")
async def upload_file(
    request: Request,
    api_key: str = Depends(get_api_key),
    file: UploadFile = File(...),
    expiry: str = Form(default="1h"),
    password: Optional[str] = Form(default=None),
    max_views: Optional[int] = Form(default=None),
    keep_exif: bool = Form(default=False)
):
    """Upload file endpoint - auth required, mirrors app.py logic"""
    
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file selected")
    
    # Check file type
    if not allowed_file(file.filename):
        raise HTTPException(status_code=400, detail="Invalid file type")
    
    # Check file size
    content = await file.read()
    if len(content) > MAX_CONTENT_LENGTH:
        raise HTTPException(status_code=413, detail="Request entity too large")
    
    # Process image
    stream = BytesIO(content)
    new_fn = process_and_encrypt_image(stream, file.filename, keep_exif)
    if not new_fn:
        raise HTTPException(status_code=500, detail="Failed to process image")
    
    # Calculate expiry
    now = datetime.now()
    expiry_delta = EXPIRY_MAP.get(expiry, timedelta(hours=1))
    expiry_date = now + expiry_delta
    
    # Hash password if provided
    pw_hash = generate_password_hash(password, method='pbkdf2:sha256') if password else None
    
    # Store in database - mirror app.py logic
    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO images (id, upload_date, expiry_date, password_hash, max_views, view_count) VALUES (?, ?, ?, ?, ?, ?)',
                (new_fn, now, expiry_date, pw_hash, max_views, -1)
            )
            db.commit()
        
        # Update stats - count towards clearnet uploads
        update_stat('total_api_uploads')
        
        # Return response with URL
        file_url = f"https://{DOMAIN}/uploads/{new_fn}"
        return {
            "success": True,
            "url": file_url,
            "filename": new_fn,
            "size": len(content),
            "expires": expiry_date.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Database error during upload: {e}")
        # Clean up file if database insert failed
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, new_fn))
        except:
            pass
        raise HTTPException(status_code=500, detail="Upload failed")

# Custom exception handler for consistent error format
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers
    )

if __name__ == "__main__":
    # This won't be used in production (systemd service uses gunicorn)
    # But useful for development
    uvicorn.run(
        "api:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )