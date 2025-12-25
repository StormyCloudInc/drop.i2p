#!/usr/bin/env python3
"""
PhotoDNA CSAM check script for drop.i2p
Reads image bytes from stdin and sends to Microsoft PhotoDNA API.

Exit codes:
  0 = No match (safe)
  1 = Match found (CSAM detected)
  2 = Invalid image (not an image or can't decode)
  3 = API error (timeout, auth failure, etc.)
  5 = Configuration error (missing API key)

Output format: JSON on stdout
"""
import sys
import os
import json
from io import BytesIO

# Import dependencies
try:
    from PIL import Image
    import requests
except ImportError as e:
    print(json.dumps({
        "code": 5,
        "message": f"Missing dependency: {e}",
        "match": False
    }))
    sys.exit(5)

# API configuration (from environment)
API_KEY = os.environ.get("PHOTODNA_API_KEY", "")
API_URL = "https://api.microsoftmoderator.com/photodna/v1.0/Match"
TIMEOUT = int(os.environ.get("PHOTODNA_TIMEOUT", "10"))


def output_result(code: int, message: str, details: dict = None):
    """Output JSON result and exit."""
    result = {
        "code": code,
        "message": message,
        "match": code == 1,
    }
    if details:
        result["details"] = details
    print(json.dumps(result))
    sys.exit(code)


def detect_image_type(image_bytes: bytes) -> str:
    """Detect image MIME type from magic bytes."""
    if image_bytes[:3] == b'\xff\xd8\xff':
        return "image/jpeg"
    elif image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        return "image/png"
    elif image_bytes[:6] in (b'GIF87a', b'GIF89a'):
        return "image/gif"
    elif image_bytes[:4] == b'RIFF' and image_bytes[8:12] == b'WEBP':
        return "image/webp"
    elif image_bytes[:2] == b'BM':
        return "image/bmp"
    else:
        return "image/jpeg"  # Default fallback


def validate_image(image_bytes: bytes) -> tuple:
    """Validate that the bytes represent a valid image."""
    try:
        img = Image.open(BytesIO(image_bytes))
        img.load()  # Force load to catch truncated images

        # Check minimum size (PhotoDNA requires reasonable dimensions)
        width, height = img.size
        if width < 50 or height < 50:
            return None, f"Image too small: {width}x{height} (minimum 50x50)"

        return img, None
    except Exception as e:
        return None, f"Invalid image: {e}"


def check_api(image_bytes: bytes, content_type: str) -> tuple:
    """Send image to Microsoft PhotoDNA API for matching."""
    if not API_KEY:
        return None, "API key not configured"

    try:
        headers = {
            "Content-Type": content_type,
            "Ocp-Apim-Subscription-Key": API_KEY
        }

        response = requests.post(
            API_URL,
            headers=headers,
            params={"enhance": "true"},
            data=image_bytes,
            timeout=TIMEOUT
        )

        if response.status_code == 401:
            return None, "API authentication failed"

        if response.status_code == 403:
            return None, "API access forbidden"

        if response.status_code != 200:
            return None, f"API returned status {response.status_code}: {response.text[:200]}"

        data = response.json()

        # Check for API-level errors
        status = data.get("Status", {})
        if status.get("Code", 0) != 3000:
            return None, f"API error: {status.get('Description', 'Unknown error')}"

        is_match = data.get("IsMatch", False)

        details = {
            "is_match": is_match,
            "tracking_id": data.get("TrackingId"),
        }

        # Include match details if present
        match_details = data.get("MatchDetails")
        if match_details and is_match:
            match_flags = match_details.get("MatchFlags", [])
            if match_flags:
                details["source"] = match_flags[0].get("Source")
                details["violations"] = match_flags[0].get("Violations", [])

        return details, None

    except requests.Timeout:
        return None, "API request timed out"
    except requests.RequestException as e:
        return None, f"API request failed: {e}"
    except Exception as e:
        return None, f"API check error: {e}"


def main():
    # Check API key
    if not API_KEY:
        output_result(5, "PhotoDNA API key not configured")

    # Read image from stdin
    try:
        image_bytes = sys.stdin.buffer.read()
    except Exception as e:
        output_result(2, f"Failed to read image data: {e}")

    if not image_bytes:
        output_result(2, "No image data received")

    # Validate image
    img, error = validate_image(image_bytes)
    if error:
        output_result(2, error)

    # Detect content type
    content_type = detect_image_type(image_bytes)

    # Check API
    result, error = check_api(image_bytes, content_type)
    if error:
        output_result(3, error)

    # Return result
    if result["is_match"]:
        output_result(1, "PhotoDNA match found", result)
    else:
        output_result(0, "No match", result)


if __name__ == "__main__":
    main()
