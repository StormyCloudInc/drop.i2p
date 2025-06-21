# wsgi.py
# This file is the entry point for the Gunicorn WSGI server.
# It imports the 'app' object from your main application file.

from app import app

if __name__ == "__main__":
    app.run()
