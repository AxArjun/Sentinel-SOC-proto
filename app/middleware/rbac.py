from functools import wraps
from flask import g, session, abort, redirect, url_for, request
from app.models.db_models import User

def load_logged_in_user():
    """Context processor or before_request hook to load user details into flask.g"""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        # Load user from DB
        g.user = User.query.get(user_id)
        # If user was deleted or disabled, force log out
        if not g.user or not g.user.is_active:
            session.clear()
            g.user = None

def login_required(f):
    """Enforces that a user must be authenticated to view this endpoint."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def require_permission(permission_name):
    """Decorator checking that a user has a specific permission in their mapped role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if g.user is None:
                return redirect(url_for('auth.login'))
            if not g.user.has_permission(permission_name):
                return abort(403) # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def inject_security_headers(response):
    """Global after_request middleware to inject standard security response headers."""
    # Prevent application from being framed (Clickjacking)
    response.headers['X-Frame-Options'] = 'DENY'
    # Block browser MIME-type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Cross-site scripting protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Strict Transport Security (HSTS)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Content Security Policy (Basic default policy)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response
