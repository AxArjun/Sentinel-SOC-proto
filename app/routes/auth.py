from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, g
from app.models import db
from app.models.db_models import User, Role, AuditLog
from app.forms.auth_forms import LoginForm, RegistrationForm
from app.middleware.rbac import require_permission, login_required

auth_bp = Blueprint('auth', __name__)

def log_audit_event(action, details, user_id=None):
    """Helper to log audit events into the database."""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # If multiple proxy IPs, extract the first one
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()
        
    audit_entry = AuditLog(
        user_id=user_id or session.get('user_id'),
        action=action,
        details=details,
        ip_address=ip,
        user_agent=request.user_agent.string[:255] if request.user_agent else 'Unknown'
    )
    db.session.add(audit_entry)
    db.session.commit()

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect if already logged in
    if g.user:
        return redirect(url_for('dashboard.home'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.is_active and user.check_password(form.password.data):
            # Regenerate session to prevent session fixation attacks
            session.clear()
            session['user_id'] = user.id
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            log_audit_event('USER_LOGIN_SUCCESS', f"User '{user.username}' logged in successfully.", user.id)
            flash('Welcome back, Secure Portal access granted.', 'success')
            
            # Redirect to next parameter or home dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'): # Validate local redirect path
                return redirect(next_page)
            return redirect(url_for('dashboard.home'))
            
        else:
            # Audit failed login attempt
            log_details = f"Failed login attempt for username: {form.username.data}"
            log_audit_event('USER_LOGIN_FAILURE', log_details, user.id if user else None)
            flash('Invalid username or password, or account is disabled.', 'danger')
            
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    username = g.user.username
    user_id = g.user.id
    # Log audit event before clearing the session
    log_audit_event('USER_LOGOUT', f"User '{username}' logged out.", user_id)
    session.clear()
    flash('You have been logged out securely.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@login_required
@require_permission('manage_users')
def register():
    form = RegistrationForm()
    
    # Dynamically populate the role choices from the database
    roles = Role.query.all()
    form.role_id.choices = [(role.id, role.name) for role in roles]
    
    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists.', 'warning')
            return render_template('auth/register.html', form=form)
            
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            role_id=form.role_id.data,
            is_active=True
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        
        log_audit_event('USER_CREATED', f"New user '{new_user.username}' created with role ID: {new_user.role_id}.")
        flash(f"User account '{new_user.username}' created successfully.", 'success')
        return redirect(url_for('dashboard.home'))
        
    return render_template('auth/register.html', form=form)
