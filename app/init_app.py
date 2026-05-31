import os
from flask import Flask, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect
from app.models import db
from app.models.db_models import Role, Permission, User, SystemSetting
from config import Config

# Initialize CSRF Protection
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize DB & CSRF
    db.init_app(app)
    csrf.init_app(app)
    
    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp)
    
    # Global root route redirects to login or dashboard depending on session state
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard.home'))
        return redirect(url_for('auth.login'))
        
    # Database seeding context hook
    with app.app_context():
        # Create database tables if they do not exist
        db.create_all()
        seed_database()
        
    return app

def seed_database():
    """Seed initial roles, permissions, and admin user account if empty."""
    # Check if database is already seeded
    if Role.query.first():
        return
        
    print("[Database Seed] Seeding default roles and permissions...")
    
    # 1. Create Permissions
    view_threats = Permission(name='view_threats', description='Allows viewing threat intelligence profiles.')
    create_threats = Permission(name='create_threats', description='Allows adding new threat intelligence profiles.')
    edit_threats = Permission(name='edit_threats', description='Allows editing threat intelligence profiles.')
    delete_threats = Permission(name='delete_threats', description='Allows removing threat intelligence profiles.')
    
    view_ioc = Permission(name='view_ioc', description='Allows searching and viewing indicators of compromise.')
    manage_ioc = Permission(name='manage_ioc', description='Allows adding, editing, and deleting indicators of compromise.')
    
    view_alerts = Permission(name='view_alerts', description='Allows viewing active security alerts.')
    manage_alerts = Permission(name='manage_alerts', description='Allows triaging and resolving alerts.')
    
    manage_users = Permission(name='manage_users', description='Allows creating, editing, and deleting system users.')
    view_audit_logs = Permission(name='view_audit_logs', description='Allows auditing system logins and administration actions.')
    manage_settings = Permission(name='manage_settings', description='Allows configuring global system ingestion parameters.')
    
    all_perms = [
        view_threats, create_threats, edit_threats, delete_threats,
        view_ioc, manage_ioc, view_alerts, manage_alerts,
        manage_users, view_audit_logs, manage_settings
    ]
    for perm in all_perms:
        db.session.add(perm)
    db.session.commit()
    
    # 2. Create Roles and Map Permissions
    admin_role = Role(name='Administrator', description='Complete system access.')
    analyst_role = Role(name='Analyst', description='Access to monitor alerts, track threats, and handle incidents.')
    ciso_role = Role(name='CISO', description='Access to analytics, high-level dashboards, and security reports.')
    
    # Assign permissions to roles
    admin_role.permissions.extend(all_perms)
    analyst_role.permissions.extend([
        view_threats, create_threats, edit_threats,
        view_ioc, manage_ioc,
        view_alerts, manage_alerts
    ])
    ciso_role.permissions.extend([
        view_threats, view_ioc, view_alerts
    ])
    
    db.session.add_all([admin_role, analyst_role, ciso_role])
    db.session.commit()
    
    # 3. Create Default Admin and Analyst Accounts
    print("[Database Seed] Seeding administrator and analyst accounts...")
    admin_user = User(
        username='admin',
        email='admin@threatintel.local',
        role_id=admin_role.id,
        is_active=True
    )
    admin_user.set_password('AdminSecPass123!')
    
    analyst_user = User(
        username='analyst',
        email='analyst@threatintel.local',
        role_id=analyst_role.id,
        is_active=True
    )
    analyst_user.set_password('AnalystSecPass123!')
    
    db.session.add_all([admin_user, analyst_user])
    db.session.commit()
    
    # 4. Create Default System Settings
    print("[Database Seed] Seeding system settings...")
    settings = [
        SystemSetting(setting_key='ingestion_frequency_minutes', setting_value='60', setting_group='Ingestion', description='Sync frequency for threat feeds.'),
        SystemSetting(setting_key='auto_triage_false_positives', setting_value='True', setting_group='Alerting', description='Suppress matching indicators marked as FP.'),
        SystemSetting(setting_key='min_alert_confidence_threshold', setting_value='50', setting_group='Alerting', description='Minimum confidence score of an IOC to trigger notifications.')
    ]
    db.session.add_all(settings)
    db.session.commit()
    print("[Database Seed] Seeding completed successfully.")
