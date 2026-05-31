import os
from flask import Flask, redirect, url_for, session
from flask_wtf.csrf import CSRFProtect
from app.models import db
from app.models.db_models import Role, Permission, User, SystemSetting, ThreatFeed, Threat, Vulnerability, IOC, Incident, Alert
from config import Config

# Initialize CSRF Protection
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize DB & CSRF
    db.init_app(app)
    csrf.init_app(app)
    
    # Register Middleware Hooks
    from app.middleware.rbac import load_logged_in_user, inject_security_headers
    app.before_request(load_logged_in_user)
    app.after_request(inject_security_headers)
    
    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.threats import threats_bp
    from app.routes.incidents import incidents_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(threats_bp)
    app.register_blueprint(incidents_bp)
    
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
    """Seed initial roles, permissions, admin user accounts, and mock SOC telemetry if empty."""
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

    # 5. Create Threat Feeds
    print("[Database Seed] Seeding threat feeds...")
    feed1 = ThreatFeed(name='OTX AlienVault', feed_url='https://otx.alienvault.com/api/v1/feeds/custom', feed_type='STIX')
    feed2 = ThreatFeed(name='Abuse.ch SSLBL', feed_url='https://sslbl.abuse.ch/api/v1/json', feed_type='JSON')
    db.session.add_all([feed1, feed2])
    db.session.commit()

    # 6. Create Threat Actors / Campaigns
    print("[Database Seed] Seeding threat profiles...")
    t1 = Threat(name='APT29 (Cozy Bear)', description='State-sponsored cyber espionage group active since at least 2008, targeting government and critical infrastructure.', threat_actor='APT29', malware_family='Duke family', severity_score=92)
    t2 = Threat(name='APT28 (Fancy Bear)', description='Military intelligence group targeting defense, security, and diplomatic targets using spearphishing and custom implants.', threat_actor='APT28', malware_family='Sofacy', severity_score=88)
    t3 = Threat(name='Wizard Spider', description='Financial crime syndicate responsible for Ryuk and Conti ransomware distribution networks.', threat_actor='Wizard Spider', malware_family='Ryuk', severity_score=85)
    t4 = Threat(name='Lazarus Group', description='State-backed operations group known for cyberattacks against media, aerospace, financial, and critical infrastructure sectors.', threat_actor='Lazarus Group', malware_family='Destover', severity_score=95)
    db.session.add_all([t1, t2, t3, t4])
    db.session.commit()

    # 7. Create Vulnerabilities (CVEs)
    print("[Database Seed] Seeding vulnerabilities...")
    v1 = Vulnerability(cve_id='CVE-2021-44228', description='Apache Log4j2 JNDI remote code execution vulnerability.', cvss_score=10.0, epss_score=0.9734, patch_status='Patched')
    v2 = Vulnerability(cve_id='CVE-2023-34362', description='Progress MOVEit Transfer SQL Injection remote code execution vulnerability.', cvss_score=9.8, epss_score=0.9125, patch_status='Unpatched')
    v3 = Vulnerability(cve_id='CVE-2024-21626', description='runc container breakout vulnerability via file descriptor leak.', cvss_score=8.6, epss_score=0.0841, patch_status='Patched')
    db.session.add_all([v1, v2, v3])
    db.session.commit()

    # Link Threat Campaigns to CVEs
    t1.vulnerabilities.append(v1)
    t1.vulnerabilities.append(v2)
    t2.vulnerabilities.append(v1)
    t4.vulnerabilities.append(v3)
    db.session.commit()

    # 8. Create IOCs
    print("[Database Seed] Seeding indicators of compromise...")
    i1 = IOC(value='185.220.101.5', type='IP', confidence=95, severity='Critical', threat_feed_id=feed1.id, threat_id=t1.id)
    i2 = IOC(value='update.microsoft-security-portal.com', type='Domain', confidence=85, severity='High', threat_feed_id=feed1.id, threat_id=t2.id)
    i3 = IOC(value='85.239.61.12', type='IP', confidence=90, severity='High', threat_feed_id=feed2.id, threat_id=t3.id)
    i4 = IOC(value='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', type='SHA256', confidence=100, severity='Critical', threat_feed_id=feed2.id, threat_id=t4.id)
    db.session.add_all([i1, i2, i3, i4])
    db.session.commit()

    # 9. Create Incidents
    print("[Database Seed] Seeding incidents...")
    inc1 = Incident(title='Suspicious Lateral Movement Detected', description='Multiple PowerShell executions with base64 encoded payloads detected from HR-DB-02 client machine.', status='Investigating', priority='Critical', assigned_to=analyst_user.id)
    inc2 = Incident(title='Multiple Failed Login Attempts (Brute Force)', description='Over 450 failed authentication attempts detected for root credentials from external IP 85.239.61.12.', status='New', priority='High')
    inc3 = Incident(title='Policy Violation: Shadow IT Application', description='Unauthorized file sharing utility usage detected on sales-pc-09 workstation.', status='Closed', priority='Low', assigned_to=analyst_user.id)
    inc4 = Incident(title='Data Exfiltration to Unknown IP', description='Outbound transfer spike (4.2 GB) detected to external IP 185.220.101.5 over port 443.', status='Open', priority='Critical', assigned_to=analyst_user.id)
    db.session.add_all([inc1, inc2, inc3, inc4])
    db.session.commit()

    # 10. Create Alerts
    print("[Database Seed] Seeding alerts...")
    a1 = Alert(title='Tor Exit Node Connection Match', source='Firewall', matched_value='185.220.101.5', severity='Critical', status='Investigating', ioc_id=i1.id, incident_id=inc4.id)
    a2 = Alert(title='Encoded PowerShell Process Spawned', source='EDR', matched_value='powershell.exe -enc SQBFA...', severity='High', status='Investigating', ioc_id=i3.id, incident_id=inc1.id)
    a3 = Alert(title='Brute Force Authentication Match', source='IDS', matched_value='85.239.61.12', severity='High', status='Unassigned', ioc_id=i3.id, incident_id=inc2.id)
    db.session.add_all([a1, a2, a3])
    db.session.commit()

    print("[Database Seed] Seeding completed successfully.")
