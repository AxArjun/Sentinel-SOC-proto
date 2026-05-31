from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import db

# Many-to-Many association table for Role and Permission
role_permissions = db.Table(
    'role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id', ondelete='CASCADE'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id', ondelete='CASCADE'), primary_key=True)
)

# Many-to-Many association table for Threat Campaign and Vulnerability CVE
threat_vulnerabilities = db.Table(
    'threat_vulnerabilities',
    db.Column('threat_id', db.Integer, db.ForeignKey('threats.id', ondelete='CASCADE'), primary_key=True),
    db.Column('vulnerability_id', db.Integer, db.ForeignKey('vulnerabilities.id', ondelete='CASCADE'), primary_key=True)
)

class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    users = db.relationship('User', backref='role', lazy=True)
    permissions = db.relationship('Permission', secondary=role_permissions, backref=db.backref('roles', lazy='dynamic'))

    def __repr__(self):
        return f"<Role {self.name}>"

class Permission(db.Model):
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Permission {self.name}>"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), nullable=False, unique=True, index=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='RESTRICT'), nullable=False)
    is_active = db.Column(db.Boolean, default=True, index=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    assigned_incidents = db.relationship('Incident', backref='assignee', lazy=True)
    reports = db.relationship('Report', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def has_permission(self, permission_name):
        return any(perm.name == permission_name for perm in self.role.permissions)

    def __repr__(self):
        return f"<User {self.username}>"

class ThreatFeed(db.Model):
    __tablename__ = 'threat_feeds'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    feed_url = db.Column(db.String(500), nullable=False)
    feed_type = db.Column(db.String(50), nullable=False) # e.g. STIX, TAXII, JSON, CSV
    auth_credentials = db.Column(db.Text, nullable=True) # Encrypted JSON details
    is_enabled = db.Column(db.Boolean, default=True, index=True)
    last_sync = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    iocs = db.relationship('IOC', backref='feed', lazy=True)

    def __repr__(self):
        return f"<ThreatFeed {self.name}>"

class Threat(db.Model):
    __tablename__ = 'threats'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(150), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=True)
    threat_actor = db.Column(db.String(100), nullable=True, index=True) # e.g. APT29
    malware_family = db.Column(db.String(100), nullable=True)
    severity_score = db.Column(db.Integer, default=50, nullable=False, index=True) # 1-100 scale
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    iocs = db.relationship('IOC', backref='threat', lazy=True)
    vulnerabilities = db.relationship('Vulnerability', secondary=threat_vulnerabilities, backref=db.backref('threats', lazy='dynamic'))

    def __repr__(self):
        return f"<Threat {self.name}>"

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cve_id = db.Column(db.String(30), nullable=False, unique=True, index=True) # e.g. CVE-2021-44228
    description = db.Column(db.Text, nullable=True)
    cvss_score = db.Column(db.Numeric(3, 1), nullable=False) # e.g. 9.8
    epss_score = db.Column(db.Numeric(5, 4), default=0.0000, nullable=True) # Exploit Prediction Scoring System
    patch_status = db.Column(db.String(50), default='Unpatched')
    published_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Vulnerability {self.cve_id}>"

class IOC(db.Model):
    __tablename__ = 'ioc'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    value = db.Column(db.String(255), nullable=False, unique=True, index=True) # e.g. '192.168.1.1'
    type = db.Column(db.String(50), nullable=False) # IP, Domain, URL, MD5, SHA256
    confidence = db.Column(db.Integer, default=50, nullable=False) # 0-100 scale
    severity = db.Column(db.String(20), default='Medium', nullable=False) # Low, Medium, High, Critical
    threat_feed_id = db.Column(db.Integer, db.ForeignKey('threat_feeds.id', ondelete='SET NULL'), nullable=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id', ondelete='SET NULL'), nullable=True)
    is_false_positive = db.Column(db.Boolean, default=False, index=True)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    alerts = db.relationship('Alert', backref='ioc', lazy=True)

    def __repr__(self):
        return f"<IOC {self.type}:{self.value}>"

class Incident(db.Model):
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(30), default='New', nullable=False, index=True) # New, Open, Investigating, Remediated, Closed
    priority = db.Column(db.String(20), default='Medium', nullable=False, index=True) # Low, Medium, High, Critical
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    alerts = db.relationship('Alert', backref='incident', lazy=True)

    def __repr__(self):
        return f"<Incident {self.id}:{self.title}>"

class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(150), nullable=False)
    source = db.Column(db.String(100), nullable=False) # EDR, Firewall, IDS
    matched_value = db.Column(db.String(255), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, index=True) # Low, Medium, High, Critical
    status = db.Column(db.String(30), default='Unassigned', nullable=False, index=True) # Unassigned, Investigating, Resolved, False Positive
    ioc_id = db.Column(db.Integer, db.ForeignKey('ioc.id', ondelete='SET NULL'), nullable=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incidents.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Alert {self.id}:{self.title}>"

class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(150), nullable=False)
    report_type = db.Column(db.String(50), nullable=False) # Daily, Weekly, Monthly, Incident
    file_path = db.Column(db.String(500), nullable=False)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Report {self.title}>"

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True) # USER_LOGIN, USER_LOGOUT, IOC_CREATED, etc.
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<AuditLog {self.action} at {self.created_at}>"

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    
    setting_key = db.Column(db.String(100), primary_key=True)
    setting_value = db.Column(db.Text, nullable=False)
    setting_group = db.Column(db.String(50), nullable=False) # Ingestion, Alerting, SMTP, etc.
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<SystemSetting {self.setting_key}>"
