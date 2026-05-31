from flask import Blueprint, render_template, g
from app.models.db_models import Threat, IOC, Alert, Incident, AuditLog
from app.middleware.rbac import login_required

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/dashboard')
@login_required
def home():
    # Gather statistics from the database for the dashboard widgets
    stats = {
        'threats': Threat.query.count(),
        'iocs': IOC.query.count(),
        'alerts': Alert.query.count(),
        'incidents': Incident.query.count()
    }
    
    # Load recent activity lists for the high-density tables
    recent_threats = Threat.query.order_by(Threat.severity_score.desc()).limit(5).all()
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(5).all()
    recent_incidents = Incident.query.filter(Incident.status != 'Closed').order_by(Incident.created_at.desc()).limit(5).all()
    
    # Load recent audit logs for administration auditing, if permitted
    audit_logs = []
    if g.user.has_permission('view_audit_logs'):
        audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all()
        
    return render_template(
        'dashboard.html', 
        stats=stats, 
        recent_threats=recent_threats,
        recent_alerts=recent_alerts,
        recent_incidents=recent_incidents,
        audit_logs=audit_logs
    )
