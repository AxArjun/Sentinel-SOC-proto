from flask import Blueprint, render_template, request, jsonify, g, flash, redirect, url_for
from app.models import db
from app.models.db_models import Threat, IOC, Vulnerability
from app.middleware.rbac import login_required, require_permission
from app.routes.auth import log_audit_event

threats_bp = Blueprint('threats', __name__)

@threats_bp.route('/threats')
@login_required
@require_permission('view_threats')
def hub():
    query_str = request.args.get('search', '')
    if query_str:
        threats_list = Threat.query.filter(
            (Threat.name.like(f"%{query_str}%")) |
            (Threat.threat_actor.like(f"%{query_str}%")) |
            (Threat.malware_family.like(f"%{query_str}%"))
        ).all()
    else:
        threats_list = Threat.query.order_by(Threat.severity_score.desc()).all()
        
    cves = Vulnerability.query.order_by(Vulnerability.cvss_score.desc()).all()
    iocs_count = IOC.query.count()
    
    # Mock data for dark web mentions
    dark_web_mentions = [
        {"timestamp": "2026-05-30 11:15", "actor": "APT29", "source": "RaidForums Clone", "sentiment": "Critical", "leak_size": "2.1 GB"},
        {"timestamp": "2026-05-30 09:44", "actor": "Wizard Spider", "source": "Exploit.in", "sentiment": "High", "leak_size": "N/A"},
        {"timestamp": "2026-05-30 05:12", "actor": "Lazarus Group", "source": "BreachForums", "sentiment": "Critical", "leak_size": "420 MB"}
    ]
    
    return render_template(
        'threat_intelligence.html', 
        threats=threats_list, 
        cves=cves, 
        iocs_count=iocs_count,
        search_query=query_str,
        dark_web_mentions=dark_web_mentions
    )

@threats_bp.route('/threats/api/origins')
@login_required
@require_permission('view_threats')
def api_origins():
    # Return mock geo-coordinates for live threat map display
    origins = [
        {"city": "Saint Petersburg", "country": "Russia", "lat": 59.9343, "lon": 30.3351, "count": 24, "actor": "Cozy Bear"},
        {"city": "Pyongyang", "country": "North Korea", "lat": 39.0392, "lon": 125.7625, "count": 18, "actor": "Lazarus Group"},
        {"city": "Shanghai", "country": "China", "lat": 31.2304, "lon": 121.4737, "count": 15, "actor": "APT41"},
        {"city": "Tehran", "country": "Iran", "lat": 35.6892, "lon": 51.3890, "count": 9, "actor": "MuddyWater"}
    ]
    return jsonify(origins)
