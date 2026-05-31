from flask import Blueprint, render_template, request, jsonify, g, flash, redirect, url_for
from app.models import db
from app.models.db_models import Incident, Alert, User, AuditLog
from app.middleware.rbac import login_required, require_permission
from app.routes.auth import log_audit_event
from datetime import datetime

incidents_bp = Blueprint('incidents', __name__)

@incidents_bp.route('/incidents')
@login_required
@require_permission('view_alerts')
def list_incidents():
    query_str = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    priority_filter = request.args.get('priority', '')
    
    q = Incident.query
    
    if query_str:
        q = q.filter(
            (Incident.title.like(f"%{query_str}%")) |
            (Incident.description.like(f"%{query_str}%"))
        )
    if status_filter:
        q = q.filter_by(status=status_filter)
    if priority_filter:
        q = q.filter_by(priority=priority_filter)
        
    incidents_list = q.order_by(Incident.created_at.desc()).all()
    
    # Load selected incident if provided, otherwise default to first
    selected_id = request.args.get('selected_id', type=int)
    selected_incident = None
    if selected_id:
        selected_incident = Incident.query.get(selected_id)
    elif incidents_list:
        selected_incident = incidents_list[0]
        
    analysts = User.query.all()
    
    return render_template(
        'incidents.html',
        incidents=incidents_list,
        selected_incident=selected_incident,
        analysts=analysts,
        search_query=query_str,
        status_filter=status_filter,
        priority_filter=priority_filter
    )

@incidents_bp.route('/incidents/<int:incident_id>/update', methods=['POST'])
@login_required
@require_permission('manage_alerts')
def update_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    
    status = request.form.get('status')
    priority = request.form.get('priority')
    assigned_to = request.form.get('assigned_to')
    
    if status:
        old_status = incident.status
        incident.status = status
        if status in ['Closed', 'Remediated']:
            incident.closed_at = datetime.utcnow()
        log_audit_event('INCIDENT_UPDATE', f"Incident #{incident.id} status updated from '{old_status}' to '{status}'.")
        
    if priority:
        old_priority = incident.priority
        incident.priority = priority
        log_audit_event('INCIDENT_UPDATE', f"Incident #{incident.id} priority updated from '{old_priority}' to '{priority}'.")
        
    if assigned_to:
        old_assignee = incident.assignee.username if incident.assignee else 'None'
        if assigned_to == 'None' or assigned_to == '':
            incident.assigned_to = None
            new_assignee_name = 'None'
        else:
            user = User.query.get(int(assigned_to))
            if user:
                incident.assigned_to = user.id
                new_assignee_name = user.username
        log_audit_event('INCIDENT_UPDATE', f"Incident #{incident.id} assignee changed from '{old_assignee}' to '{new_assignee_name}'.")
        
    db.session.commit()
    flash(f"Incident #{incident.id} updated successfully.", 'success')
    return redirect(url_for('incidents.list_incidents', selected_id=incident.id))

@incidents_bp.route('/incidents/<int:incident_id>/notes/add', methods=['POST'])
@login_required
@require_permission('manage_alerts')
def add_note(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    note_text = request.form.get('note_text', '').strip()
    
    if note_text:
        # Append mock note to description since db_models doesn't have a separate notes table
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        note_entry = f"\n\n--- [Note by {g.user.username} on {timestamp} UTC] ---\n{note_text}"
        incident.description = (incident.description or "") + note_entry
        db.session.commit()
        log_audit_event('INCIDENT_NOTE_ADDED', f"Added note to incident #{incident.id}.")
        flash("Operational note recorded.", "success")
    else:
        flash("Note text cannot be empty.", "warning")
        
    return redirect(url_for('incidents.list_incidents', selected_id=incident.id))

@incidents_bp.route('/alerts/<int:alert_id>/triage', methods=['POST'])
@login_required
@require_permission('manage_alerts')
def triage_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    action = request.form.get('action') # resolve, false_positive
    
    if action == 'resolve':
        alert.status = 'Resolved'
        log_audit_event('ALERT_TRIAGE', f"Alert #{alert.id} marked as Resolved.")
        flash(f"Alert #{alert.id} successfully resolved.", "success")
    elif action == 'false_positive':
        alert.status = 'False Positive'
        log_audit_event('ALERT_TRIAGE', f"Alert #{alert.id} marked as False Positive.")
        flash(f"Alert #{alert.id} marked as False Positive.", "info")
        
    db.session.commit()
    
    # Redirect back to the incident page that this alert belongs to if present
    if alert.incident_id:
        return redirect(url_for('incidents.list_incidents', selected_id=alert.incident_id))
    return redirect(url_for('dashboard.home'))
