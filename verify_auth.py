import sys
from app import create_app, db
from app.models.db_models import Role, Permission, User, SystemSetting

def test_database_integrity():
    print("[Test] Initializing application test context...")
    app = create_app()
    
    with app.app_context():
        print("[Test] Verifying Roles and Permissions...")
        roles = Role.query.all()
        role_names = [role.name for role in roles]
        expected_roles = ['Administrator', 'Analyst', 'CISO']
        
        for expected in expected_roles:
            if expected not in role_names:
                print(f"[FAIL] Missing expected role: {expected}")
                sys.exit(1)
            print(f"[OK] Role verified: {expected}")
            
        # Verify permissions populated
        permissions_count = Permission.query.count()
        if permissions_count == 0:
            print("[FAIL] No permissions populated in database.")
            sys.exit(1)
        print(f"[OK] Permissions verified (Count: {permissions_count})")
        
        # Verify Default User credentials
        print("[Test] Verifying default user credentials...")
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            print("[FAIL] Default user 'admin' not found.")
            sys.exit(1)
            
        if not admin.check_password('AdminSecPass123!'):
            print("[FAIL] Admin password verification failed.")
            sys.exit(1)
            
        print("[OK] Default admin user credential hash verified successfully.")
        
        analyst = User.query.filter_by(username='analyst').first()
        if not analyst:
            print("[FAIL] Default user 'analyst' not found.")
            sys.exit(1)
            
        if not analyst.check_password('AnalystSecPass123!'):
            print("[FAIL] Analyst password verification failed.")
            sys.exit(1)
            
        print("[OK] Default analyst user credential hash verified successfully.")
        
        # Verify permission check methods
        print("[Test] Verifying user permissions mapping matches RBAC rules...")
        if not admin.has_permission('manage_users'):
            print("[FAIL] Admin user does not have 'manage_users' permission.")
            sys.exit(1)
        if analyst.has_permission('manage_users'):
            print("[FAIL] Analyst user has unauthorized 'manage_users' permission.")
            sys.exit(1)
            
        print("[OK] Admin & Analyst RBAC permissions verify correctly.")
        
        # Verify system settings
        print("[Test] Verifying default system settings configuration...")
        setting = SystemSetting.query.get('ingestion_frequency_minutes')
        if not setting or setting.setting_value != '60':
            print("[FAIL] System setting check failed.")
            sys.exit(1)
            
        print("[OK] System configuration settings verified.")
        
    print("\n[ALL TESTS PASSED SUCCESSFULLY]")
    sys.exit(0)

if __name__ == '__main__':
    test_database_integrity()
