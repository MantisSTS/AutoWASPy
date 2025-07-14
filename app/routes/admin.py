"""
Admin routes for system administration
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from app import db
from app.models import OWASPDataCache
from app.services import OWASPService, APISecurityService, IoTSecurityService, ASVSService
# from app.services.cloud_security_service import CloudSecurityService
from app.services.comprehensive_owasp_service import ComprehensiveOWASPService

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/refresh-owasp', methods=['GET', 'POST'])
def refresh_owasp_data():
    """Refresh OWASP testing data from remote sources"""
    if request.method == 'POST':
        try:
            # Refresh each framework individually from GitHub
            flash('Refreshing OWASP testing frameworks from GitHub...', 'info')
            
            # WSTG refresh
            try:
                wstg_tests = OWASPService.fetch_wstg_data()
                flash(f"✅ WSTG: Successfully refreshed {len(wstg_tests)} test cases", 'success')
            except Exception as e:
                flash(f"❌ WSTG: Failed to refresh - {str(e)}", 'error')
            
            # MASTG refresh
            try:
                mastg_tests = OWASPService.fetch_mstg_data()
                flash(f"✅ MASTG: Successfully refreshed {len(mastg_tests)} test cases", 'success')
            except Exception as e:
                flash(f"❌ MASTG: Failed to refresh - {str(e)}", 'error')
            
            # API Security refresh
            try:
                api_tests = APISecurityService.fetch_api_security_data()
                flash(f"✅ API Security: Successfully refreshed {len(api_tests)} test cases", 'success')
            except Exception as e:
                flash(f"❌ API Security: Failed to refresh - {str(e)}", 'error')
            
            # IoT Security refresh
            try:
                iot_tests = IoTSecurityService.fetch_iot_security_data()
                flash(f"✅ IoT Security: Successfully refreshed {len(iot_tests)} test cases", 'success')
            except Exception as e:
                flash(f"❌ IoT Security: Failed to refresh - {str(e)}", 'error')
            
            # ASVS refresh
            try:
                asvs_tests = ASVSService.fetch_asvs_data()
                flash(f"✅ ASVS: Successfully refreshed {len(asvs_tests)} test cases", 'success')
            except Exception as e:
                flash(f"❌ ASVS: Failed to refresh - {str(e)}", 'error')
            
            flash('Framework refresh completed! New projects will use cached data for fast creation.', 'info')
            return redirect(url_for('admin.refresh_owasp_data'))
            
        except Exception as e:
            flash(f'Error refreshing OWASP data: {str(e)}', 'error')
            return redirect(url_for('admin.refresh_owasp_data'))
    
    # GET request - show current cache status
    try:
        cache_status = ComprehensiveOWASPService.get_cache_status()
        frameworks = ComprehensiveOWASPService.get_all_frameworks()
        
        # Combine framework info with cache status
        framework_status = {}
        for key, info in frameworks.items():
            framework_status[key] = {
                'info': info,
                'cache': cache_status.get(key, {
                    'last_updated': None,
                    'data_source': 'none',
                    'test_count': 0
                })
            }
        
        return render_template('refresh_owasp.html', 
                             framework_status=framework_status,
                             total_frameworks=len(frameworks))
    except Exception as e:
        flash(f'Error loading cache status: {str(e)}', 'error')
        return render_template('refresh_owasp.html', 
                             framework_status={},
                             total_frameworks=0)

@bp.route('/api/frameworks')
def api_frameworks():
    """API endpoint to get all available frameworks"""
    try:
        frameworks = ComprehensiveOWASPService.get_all_frameworks()
        return jsonify({
            'success': True,
            'frameworks': frameworks
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/testing-plan/<app_type>')
def api_testing_plan(app_type):
    """API endpoint to get risk-based testing plan"""
    try:
        risk_level = request.args.get('risk_level', 'medium')
        plan = ComprehensiveOWASPService.get_risk_based_testing_plan(app_type, risk_level)
        return jsonify({
            'success': True,
            'testing_plan': plan
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
