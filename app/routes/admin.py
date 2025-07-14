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
            # Use comprehensive service to refresh all frameworks
            flash('Refreshing all OWASP testing frameworks...', 'info')
            results = ComprehensiveOWASPService.refresh_all_frameworks()
            
            # Report results
            for framework_key, result in results.items():
                if result['success']:
                    flash(f"✅ {framework_key.upper()}: {result['message']}", 'success')
                else:
                    flash(f"❌ {framework_key.upper()}: {result['message']}", 'error')
            
            flash('All frameworks have been refreshed!', 'success')
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
