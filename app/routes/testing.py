"""
Testing and automated testing routes
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from app import db
from app.models import Project, AutoTestResult
from app.services import AutoTestService
from app.services.enhanced_autotest_service import EnhancedAutoTestService

bp = Blueprint('testing', __name__, url_prefix='/project')

@bp.route('/<int:project_id>/autotest', methods=['POST'])
def run_auto_tests(project_id):
    """Run enhanced automated security tests for a project"""
    project = db.get_or_404(Project, project_id)
    
    if not project.urls:
        flash('No URLs configured for automatic testing', 'error')
        return redirect(url_for('projects.project_detail', project_id=project_id))
    
    urls = [url.strip() for url in project.urls.split('\n') if url.strip()]
    
    # Use enhanced auto tests that map to OWASP checklist
    enhanced_tests = EnhancedAutoTestService.get_all_tests()
    
    # Legacy tests for additional coverage
    legacy_tests = [
        ('Information Disclosure Test', AutoTestService.test_information_disclosure),
        ('Clickjacking Protection Test', AutoTestService.test_clickjacking_protection),
        ('CORS Configuration Test', AutoTestService.test_cors_configuration),
        ('Content Type Validation Test', AutoTestService.test_content_type_validation),
        ('Cache Control Test', AutoTestService.test_cache_control),
        ('Subdomain Takeover Test', AutoTestService.test_subdomain_takeover),
        ('Directory Listing Test', AutoTestService.test_directory_listing),
        ('Error Handling Test', AutoTestService.test_error_handling),
        ('HTTP Security Features Test', AutoTestService.test_http_security_features),
        ('Input Validation Test', AutoTestService.test_input_validation),
        ('Robots.txt Analysis', AutoTestService.test_robots_txt_analysis),
        ('Web Server Detection', AutoTestService.test_web_server_detection),
        ('Admin Panel Detection', AutoTestService.test_admin_panel_detection),
        ('Backup File Detection', AutoTestService.test_backup_file_detection),
        ('Version Control Exposure', AutoTestService.test_version_control_exposure)
    ]
    
    # Combine all tests
    auto_tests = enhanced_tests + legacy_tests
    
    total_tests = 0
    successful_tests = 0
    checklist_updates = 0
    
    for url in urls:
        flash(f'Running automated tests for: {url}', 'info')
        
        for test_name, test_function in auto_tests:
            try:
                print(f"Running {test_name} for {url}")
                test_result = test_function(url)
                
                # Store auto-test result
                auto_result = AutoTestResult(
                    project_id=project_id,
                    test_name=test_name,
                    url_tested=url,
                    result=test_result['result'],
                    evidence=test_result['evidence'],
                    request_data=test_result['request'],
                    response_data=test_result['response']
                )
                db.session.add(auto_result)
                
                # Update OWASP checklist if this is an enhanced test
                if test_function in [test[1] for test in enhanced_tests]:
                    try:
                        EnhancedAutoTestService.update_checklist_items(project_id, test_name, test_result)
                        checklist_updates += 1
                        print(f"Updated checklist for {test_name}")
                    except Exception as e:
                        print(f"Error updating checklist for {test_name}: {e}")
                
                total_tests += 1
                if test_result['result'] == 'pass':
                    successful_tests += 1
                    
            except Exception as e:
                print(f"Error running {test_name} for {url}: {e}")
                # Log the error but continue with other tests
                error_result = AutoTestResult(
                    project_id=project_id,
                    test_name=test_name,
                    url_tested=url,
                    result='error',
                    evidence=f'Test failed with error: {str(e)}',
                    request_data='N/A - Test Error',
                    response_data='N/A - Test Error'
                )
                db.session.add(error_result)
                total_tests += 1
    
    db.session.commit()
    
    # Enhanced success message
    success_msg = f'Automated tests completed! {successful_tests}/{total_tests} tests passed.'
    if checklist_updates > 0:
        success_msg += f' {checklist_updates} checklist items automatically updated.'
    
    flash(success_msg, 'success')
    return redirect(url_for('projects.project_detail', project_id=project_id))

@bp.route('/<int:project_id>/autotest-results')
def autotest_results(project_id):
    """Show automated test results for a project"""
    project = db.get_or_404(Project, project_id)
    results = AutoTestResult.query.filter_by(project_id=project_id).order_by(AutoTestResult.created_date.desc()).all()
    return render_template('autotest_results.html', project=project, results=results)
